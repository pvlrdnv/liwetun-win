#include "store.h"
#include "security.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <algorithm>
#include <array>

namespace liwetun::storage {
namespace {
constexpr size_t kMaxContainer = kMaxPayload + 65536;
constexpr std::array<unsigned char, 8> kHeader{'L', 'W', 'P', 'S', 1, 0, 0, 0};
constexpr std::array<unsigned char, 8> kInner{'L', 'W', 'P', 'D', 1, 0, 0, 0};
constexpr char kPurpose[] = "LiWeTun.profile-store.v1";
constexpr char kJournalPurpose[] = "LiWeTun.diagnostic-journal.v1";
#ifdef LIWETUN_STORAGE_TEST_ONLY
constexpr wchar_t kDirectory[] = L"LiWeTun-Storage-CI";
#else
constexpr wchar_t kDirectory[] = L"LiWeTun";
#endif

void Wipe(std::string& value) {
  if (!value.empty()) SecureZeroMemory(value.data(), value.size());
  value.clear();
}
struct WipeString { std::string& value; ~WipeString() { Wipe(value); } };
struct WipeVector {
  std::vector<unsigned char>& value;
  ~WipeVector() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); }
};
struct LocalDeleter { void operator()(void* value) const { if (value) LocalFree(value); } };
using Local = std::unique_ptr<void, LocalDeleter>;
struct Blob {
  DATA_BLOB data{};
  ~Blob() { if (data.pbData) { SecureZeroMemory(data.pbData, data.cbData); LocalFree(data.pbData); } }
};
DATA_BLOB Entropy(Area area) {
  if (area == Area::Journal) return DATA_BLOB{static_cast<DWORD>(sizeof(kJournalPurpose) - 1),
      reinterpret_cast<BYTE*>(const_cast<char*>(kJournalPurpose))};
  return DATA_BLOB{static_cast<DWORD>(sizeof(kPurpose) - 1),
      reinterpret_cast<BYTE*>(const_cast<char*>(kPurpose))};
}
Code IoCode(DWORD error) {
  if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return Code::Missing;
  if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD) return Code::Denied;
  if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) return Code::Busy;
  return Code::Failed;
}
bool HashBytes(const unsigned char* data, size_t size, Digest& digest) {
  if (size > kMaxContainer) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
  BCRYPT_HASH_HANDLE hash = nullptr;
  bool valid = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
  if (valid && size) valid = BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) >= 0;
  valid = valid && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return valid;
}
std::string Hex(const Digest& value) {
  constexpr char alphabet[] = "0123456789abcdef";
  std::string result;
  for (unsigned char byte : value) { result += alphabet[byte >> 4]; result += alphabet[byte & 15]; }
  return result;
}
bool RevisionValid(const std::string& revision) {
  return revision.empty() || (revision.size() == 64 && std::all_of(revision.begin(), revision.end(), [](char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
  }));
}
std::wstring StoreDirectory() {
  PWSTR local = nullptr;
  if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local) != S_OK) return {};
  std::wstring path(local);
  CoTaskMemFree(local);
  return path + L"\\" + kDirectory;
}
struct Context {
  Area area = Area::Profiles;
  std::vector<unsigned char> token_user;
  std::wstring sid, directory;
  Local descriptor;
  Handle mutex, directory_lock;
  bool acquired = false;
  Code code = Code::Failed;
  ~Context() { if (acquired) ReleaseMutex(mutex.get()); }
  PSID User() const { return reinterpret_cast<const TOKEN_USER*>(token_user.data())->User.Sid; }
};
std::wstring File(const Context& context, bool pending = false) {
  return context.directory + L"\\" + (pending ? L".journal.v1.pending.bin" :
      context.area == Area::Profiles ? L"profiles.v1.bin" : L"journal.v1.bin");
}
bool PrivateObject(HANDLE file, PSID user, bool directory) {
  FILE_ATTRIBUTE_TAG_INFO attributes{};
  if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
      (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
      bool(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory) return false;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR raw = nullptr;
  if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, nullptr, &dacl, nullptr, &raw) != ERROR_SUCCESS) return false;
  Local descriptor(raw);
  if (!owner || !dacl || !EqualSid(owner, user) || !IsValidAcl(dacl)) return false;
  bool own_access = false;
  for (DWORD i = 0; i < dacl->AceCount; ++i) {
    void* entry = nullptr;
    if (!GetAce(dacl, i, &entry)) return false;
    auto* header = static_cast<ACE_HEADER*>(entry);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) return false;
    auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(entry);
    PSID sid = &allowed->SidStart;
    if (!IsValidSid(sid) || (!EqualSid(sid, user) && !IsWellKnownSid(sid, WinLocalSystemSid))) return false;
    if (EqualSid(sid, user) && !(header->AceFlags & INHERIT_ONLY_ACE)) own_access = true;
  }
  return own_access;
}
bool OpenContext(Context& context, bool create, Area area) {
  if (area != Area::Profiles && area != Area::Journal) return false;
  context.area = area;
  Handle token;
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) return false;
  token.reset(raw_token);
  DWORD bytes = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &bytes);
  if (!bytes || bytes > 65536) return false;
  context.token_user.resize(bytes);
  if (!GetTokenInformation(token.get(), TokenUser, context.token_user.data(), bytes, &bytes)) return false;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(context.User(), &sid)) return false;
  context.sid = sid;
  LocalFree(sid);
  const std::wstring sddl = L"O:" + context.sid + L"D:P(A;OICI;FA;;;" + context.sid + L")(A;OICI;FA;;;SY)";
  PSECURITY_DESCRIPTOR raw = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &raw, nullptr)) return false;
  context.descriptor.reset(raw);
  // Kernel objects use an independent descriptor without filesystem ACE flags.
  const std::wstring mutex_sddl = L"O:" + context.sid + L"D:P(A;;GA;;;" + context.sid + L")(A;;GA;;;SY)";
  raw = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(mutex_sddl.c_str(), SDDL_REVISION_1, &raw, nullptr)) return false;
  Local mutex_descriptor(raw);
  SECURITY_ATTRIBUTES mutex_attributes{sizeof(SECURITY_ATTRIBUTES), raw, FALSE};
  context.mutex.reset(CreateMutexW(&mutex_attributes, FALSE, (L"Global\\LiWeTun.ProfileStore." + context.sid).c_str()));
  if (!context.mutex) { context.code = IoCode(GetLastError()); return false; }
  const DWORD wait = WaitForSingleObject(context.mutex.get(), 2000);
  if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) { context.code = Code::Busy; return false; }
  context.acquired = true;
  context.directory = StoreDirectory();
  if (context.directory.empty()) return false;
  if (create) {
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), context.descriptor.get(), FALSE};
    if (!CreateDirectoryW(context.directory.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS) {
      context.code = IoCode(GetLastError()); return false;
    }
  }
  context.directory_lock.reset(CreateFileW(context.directory.c_str(), READ_CONTROL | FILE_LIST_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!context.directory_lock || context.directory_lock.get() == INVALID_HANDLE_VALUE) {
    context.code = IoCode(GetLastError()); return false;
  }
  if (!PrivateObject(context.directory_lock.get(), context.User(), true)) { context.code = Code::Denied; return false; }
  context.code = Code::Ok;
  return true;
}
Code ReadContainer(Context& context, std::vector<unsigned char>& bytes, std::string& revision, bool pending = false) {
  Handle file(CreateFileW(File(context, pending).c_str(), GENERIC_READ | READ_CONTROL,
      FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!file || file.get() == INVALID_HANDLE_VALUE) return IoCode(GetLastError());
  if (!PrivateObject(file.get(), context.User(), false)) return Code::Denied;
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file.get(), &size)) return Code::Failed;
  if (size.QuadPart < 0 || static_cast<uint64_t>(size.QuadPart) > kMaxContainer) return Code::TooLarge;
  bytes.resize(static_cast<size_t>(size.QuadPart));
  DWORD done = 0;
  if (!bytes.empty() && (!ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &done, nullptr) || done != bytes.size())) return Code::Failed;
  Digest digest{};
  if (!HashBytes(bytes.data(), bytes.size(), digest)) return Code::Failed;
  revision = Hex(digest);
  return Code::Ok;
}
Snapshot Decode(const std::vector<unsigned char>& bytes, Area area) {
  if (bytes.size() < kHeader.size() || !std::equal(kHeader.begin(), kHeader.begin() + 4, bytes.begin())) return Snapshot(Code::Corrupt);
  if (!std::equal(kHeader.begin(), kHeader.end(), bytes.begin())) return Snapshot(Code::Unsupported);
  DATA_BLOB input{static_cast<DWORD>(bytes.size() - kHeader.size()), const_cast<BYTE*>(bytes.data() + kHeader.size())};
  DATA_BLOB entropy = Entropy(area);
  Blob plain;
  if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain.data)) return Snapshot(Code::Corrupt);
  const size_t prefix = kInner.size() + Digest{}.size();
  if (plain.data.cbData < prefix || plain.data.cbData - prefix > kMaxPayload ||
      !std::equal(kInner.begin(), kInner.end(), plain.data.pbData)) return Snapshot(Code::Corrupt);
  Digest digest{};
  const BYTE* payload = plain.data.pbData + prefix;
  const size_t size = plain.data.cbData - prefix;
  if (!HashBytes(payload, size, digest) || !std::equal(digest.begin(), digest.end(), plain.data.pbData + kInner.size())) return Snapshot(Code::Corrupt);
  Snapshot result(Code::Ok);
  result.payload.assign(reinterpret_cast<const char*>(payload), size);
  return result;
}
Code Encode(std::string& payload, std::vector<unsigned char>& bytes, Area area) {
  if (payload.size() > kMaxPayload) return Code::TooLarge;
  Digest digest{};
  if (!HashBytes(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest)) return Code::Failed;
  std::vector<unsigned char> plain(kInner.begin(), kInner.end());
  WipeVector cleanup{plain};
  plain.insert(plain.end(), digest.begin(), digest.end());
  plain.insert(plain.end(), payload.begin(), payload.end());
  DATA_BLOB input{static_cast<DWORD>(plain.size()), plain.data()};
  DATA_BLOB entropy = Entropy(area);
  Blob encrypted;
  // No CRYPTPROTECT_LOCAL_MACHINE: bind protection to the calling Windows user.
  if (!CryptProtectData(&input, L"LiWeTun profile store v1", &entropy, nullptr, nullptr,
      CRYPTPROTECT_UI_FORBIDDEN, &encrypted.data)) return Code::Failed;
  if (encrypted.data.cbData > kMaxContainer - kHeader.size()) return Code::TooLarge;
  bytes.assign(kHeader.begin(), kHeader.end());
  bytes.insert(bytes.end(), encrypted.data.pbData, encrypted.data.pbData + encrypted.data.cbData);
  return Code::Ok;
}
Code RemoveJournalPending(Context& context, bool explicit_clear) {
  if (context.area != Area::Journal) return Code::Ok;
  std::vector<unsigned char> bytes;
  std::string revision;
  const Code found = ReadContainer(context, bytes, revision, true);
  if (found == Code::Missing) return Code::Ok;
  if (found != Code::Ok) return found;
  // After a crash retain the last committed canonical file. Only a private,
  // valid task-specific encrypted pending file can be discarded automatically.
  if (!explicit_clear) {
    auto decoded = Decode(bytes, Area::Journal);
    if (decoded.code != Code::Ok) return decoded.code;
  }
  return DeleteFileW(File(context, true).c_str()) ? Code::Ok : IoCode(GetLastError());
}
Code Replace(Context& context, const std::vector<unsigned char>& bytes) {
  Digest random{};
  if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return Code::Failed;
  const std::string suffix = Hex(random);
  const std::wstring temporary = context.area == Area::Journal ? File(context, true) :
      context.directory + L"\\.profiles." + std::wstring(suffix.begin(), suffix.end()) + L".tmp";
  const std::wstring destination = File(context);
  const Code pending = RemoveJournalPending(context, false);
  if (pending != Code::Ok) return pending;
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), context.descriptor.get(), FALSE};
  Handle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
  if (!file || file.get() == INVALID_HANDLE_VALUE) return IoCode(GetLastError());
  DWORD done = 0;
  const bool written = WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &done, nullptr) &&
      done == bytes.size() && FlushFileBuffers(file.get());
  const DWORD write_error = GetLastError();
  file.reset();
  Code result = written ? Code::Ok : IoCode(write_error);
  if (written && !MoveFileExW(temporary.c_str(), destination.c_str(),
      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) result = IoCode(GetLastError());
  if (result != Code::Ok) DeleteFileW(temporary.c_str()); // Exact encrypted temporary file just created here.
  return result;
}
}  // namespace

Snapshot::~Snapshot() { Wipe(payload); }
Snapshot& Snapshot::operator=(Snapshot&& other) noexcept {
  if (this != &other) { Wipe(payload); code = other.code; payload = std::move(other.payload); revision = std::move(other.revision); }
  return *this;
}
Snapshot Load(Area area) {
  try {
    Context context;
    if (!OpenContext(context, false, area)) return Snapshot(context.code);
    std::vector<unsigned char> bytes;
    std::string revision;
    const Code code = ReadContainer(context, bytes, revision);
    if (code != Code::Ok) return Snapshot(code);
    Snapshot result = Decode(bytes, area);
    result.revision = std::move(revision);
    return result;
  } catch (...) { return Snapshot(Code::Failed); }
}
Snapshot Save(std::string payload, const std::string& expected_revision, Area area) {
  WipeString cleanup{payload};
  try {
    if (payload.size() > kMaxPayload) return Snapshot(Code::TooLarge);
    if (!RevisionValid(expected_revision)) return Snapshot(Code::Conflict);
    Context context;
    if (!OpenContext(context, true, area)) return Snapshot(context.code);
    std::vector<unsigned char> previous;
    std::string revision;
    const Code found = ReadContainer(context, previous, revision);
    if (found != Code::Ok && found != Code::Missing) return Snapshot(found);
    if (revision != expected_revision) return Snapshot(Code::Conflict);
    if (found == Code::Ok) {
      Snapshot valid = Decode(previous, area);
      if (valid.code != Code::Ok) return Snapshot(valid.code);
    }
    std::vector<unsigned char> encrypted;
    const Code encoded = Encode(payload, encrypted, area);
    if (encoded != Code::Ok) return Snapshot(encoded);
    const Code written = Replace(context, encrypted);
    if (written != Code::Ok) return Snapshot(written);
    Digest digest{};
    if (!HashBytes(encrypted.data(), encrypted.size(), digest)) return Snapshot(Code::Failed);
    Snapshot result(Code::Ok);
    result.revision = Hex(digest);
    return result;
  } catch (...) { return Snapshot(Code::Failed); }
}
Snapshot Clear(const std::string& expected_revision, Area area) {
  try {
    if (!RevisionValid(expected_revision)) return Snapshot(Code::Conflict);
    Context context;
    if (!OpenContext(context, false, area)) return Snapshot(context.code == Code::Missing && expected_revision.empty() ? Code::Ok : context.code);
    std::vector<unsigned char> bytes;
    std::string revision;
    const Code found = ReadContainer(context, bytes, revision);
    if (found != Code::Ok && found != Code::Missing) return Snapshot(found);
    if (revision != expected_revision) return Snapshot(Code::Conflict);
    const Code pending = RemoveJournalPending(context, true);
    if (pending != Code::Ok) return Snapshot(pending);
    if (found == Code::Ok && !DeleteFileW(File(context).c_str())) return Snapshot(IoCode(GetLastError()));
    return Snapshot(Code::Ok);
  } catch (...) { return Snapshot(Code::Failed); }
}
#ifdef LIWETUN_STORAGE_TEST_ONLY
std::wstring TestDirectory() { return StoreDirectory(); }
bool TestCanDecryptContainer(const std::vector<unsigned char>& bytes) { return Decode(bytes, Area::Profiles).code == Code::Ok; }
#endif
}  // namespace liwetun::storage
