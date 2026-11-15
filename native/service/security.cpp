#include "security.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <algorithm>

namespace liwetun {
namespace {
bool SystemOrAdmins(PSID sid) {
  return IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid);
}
bool TrustedOwner(PSID sid) {
  if (SystemOrAdmins(sid)) return true;
  DWORD bytes = 0, domain_bytes = 0;
  SID_NAME_USE use{};
  LookupAccountNameW(nullptr, L"NT SERVICE\\TrustedInstaller", nullptr, &bytes, nullptr, &domain_bytes, &use);
  if (bytes == 0) return false;
  std::vector<unsigned char> value(bytes);
  std::vector<wchar_t> domain(domain_bytes);
  return LookupAccountNameW(nullptr, L"NT SERVICE\\TrustedInstaller", value.data(), &bytes, domain.data(), &domain_bytes, &use) && EqualSid(sid, value.data());
}
bool SafeAcl(HANDLE file) {
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  bool valid = owner && dacl && TrustedOwner(owner);
  if (valid) {
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
      void* entry = nullptr;
      if (!GetAce(dacl, i, &entry)) { valid = false; break; }
      const auto* header = static_cast<ACE_HEADER*>(entry);
      if (header->AceFlags & INHERIT_ONLY_ACE) continue;
      if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
      if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) { valid = false; break; }
      auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
      constexpr DWORD write = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
          FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
      if ((ace->Mask & write) && !TrustedOwner(&ace->SidStart)) { valid = false; break; }
    }
  }
  if (descriptor) LocalFree(descriptor);
  return valid;
}
bool Signature(HANDLE file, const std::wstring& path, Digest& signer) {
  WINTRUST_FILE_INFO file_info{};
  file_info.cbStruct = sizeof(file_info);
  file_info.pcwszFilePath = path.c_str();
  file_info.hFile = file;
  WINTRUST_DATA data{};
  data.cbStruct = sizeof(data);
  data.dwUIChoice = WTD_UI_NONE;
  data.fdwRevocationChecks = WTD_REVOKE_NONE;
  data.dwUnionChoice = WTD_CHOICE_FILE;
  data.pFile = &file_info;
  data.dwStateAction = WTD_STATEACTION_VERIFY;
  data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG result = WinVerifyTrust(nullptr, &policy, &data);
  bool valid = false;
  if (result == ERROR_SUCCESS && data.hWVTStateData) {
    auto* provider = WTHelperProvDataFromStateData(data.hWVTStateData);
    auto* signature = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
    auto* cert = signature ? WTHelperGetProvCertFromChain(signature, 0) : nullptr;
    DWORD size = static_cast<DWORD>(signer.size());
    valid = cert && cert->pCert && CertGetCertificateContextProperty(
        cert->pCert, CERT_SHA256_HASH_PROP_ID, signer.data(), &size) && size == signer.size();
  }
  data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policy, &data);
  return valid;
}
bool Token(HANDLE process, Handle& token) {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &raw)) return false;
  token.reset(raw);
  return true;
}
std::vector<unsigned char> TokenValue(HANDLE token, TOKEN_INFORMATION_CLASS type) {
  DWORD size = 0;
  GetTokenInformation(token, type, nullptr, 0, &size);
  if (!size || size > 65536) return {};
  std::vector<unsigned char> value(size);
  if (!GetTokenInformation(token, type, value.data(), size, &size)) return {};
  return value;
}
}  // namespace

std::wstring SelfPath() {
  std::vector<wchar_t> path(32768);
  const DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  return size && size < path.size() ? std::wstring(path.data(), size) : L"";
}
std::wstring Directory(const std::wstring& path) { return path.substr(0, path.find_last_of(L"\\/")); }
bool EqualPath(const std::wstring& a, const std::wstring& b) {
  return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
bool ProtectedPath(const std::wstring& path) {
  PWSTR program_files = nullptr;
  if (SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &program_files) != S_OK) return false;
  const std::wstring root(program_files);
  CoTaskMemFree(program_files);
  // Canonical final paths use the extended prefix.
  const std::wstring canonical_root = L"\\\\?\\" + root;
  std::wstring current = path;
  if (current.size() <= canonical_root.size() ||
      !EqualPath(current.substr(0, canonical_root.size() + 1), canonical_root + L"\\")) return false;
  while (current.size() >= canonical_root.size()) {
    Handle file(CreateFileW(current.c_str(), READ_CONTROL, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!file || file.get() == INVALID_HANDLE_VALUE || !SafeAcl(file.get())) return false;
    if (EqualPath(current, canonical_root)) return true;
    current = Directory(current);
  }
  return false;
}
bool OpenTrustedImage(const std::wstring& path, Image& image, bool require_signature) {
  Handle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (!file || file.get() == INVALID_HANDLE_VALUE) return false;
  std::vector<wchar_t> final_path(32768);
  const DWORD size = GetFinalPathNameByHandleW(file.get(), final_path.data(), static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED);
  if (!size || size >= final_path.size()) return false;
  std::wstring canonical(final_path.data(), size);
  if (!ProtectedPath(canonical)) return false;
  Digest signer{};
  if (require_signature && !Signature(file.get(), canonical, signer)) return false;
  image.handle = std::move(file);
  image.path = std::move(canonical);
  image.signer = signer;
  return true;
}
bool SameSigner(const Image& a, const Image& b) { return a.signer == b.signer && a.signer != Digest{}; }
bool HashFile(HANDLE file, Digest& digest) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
  BCRYPT_HASH_HANDLE hash = nullptr;
  bool valid = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
  std::array<unsigned char, 65536> buffer{};
  LARGE_INTEGER zero{};
  valid = valid && SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
  while (valid) {
    DWORD size = 0;
    if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &size, nullptr)) { valid = false; break; }
    if (size == 0) break;
    valid = BCryptHashData(hash, buffer.data(), size, 0) >= 0;
  }
  valid = valid && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return valid;
}
bool ProcessActor(DWORD pid, Actor& actor) {
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
  if (!process || WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT) return false;
  Handle token;
  if (!Token(process.get(), token)) return false;
  auto user = TokenValue(token.get(), TokenUser);
  auto stats = TokenValue(token.get(), TokenStatistics);
  auto session = TokenValue(token.get(), TokenSessionId);
  if (user.empty() || stats.empty() || session.empty()) return false;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid)) return false;
  actor.sid = sid;
  LocalFree(sid);
  actor.session = *reinterpret_cast<DWORD*>(session.data());
  actor.logon = reinterpret_cast<TOKEN_STATISTICS*>(stats.data())->AuthenticationId;
  std::vector<wchar_t> path(32768);
  DWORD size = static_cast<DWORD>(path.size());
  if (!QueryFullProcessImageNameW(process.get(), 0, path.data(), &size) || !OpenTrustedImage(std::wstring(path.data(), size), actor.image)) return false;
  actor.process = std::move(process);
  return true;
}
bool IsSystemProcess(HANDLE process) {
  Handle token;
  if (!Token(process, token)) return false;
  auto user = TokenValue(token.get(), TokenUser);
  return !user.empty() && IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, WinLocalSystemSid);
}
bool AuthorizePipe(HANDLE pipe, const std::wstring& owner_sid, const Image& service, Actor& actor) {
  ULONG pid = 0;
  return GetNamedPipeClientProcessId(pipe, &pid) && ProcessActor(pid, actor) &&
      actor.sid == owner_sid && SameSigner(service, actor.image) &&
      EqualPath(Directory(service.path), Directory(actor.image.path)) &&
      EqualPath(actor.image.path.substr(actor.image.path.find_last_of(L"\\") + 1), L"liwetun.exe");
}
bool VerifyServer(HANDLE pipe, const Image& client) {
  ULONG pid = 0;
  if (!GetNamedPipeServerProcessId(pipe, &pid)) return false;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  SC_HANDLE service = manager ? OpenServiceW(manager, L"LiWeTun", SERVICE_QUERY_STATUS) : nullptr;
  SERVICE_STATUS_PROCESS status{};
  DWORD bytes = 0;
  const bool expected = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
      reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes) && status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId == pid;
  if (service) CloseServiceHandle(service);
  if (manager) CloseServiceHandle(manager);
  Actor server;
  return expected && ProcessActor(pid, server) && IsSystemProcess(server.process.get()) &&
      SameSigner(client, server.image) && EqualPath(Directory(client.path), Directory(server.image.path)) &&
      EqualPath(server.image.path.substr(server.image.path.find_last_of(L"\\") + 1), L"liwetun_service.exe");
}
}  // namespace liwetun
