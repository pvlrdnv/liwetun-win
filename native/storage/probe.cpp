// Disposable CI only. No real profile input, arbitrary paths or plaintext logs.
#include "store.h"
#include "security.h"
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <fstream>
#include <future>
#include <iostream>
#include <filesystem>

namespace st = liwetun::storage;
using liwetun::Handle;
namespace {
const std::string kCanary = "SYNTHETIC_LIWETUN_DPAPI_PRIVATE_CANARY_261115";
const std::string kPayload = "{\"schema_version\":1,\"synthetic_secret\":\"" + kCanary + "\"}";
const char* stage = "initialization";
std::vector<const char*> checks;
void Check(bool value, const char* name) {
  stage = name;
  if (!value) throw 1;
  checks.push_back(name);
}
std::vector<unsigned char> Raw(const std::wstring& path) {
  std::ifstream input(std::filesystem::path(path), std::ios::binary | std::ios::ate);
  const auto size = input.tellg();
  if (!input || size < 0 || size > 2 * 1024 * 1024) throw 1;
  std::vector<unsigned char> bytes(static_cast<size_t>(size));
  input.seekg(0);
  input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!input) throw 1;
  return bytes;
}
void Rewrite(const std::wstring& path, const std::vector<unsigned char>& bytes) {
  // Only fixture ciphertext/container bytes, never kPayload or other plaintext.
  std::ofstream output(std::filesystem::path(path), std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!output) throw 1;
}
bool SetAcl(const std::wstring& path, bool broad) {
  Handle token;
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
  token.reset(raw);
  DWORD size = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
  std::vector<unsigned char> user(size);
  if (!size || !GetTokenInformation(token.get(), TokenUser, user.data(), size, &size)) return false;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid)) return false;
  std::wstring sddl = L"D:P(A;;FA;;;" + std::wstring(sid) + L")(A;;FA;;;SY)";
  LocalFree(sid);
  if (broad) sddl += L"(A;;FR;;;WD)";
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return false;
  PACL dacl = nullptr;
  BOOL present = FALSE, defaulted = FALSE;
  const bool valid = GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present &&
      SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
  LocalFree(descriptor);
  return valid;
}
bool EnableSymlinkPrivilege() {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw)) return false;
  Handle token(raw);
  TOKEN_PRIVILEGES privileges{};
  privileges.PrivilegeCount = 1;
  if (!LookupPrivilegeValueW(nullptr, SE_CREATE_SYMBOLIC_LINK_NAME, &privileges.Privileges[0].Luid)) return false;
  privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  SetLastError(ERROR_SUCCESS);
  return AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
}
void UserTests(bool cleanup) {
  const auto directory = st::TestDirectory();
  const auto file = directory + L"\\profiles.v1.bin";
  if (cleanup) {
    auto current = st::Load();
    Check((current.code == st::Code::Ok || current.code == st::Code::Corrupt || current.code == st::Code::Unsupported) &&
        st::Clear(current.revision).code == st::Code::Ok && RemoveDirectoryW(directory.c_str()), "task_storage_removed");
    return;
  }
  Check(GetFileAttributesW(directory.c_str()) == INVALID_FILE_ATTRIBUTES, "fresh_task_directory");
  Check(st::Load().code == st::Code::Missing && GetFileAttributesW(directory.c_str()) == INVALID_FILE_ATTRIBUTES,
      "missing_load_creates_no_files");
  auto first = st::Save(kPayload, "");
  Check(first.code == st::Code::Ok && first.revision.size() == 64, "current_user_dpapi_save");
  auto loaded = st::Load();
  Check(loaded.code == st::Code::Ok && loaded.payload == kPayload && loaded.revision == first.revision, "current_user_roundtrip");
  const auto encrypted = Raw(file);
  Check(std::search(encrypted.begin(), encrypted.end(), kCanary.begin(), kCanary.end()) == encrypted.end(), "no_plaintext_in_file");
  Check(st::Save("different synthetic value", "").code == st::Code::Conflict && st::Load().payload == kPayload, "stale_revision_preserves_data");
  Check(st::Save(std::string(st::kMaxPayload + 1, 'x'), first.revision).code == st::Code::TooLarge &&
      st::Load().revision == first.revision, "oversized_save_preserves_data");
  {
    Handle lock(CreateFileW(file.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    Check(lock && lock.get() != INVALID_HANDLE_VALUE && st::Save(kPayload, first.revision).code == st::Code::Busy,
        "locked_file_fails_without_fallback");
  }
  Check(SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_READONLY), "readonly_fixture");
  Check(st::Save(kPayload + " ", first.revision).code != st::Code::Ok, "failed_replace_reported");
  Check(SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL) && st::Load().revision == first.revision,
      "failed_replace_keeps_previous_file");
  size_t count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(directory)) { (void)entry; ++count; }
  Check(count == 1, "no_failed_write_temporary_file");
  auto left = std::async(std::launch::async, [&] { return st::Save(kPayload + " ", first.revision); });
  auto right = std::async(std::launch::async, [&] { return st::Save(kPayload + "\n", first.revision); });
  const auto a = left.get().code, b = right.get().code;
  Check((a == st::Code::Ok && b == st::Code::Conflict) || (b == st::Code::Ok && a == st::Code::Conflict), "concurrent_compare_and_swap");
  auto current = st::Load();
  Check(current.code == st::Code::Ok && (current.payload == kPayload + " " || current.payload == kPayload + "\n"), "concurrent_result_complete");
  Check(SetAcl(file, true), "broad_acl_fixture");
  Check(st::Load().code == st::Code::Denied && st::Save(kPayload, current.revision).code == st::Code::Denied, "broad_acl_denied");
  Check(SetAcl(file, false) && st::Load().code == st::Code::Ok, "private_acl_restored");
  auto tampered = Raw(file);
  tampered.back() ^= 1;
  Rewrite(file, tampered);
  auto corrupt = st::Load();
  Check(corrupt.code == st::Code::Corrupt && corrupt.payload.empty() && !corrupt.revision.empty(), "tampering_denied");
  Check(st::Save(kPayload, corrupt.revision).code == st::Code::Corrupt, "corrupt_file_not_overwritten");
  Check(st::Clear(corrupt.revision).code == st::Code::Ok && st::Load().code == st::Code::Missing, "explicit_corrupt_reset");
  auto saved = st::Save(kPayload, "");
  Check(saved.code == st::Code::Ok, "save_after_reset");
  auto newer = Raw(file);
  newer[4] = 2;
  Rewrite(file, newer);
  auto unsupported = st::Load();
  Check(unsupported.code == st::Code::Unsupported && st::Save(kPayload, unsupported.revision).code == st::Code::Unsupported,
      "unknown_version_preserved");
  Check(st::Clear(unsupported.revision).code == st::Code::Ok, "explicit_version_reset");
  saved = st::Save(kPayload, "");
  Check(saved.code == st::Code::Ok, "reparse_target_ready");
  const auto target = directory + L"\\reparse-target.bin";
  Check(MoveFileExW(file.c_str(), target.c_str(), 0) && EnableSymlinkPrivilege() &&
      CreateSymbolicLinkW(file.c_str(), target.c_str(), 0), "real_reparse_fixture");
  Check(st::Load().code == st::Code::Denied && st::Save(kPayload, saved.revision).code == st::Code::Denied,
      "reparse_file_denied");
  Check(DeleteFileW(file.c_str()) && MoveFileExW(target.c_str(), file.c_str(), 0) &&
      st::Load().code == st::Code::Ok, "reparse_target_unchanged");
  current = st::Load();
  Check(st::Clear(current.revision).code == st::Code::Ok, "clear_before_cross_context");
  saved = st::Save(kPayload, "");
  Check(saved.code == st::Code::Ok, "cross_context_fixture_ready");
  // The parent copies only these ciphertext bytes into a protected task folder.
}

SERVICE_STATUS_HANDLE service_status = nullptr;
void ReportStatus(DWORD state) {
  SERVICE_STATUS status{};
  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = state;
  SetServiceStatus(service_status, &status);
}
void WINAPI Control(DWORD) {}
void WINAPI SystemTest(DWORD argc, LPWSTR* argv) {
  service_status = RegisterServiceCtrlHandlerW(argc ? argv[0] : L"", Control);
  if (!service_status) return;
  ReportStatus(SERVICE_RUNNING);
  bool valid = false, denied = false;
  liwetun::Image self;
  if (!liwetun::OpenTrustedImage(liwetun::SelfPath(), self, false)) { ReportStatus(SERVICE_STOPPED); return; }
  try {
    const auto bytes = Raw(liwetun::Directory(self.path) + L"\\cross-user.bin");
    valid = bytes.size() >= 8 && std::string(bytes.begin(), bytes.begin() + 4) == "LWPS";
    denied = valid && !st::TestCanDecryptContainer(bytes);
  } catch (...) {}
  const auto output_path = liwetun::Directory(self.path) + L"\\system-result.json";
  std::ofstream output{std::filesystem::path(output_path)};
  output << "{\"input_valid\":" << (valid ? "true" : "false")
      << ",\"wrong_context_denied\":" << (denied ? "true" : "false") << "}\n";
  output.close();
  ReportStatus(SERVICE_STOPPED);
}
}  // namespace
int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && std::wstring(argv[1]) == L"--system-test") {
    // Only SCM can start this entry point; the parent creates it on disposable
    // CI, with the executable/ciphertext in its protected Program Files folder.
    SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(L""), SystemTest}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : 2;
  }
  wchar_t environment[8]{};
  if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", environment, 8) != 4 || std::wstring(environment) != L"true") return 3;
  try {
    UserTests(argc == 2 && std::wstring(argv[1]) == L"--cleanup");
    std::cout << "{\"passed\":true,\"checks\":[";
    for (size_t i = 0; i < checks.size(); ++i) { if (i) std::cout << ','; std::cout << '"' << checks[i] << '"'; }
    std::cout << "]}\n";
    return 0;
  } catch (...) {
    std::cout << "{\"passed\":false,\"failed_check\":\"" << stage << "\"}\n";
    return 1;
  }
}
