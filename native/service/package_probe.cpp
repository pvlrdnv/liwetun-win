// Disposable CI only. Launch only the adjacent trusted GUI's fixed read-only
// status command with a medium-integrity token and no enabled admin group.
// No arbitrary program, command, credentials or network configuration is accepted.
#include "security.h"
#include <userenv.h>
#include <iostream>

using liwetun::Handle;
namespace {
const char* stage = "guard";
DWORD child_exit = MAXDWORD;
void Require(bool value, const char* name) { stage = name; if (!value) throw 1; }
std::vector<unsigned char> Information(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
  DWORD size = 0;
  GetTokenInformation(token, kind, nullptr, 0, &size);
  if (!size || size > 65536) return {};
  std::vector<unsigned char> data(size);
  if (!GetTokenInformation(token, kind, data.data(), size, &size)) return {};
  return data;
}
struct Environment {
  void* value = nullptr;
  ~Environment() { if (value) DestroyEnvironmentBlock(value); }
};
struct Attributes {
  LPPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
  ~Attributes() { if (value) DeleteProcThreadAttributeList(value); }
};
void CheckRestrictedRights(HANDLE token) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  SC_HANDLE service = manager ? OpenServiceW(manager, L"LiWeTun", SERVICE_QUERY_STATUS) : nullptr;
  SERVICE_STATUS_PROCESS status{};
  DWORD bytes = 0;
  const bool running = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
      reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes) && status.dwCurrentState == SERVICE_RUNNING;
  if (service) CloseServiceHandle(service);
  if (manager) CloseServiceHandle(manager);
  Require(running && status.dwProcessId != GetCurrentProcessId(), "query_service_pid");
  Require(ImpersonateLoggedOnUser(token) != FALSE, "impersonate_restricted_owner");
  struct Revert {
    bool active = true;
    ~Revert() { if (active) RevertToSelf(); }
  } revert;
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, status.dwProcessId));
  Require(process && liwetun::IsSystemProcess(process.get()), "restricted_live_system_identity_read");
  constexpr DWORD process_rights[]{PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION,
      PROCESS_VM_WRITE, PROCESS_DUP_HANDLE, WRITE_DAC, WRITE_OWNER};
  for (DWORD right : process_rights) {
    Handle forbidden(OpenProcess(right, FALSE, status.dwProcessId));
    Require(!forbidden && GetLastError() == ERROR_ACCESS_DENIED, "restricted_process_write_denied");
  }
  constexpr DWORD token_rights[]{TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
      TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_DEFAULT, WRITE_DAC, WRITE_OWNER};
  for (DWORD right : token_rights) {
    HANDLE raw = nullptr;
    const bool opened = OpenProcessToken(process.get(), right, &raw) != FALSE;
    Handle forbidden(raw);
    Require(!opened && GetLastError() == ERROR_ACCESS_DENIED, "restricted_token_privilege_denied");
  }
  Require(RevertToSelf() != FALSE, "revert_restricted_owner");
  revert.active = false;
}
void Run() {
  wchar_t environment[8]{};
  Require(GetEnvironmentVariableW(L"GITHUB_ACTIONS", environment, 8) == 4 &&
      std::wstring(environment) == L"true", "disposable_ci");
  liwetun::Image self, child;
  const auto directory = liwetun::Directory(liwetun::SelfPath());
  const auto executable = directory + L"\\liwetun.exe";
  Require(liwetun::OpenTrustedImage(liwetun::SelfPath(), self) &&
      liwetun::OpenTrustedImage(executable, child) && liwetun::SameSigner(self, child) &&
      liwetun::EqualPath(liwetun::Directory(self.path), liwetun::Directory(child.path)), "trusted_adjacent_gui");
  HANDLE raw = nullptr;
  Require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &raw) != FALSE, "caller_token");
  Handle token(raw);
  unsigned char admin[SECURITY_MAX_SID_SIZE]{};
  DWORD admin_size = sizeof(admin);
  Require(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin, &admin_size) != FALSE, "admin_sid");
  SID_AND_ATTRIBUTES disabled{admin, 0};
  raw = nullptr;
  Require(CreateRestrictedToken(token.get(), DISABLE_MAX_PRIVILEGE, 1, &disabled, 0, nullptr, 0, nullptr, &raw) != FALSE, "restricted_token");
  Handle restricted(raw);
  unsigned char medium[SECURITY_MAX_SID_SIZE]{};
  DWORD medium_size = sizeof(medium);
  Require(CreateWellKnownSid(WinMediumLabelSid, nullptr, medium, &medium_size) != FALSE, "medium_sid");
  TOKEN_MANDATORY_LABEL label{{medium, SE_GROUP_INTEGRITY}};
  Require(SetTokenInformation(restricted.get(), TokenIntegrityLevel, &label,
      static_cast<DWORD>(sizeof(label) + GetLengthSid(medium))) != FALSE, "set_medium_integrity");
  const auto groups = Information(restricted.get(), TokenGroups);
  const auto integrity = Information(restricted.get(), TokenIntegrityLevel);
  Require(!groups.empty() && !integrity.empty(), "read_restricted_facts");
  const auto* group_list = reinterpret_cast<const TOKEN_GROUPS*>(groups.data());
  for (DWORD i = 0; i < group_list->GroupCount; ++i) {
    Require(!EqualSid(group_list->Groups[i].Sid, admin) || !(group_list->Groups[i].Attributes & SE_GROUP_ENABLED), "admin_group_disabled");
  }
  Require(EqualSid(reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid, medium) != FALSE, "medium_integrity_verified");
  CheckRestrictedRights(restricted.get());

  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE read = nullptr, write = nullptr;
  Require(CreatePipe(&read, &write, &security, 4096) != FALSE, "output_pipe");
  Handle output(read), child_output(write);
  Require(SetHandleInformation(output.get(), HANDLE_FLAG_INHERIT, 0) != FALSE, "private_parent_handle");
  Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr));
  Require(input && input.get() != INVALID_HANDLE_VALUE, "empty_child_input");
  SIZE_T attribute_size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
  Require(attribute_size > 0 && attribute_size < 65536, "attribute_size");
  std::vector<unsigned char> attribute_storage(attribute_size);
  Attributes attributes;
  auto* attribute_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  Require(InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_size) != FALSE, "attribute_list");
  attributes.value = attribute_list;
  HANDLE inherited[]{child_output.get(), input.get()};
  Require(UpdateProcThreadAttribute(attributes.value, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) != FALSE, "explicit_child_handles");
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = input.get();
  startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = child_output.get();
  startup.lpAttributeList = attributes.value;
  Environment block;
  Require(CreateEnvironmentBlock(&block.value, restricted.get(), FALSE) != FALSE, "isolated_child_environment");
  std::wstring command = L"\"" + executable + L"\" --service-status";
  PROCESS_INFORMATION process{};
  Require(CreateProcessAsUserW(restricted.get(), executable.c_str(), command.data(), nullptr, nullptr, TRUE,
      EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, block.value,
      directory.c_str(), &startup.StartupInfo, &process) != FALSE, "launch_restricted_gui");
  Handle process_handle(process.hProcess), thread(process.hThread);
  child_output.reset();
  if (WaitForSingleObject(process_handle.get(), 15000) != WAIT_OBJECT_0) {
    TerminateProcess(process_handle.get(), 70); // Exact child just created here.
    WaitForSingleObject(process_handle.get(), 5000);
    Require(false, "child_timeout");
  }
  Require(GetExitCodeProcess(process_handle.get(), &child_exit) != FALSE, "child_exit_code");
  std::string result;
  char chunk[256]{};
  DWORD count = 0;
  while (ReadFile(output.get(), chunk, sizeof(chunk), &count, nullptr) && count) {
    result.append(chunk, count);
    Require(result.size() <= 2048, "bounded_child_output");
  }
  const std::string expected = "{\"code\":0,\"state\":0,\"runtime_ready\":true,\"core_state\":null}\n";
  Require(child_exit == 0 && result == expected, "restricted_query_reply");
}
}  // namespace
int wmain() {
  try {
    Run();
    std::cout << "{\"passed\":true,\"medium_integrity\":true,\"admin_group_enabled\":false,\"service_metadata_read_only\":true}\n";
    return 0;
  } catch (...) {
    std::cout << "{\"passed\":false,\"stage\":\"" << stage << "\",\"child_exit\":";
    if (child_exit == MAXDWORD) std::cout << "null"; else std::cout << child_exit;
    std::cout << "}\n";
    return 1;
  }
}
