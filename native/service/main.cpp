#include "backend.h"
#include "pipe_io.h"
#include <sddl.h>
#include <aclapi.h>
#include <wtsapi32.h>
#include <string>

namespace liwetun {
namespace {
Handle stopping, logged_off;
std::wstring owner_sid;
std::atomic<DWORD> lease_session{MAXDWORD};
SERVICE_STATUS_HANDLE status_handle = nullptr;
std::mutex status_mutex;
DWORD checkpoint = 0;
void Status(DWORD state, DWORD error = NO_ERROR) {
  std::lock_guard lock(status_mutex);
  SERVICE_STATUS status{};
  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = state;
  status.dwWin32ExitCode = error;
  status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE : 0;
  if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
    status.dwCheckPoint = ++checkpoint;
    status.dwWaitHint = 15000;
  }
  if (status_handle) SetServiceStatus(status_handle, &status);
}
DWORD WINAPI Control(DWORD control, DWORD event, void* data, void*) {
  if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
    Status(SERVICE_STOP_PENDING);
    SetEvent(stopping.get());
  } else if (control == SERVICE_CONTROL_SESSIONCHANGE && event == WTS_SESSION_LOGOFF && data) {
    if (static_cast<WTSSESSION_NOTIFICATION*>(data)->dwSessionId == lease_session.load()) SetEvent(logged_off.get());
  }
  return NO_ERROR;
}
bool SameLease(const Actor& actor, const Actor& lease) {
  return actor.sid == lease.sid && actor.session == lease.session &&
      actor.logon.HighPart == lease.logon.HighPart && actor.logon.LowPart == lease.logon.LowPart;
}
bool GrantReadFacts(HANDLE object, PSID sid, DWORD rights) {
  PACL existing = nullptr, updated = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &existing, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  EXPLICIT_ACCESSW access{};
  access.grfAccessPermissions = rights;
  access.grfAccessMode = GRANT_ACCESS;
  access.grfInheritance = NO_INHERITANCE;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_USER;
  access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
  const bool valid = existing && SetEntriesInAclW(1, &access, existing, &updated) == ERROR_SUCCESS &&
      SetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
          nullptr, nullptr, updated, nullptr) == ERROR_SUCCESS;
  if (updated) LocalFree(updated);
  if (descriptor) LocalFree(descriptor);
  return valid;
}
bool AllowOwnerIdentityQuery() {
  // Keep the client's live LocalSystem-token proof. Grant only metadata reads
  // on this service's own process/token to its configured owner, never a token
  // duplication/impersonation/write right or access to another system process.
  if (!IsSystemProcess(GetCurrentProcess())) return false;
  PSID sid = nullptr;
  if (!ConvertStringSidToSidW(owner_sid.c_str(), &sid)) return false;
  Handle process(OpenProcess(READ_CONTROL | WRITE_DAC, FALSE, GetCurrentProcessId()));
  HANDLE raw_token = nullptr;
  const bool opened = OpenProcessToken(GetCurrentProcess(), READ_CONTROL | WRITE_DAC, &raw_token) != FALSE;
  Handle token(raw_token);
  const bool valid = process && opened &&
      GrantReadFacts(token.get(), sid, TOKEN_QUERY) &&
      GrantReadFacts(process.get(), sid, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE);
  LocalFree(sid);
  return valid;
}
void WINAPI Main(DWORD, LPWSTR*) {
  stopping.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  logged_off.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  status_handle = RegisterServiceCtrlHandlerExW(kServiceName, Control, nullptr);
  if (!status_handle || !stopping || !logged_off) return;
  Status(SERVICE_START_PENDING);
  Image self;
  if (!OpenTrustedImage(SelfPath(), self) || !AllowOwnerIdentityQuery()) { Status(SERVICE_STOPPED, ERROR_ACCESS_DENIED); return; }
  if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)) {
    Status(SERVICE_STOPPED, ERROR_ACCESS_DENIED); return;
  }
  const std::wstring acl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + owner_sid + L")";
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
    Status(SERVICE_STOPPED, ERROR_ACCESS_DENIED); return;
  }
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  Handle pipe(CreateNamedPipeW(kPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1, 16384, 16384, 0, &attributes));
  LocalFree(descriptor);
  if (!pipe || pipe.get() == INVALID_HANDLE_VALUE) { Status(SERVICE_STOPPED, ERROR_ACCESS_DENIED); return; }
  try {
    Backend backend(self);
    Actor lease;
    bool leased = false, lease_closing = false;
    Status(SERVICE_RUNNING);
    while (WaitForSingleObject(stopping.get(), 0) != WAIT_OBJECT_0) {
      // Until tray/background lifecycle is implemented, a crashed/closed UI
      // cannot leave a tunnel behind. Only the verified lease process is watched.
      if (leased && !lease_closing && WaitForSingleObject(lease.process.get(), 0) != WAIT_TIMEOUT) {
        backend.Stop(); lease_closing = true;
      }
      if (WaitForSingleObject(logged_off.get(), 0) == WAIT_OBJECT_0) {
        backend.Stop(); lease_closing = true; ResetEvent(logged_off.get());
      }
      if (!backend.Busy()) { leased = false; lease_closing = false; lease = Actor{}; lease_session = MAXDWORD; }
      Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
      OVERLAPPED connection{};
      connection.hEvent = event.get();
      const BOOL connected = ConnectNamedPipe(pipe.get(), &connection);
      const DWORD error = connected ? ERROR_SUCCESS : GetLastError();
      bool accepted = connected || error == ERROR_PIPE_CONNECTED;
      if (!accepted && error == ERROR_IO_PENDING) {
        HANDLE waits[]{event.get(), stopping.get(), logged_off.get()};
        const DWORD wait = WaitForMultipleObjects(3, waits, FALSE, 5000);
        DWORD ignored = 0;
        if (wait == WAIT_OBJECT_0) accepted = GetOverlappedResult(pipe.get(), &connection, &ignored, FALSE) != FALSE;
        else { CancelIoEx(pipe.get(), &connection); GetOverlappedResult(pipe.get(), &connection, &ignored, TRUE); }
      }
      if (!accepted) { DisconnectNamedPipe(pipe.get()); continue; }
      Actor actor;
      if (!AuthorizePipe(pipe.get(), owner_sid, self, actor)) { DisconnectNamedPipe(pipe.get()); continue; }
      Request request{};
      Reply reply{};
      reply.core_state = UINT32_MAX;
      std::string payload;
      if (PipeIo(pipe.get(), stopping.get(), &request, sizeof(request), false)) {
        reply.nonce = request.nonce;
        if (!Valid(request)) reply.code = Code::Malformed;
        else {
          payload.resize(request.length);
          const bool body = payload.empty() || PipeIo(pipe.get(), stopping.get(), payload.data(), request.length, false);
          const bool alive = WaitForSingleObject(actor.process.get(), 0) == WAIT_TIMEOUT;
          if (!body || !alive) reply.code = Code::Denied;
          else if (request.command == Command::Start || request.command == Command::Stop) {
            if (WaitForSingleObject(logged_off.get(), 0) == WAIT_OBJECT_0) {
              backend.Stop(); lease_closing = true; ResetEvent(logged_off.get());
            }
            if (leased && !SameLease(actor, lease)) reply.code = Code::Busy;
            else if (request.command == Command::Start) {
              reply.code = backend.Start(std::move(payload));
              // This refusal happens only after SDK readiness was established.
              if (AdapterRefusal(reply.code)) reply.runtime_ready = 1;
              if (reply.code == Code::Ok) {
                lease = std::move(actor); leased = true; lease_closing = false; lease_session = lease.session;
              }
            } else { backend.Stop(); lease_closing = true; }
          }
          if (reply.code == Code::Ok) {
            backend.Snapshot(reply);
            if (request.command == Command::Stop) reply.code = Code::Ok; // Acknowledge queued stop, even from prior error state.
          }
        }
        if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size());
        TrafficReply traffic;
        void* response = &reply;
        DWORD response_size = static_cast<DWORD>(sizeof(reply));
        if (Valid(request) && request.command == Command::Traffic && reply.code == Code::Ok) {
          traffic.status = reply;
          backend.SnapshotTraffic(traffic);
          response = &traffic;
          response_size = static_cast<DWORD>(sizeof(traffic));
        }
        if (PipeIo(pipe.get(), stopping.get(), response, response_size, true)) {
          // Write completion only queues the reply. DisconnectNamedPipe would
          // discard it if the client has not read yet. Wait for this one-shot
          // client to close after consuming/validating the reply; PipeIo keeps
          // the wait bounded/cancellable instead of an unbounded flush.
          unsigned char extra = 0;
          PipeIo(pipe.get(), stopping.get(), &extra, 1, false);
        }
      }
      DisconnectNamedPipe(pipe.get());
    }
    backend.Shutdown();
    while (WaitForSingleObject(backend.Done(), 500) == WAIT_TIMEOUT) Status(SERVICE_STOP_PENDING);
  } catch (...) {
    Status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR); return;
  }
  Status(SERVICE_STOPPED);
}
bool UserSid(const std::wstring& value) {
  PSID sid = nullptr;
  if (value.size() > 184 || !ConvertStringSidToSidW(value.c_str(), &sid)) return false;
  DWORD name_size = 0, domain_size = 0;
  SID_NAME_USE type{};
  LookupAccountSidW(nullptr, sid, nullptr, &name_size, nullptr, &domain_size, &type);
  std::vector<wchar_t> name(name_size), domain(domain_size);
  bool result = name_size && LookupAccountSidW(nullptr, sid, name.data(), &name_size, domain.data(), &domain_size, &type) && type == SidTypeUser;
  LocalFree(sid);
  return result;
}
int Install(const std::wstring& sid) {
  Image self;
  if (!UserSid(sid) || !OpenTrustedImage(SelfPath(), self)) return 10;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (!manager) return 11;
  const std::wstring command = L"\"" + SelfPath() + L"\" --service " + sid;
  SC_HANDLE service = CreateServiceW(manager, kServiceName, L"LiWeTun connection service", SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
  if (!service) { CloseServiceHandle(manager); return 12; }
  const std::wstring acl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCRPLO;;;" + sid + L")";
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const bool valid = ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) &&
      SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, descriptor);
  if (descriptor) LocalFree(descriptor);
  if (!valid) DeleteService(service); // Only the registration just created by this invocation.
  CloseServiceHandle(service); CloseServiceHandle(manager);
  return valid ? 0 : 13;
}
int InstallDesktopOwner() {
  // The elevated installer's account can differ from the desktop user.
  // Resolve only this session's actual Windows shell; never guess an admin SID.
  const HWND shell = GetShellWindow();
  DWORD pid = 0, session = MAXDWORD, own_session = MAXDWORD;
  if (!shell || !GetWindowThreadProcessId(shell, &pid) || !pid ||
      !ProcessIdToSessionId(pid, &session) ||
      !ProcessIdToSessionId(GetCurrentProcessId(), &own_session) || session != own_session) return 15;
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
  if (!process || WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT) return 15;
  std::vector<wchar_t> path(32768), windows(32768);
  DWORD size = static_cast<DWORD>(path.size());
  const UINT windows_size = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
  if (!windows_size || windows_size >= windows.size() ||
      !QueryFullProcessImageNameW(process.get(), 0, path.data(), &size) ||
      !EqualPath(std::wstring(path.data(), size), std::wstring(windows.data(), windows_size) + L"\\explorer.exe")) return 15;
  HANDLE raw = nullptr;
  if (!OpenProcessToken(process.get(), TOKEN_QUERY, &raw)) return 15;
  Handle token(raw);
  DWORD bytes = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &bytes);
  if (!bytes || bytes > 65536) return 15;
  std::vector<unsigned char> user(bytes);
  if (!GetTokenInformation(token.get(), TokenUser, user.data(), bytes, &bytes)) return 15;
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &text)) return 15;
  const std::wstring sid(text);
  LocalFree(text);
  DWORD current_pid = 0;
  if (GetShellWindow() != shell || !GetWindowThreadProcessId(shell, &current_pid) ||
      current_pid != pid || WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT) return 15;
  return Install(sid);
}
int Uninstall() {
  Image self;
  if (!OpenTrustedImage(SelfPath(), self)) return 10;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  SC_HANDLE service = manager ? OpenServiceW(manager, kServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE) : nullptr;
  if (!service) {
    const DWORD error = GetLastError();
    const bool absent = manager && error == ERROR_SERVICE_DOES_NOT_EXIST;
    if (manager) CloseServiceHandle(manager);
    return absent ? 0 : 11;
  }
  DWORD bytes = 0;
  QueryServiceConfigW(service, nullptr, 0, &bytes);
  std::vector<unsigned char> config(bytes);
  bool valid = bytes && QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data()), bytes, &bytes);
  const std::wstring expected = L"\"" + SelfPath() + L"\" --service ";
  valid = valid && std::wstring(reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data())->lpBinaryPathName).starts_with(expected);
  if (valid) {
    SERVICE_STATUS status{};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) valid = false;
    SERVICE_STATUS_PROCESS current{};
    bool stopped = false;
    for (unsigned i = 0; valid && i < 100; ++i) {
      if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&current), sizeof(current), &bytes)) break;
      if (current.dwCurrentState == SERVICE_STOPPED) { stopped = true; break; }
      Sleep(200);
    }
    valid = valid && stopped && DeleteService(service);
  }
  CloseServiceHandle(service); CloseServiceHandle(manager);
  return valid ? 0 : 14;
}
}
}
int wmain(int argc, wchar_t** argv) {
  using namespace liwetun;
  if (argc == 3 && std::wstring(argv[1]) == L"--install") return Install(argv[2]);
  if (argc == 2 && std::wstring(argv[1]) == L"--install-desktop-owner") return InstallDesktopOwner();
  if (argc == 2 && std::wstring(argv[1]) == L"--uninstall") return Uninstall();
  if (argc != 3 || std::wstring(argv[1]) != L"--service" || !UserSid(argv[2])) return 2;
  owner_sid = argv[2];
  SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(kServiceName), Main}, {nullptr, nullptr}};
  return StartServiceCtrlDispatcherW(table) ? 0 : 3;
}
