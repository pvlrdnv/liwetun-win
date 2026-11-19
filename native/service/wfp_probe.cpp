#include "wfp_probe.h"
#include "client.h"
#include "security.h"
#include <windows.h>
#include <fwpmu.h>
#include <iostream>

namespace {
struct Enumeration {
  HANDLE engine = nullptr;
  HANDLE iterator = nullptr;
  ~Enumeration() {
    if (iterator) FwpmSessionDestroyEnumHandle0(engine, iterator);
    if (engine) FwpmEngineClose0(engine);
  }
};
struct Entries {
  FWPM_SESSION0** value = nullptr;
  ~Entries() { if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
};

void PrintSessions(DWORD process_id, HANDLE retained, bool watch) {
  Enumeration enumeration;
  if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &enumeration.engine) != ERROR_SUCCESS ||
      FwpmSessionCreateEnumHandle0(enumeration.engine, nullptr, &enumeration.iterator) != ERROR_SUCCESS) throw 1;
  UINT32 total = 0, dynamic = 0;
  bool exhausted = false;
  for (unsigned page = 0; page < 64; ++page) {
    Entries entries;
    UINT32 count = 0;
    if (FwpmSessionEnum0(enumeration.engine, enumeration.iterator, 64, &entries.value, &count) != ERROR_SUCCESS || count > 64) throw 1;
    for (UINT32 i = 0; i < count; ++i) {
      const auto* session = entries.value[i];
      if (session && session->processId == process_id && session->displayData.name &&
          std::wstring(session->displayData.name) == L"AdGuard VPN dynamic session") {
        ++total;
        if (session->flags & FWPM_SESSION_FLAG_DYNAMIC) ++dynamic;
      }
    }
    if (count < 64) { exhausted = true; break; }
  }
  if (!exhausted) throw 1;
  const DWORD wait = watch ? WaitForSingleObject(retained, 0) : WAIT_TIMEOUT;
  if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT) throw 1;
  std::cout << "{\"passed\":true,\"sdk_sessions\":" << total
      << ",\"sdk_dynamic_sessions\":" << dynamic;
  if (watch) std::cout << ",\"retained_process_alive\":" << (wait == WAIT_TIMEOUT ? "true" : "false");
  std::cout << "}" << std::endl;
}
}
int InspectOwnedWfpSessions(bool watch) {
  using namespace liwetun;
  const char* stage = "disposable_ci";
  uint32_t query_code = UINT32_MAX;
  try {
    wchar_t environment[8]{};
    if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", environment, 8) != 4 ||
        std::wstring(environment) != L"true") throw 1;
    // Reuse the full trusted live-service proof, without starting it or sending
    // any profile. Never accept a caller-supplied PID/provider/filter name.
    stage = "authenticated_service_query";
    const auto reply = ServiceRequest(Command::Query);
    query_code = static_cast<uint32_t>(reply.code);
    if (reply.code != Code::Ok && reply.code != Code::CoreFailure) throw 1;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, L"LiWeTun", SERVICE_QUERY_STATUS) : nullptr;
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    const bool running = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes) && status.dwCurrentState == SERVICE_RUNNING;
    if (service) CloseServiceHandle(service);
    if (manager) CloseServiceHandle(manager);
    stage = "owned_service_pid";
    if (!running || !status.dwProcessId) throw 1;
    Handle retained;
    if (watch) {
      stage = "retain_trusted_service";
      retained.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, status.dwProcessId));
      wchar_t path[32768]{};
      DWORD length = 32768;
      Image self, service_image;
      if (!retained || !QueryFullProcessImageNameW(retained.get(), 0, path, &length) ||
          !EqualPath(path, Directory(SelfPath()) + L"\\liwetun_service.exe") ||
          !OpenTrustedImage(SelfPath(), self) || !OpenTrustedImage(path, service_image) ||
          !SameSigner(self, service_image) || !IsSystemProcess(retained.get()) ||
          WaitForSingleObject(retained.get(), 0) != WAIT_TIMEOUT) throw 1;
    }
    stage = "read_wfp_sessions";
    // The retained, authenticated own-service identity stays fixed across death.
    // Never accept a PID/filter name or print unrelated WFP metadata.
    PrintSessions(status.dwProcessId, retained.get(), watch);
    if (watch) {
      char command[16]{};
      while (std::cin.getline(command, static_cast<std::streamsize>(sizeof(command)))) {
        if (std::string(command) == "quit") break;
        if (std::string(command) != "query") throw 1;
        PrintSessions(status.dwProcessId, retained.get(), true);
      }
      if (!std::cin.eof() && std::cin.fail()) throw 1;
    }
    return 0;
  } catch (...) {
    std::cout << "{\"passed\":false,\"stage\":\"" << stage << "\",\"query_code\":";
    if (query_code <= static_cast<uint32_t>(Code::AdapterProblem)) std::cout << query_code;
    else std::cout << "null";
    std::cout << "}\n";
    return 1;
  }
}
