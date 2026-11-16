#include "wfp_probe.h"
#include "client.h"
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
}
int InspectOwnedWfpSessions() {
  using namespace liwetun;
  const char* stage = "disposable_ci";
  try {
    wchar_t environment[8]{};
    if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", environment, 8) != 4 ||
        std::wstring(environment) != L"true") throw 1;
    // Reuse the full trusted live-service proof, without starting it or sending
    // any profile. Never accept a caller-supplied PID/provider/filter name.
    stage = "authenticated_service_query";
    const auto reply = ServiceRequest(Command::Query);
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
    Enumeration enumeration;
    stage = "read_wfp_sessions";
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
        // Exact label from the pinned SDK's VpnWinTunnel/WfpFirewall source.
        // Do not retain or print other names, SIDs, usernames or session IDs.
        if (session && session->processId == status.dwProcessId && session->displayData.name &&
            std::wstring(session->displayData.name) == L"AdGuard VPN dynamic session") {
          ++total;
          if (session->flags & FWPM_SESSION_FLAG_DYNAMIC) ++dynamic;
        }
      }
      if (count < 64) { exhausted = true; break; }
    }
    stage = "bounded_wfp_enumeration";
    if (!exhausted) throw 1;
    std::cout << "{\"passed\":true,\"sdk_sessions\":" << total
        << ",\"sdk_dynamic_sessions\":" << dynamic << "}\n";
    return 0;
  } catch (...) {
    std::cout << "{\"passed\":false,\"stage\":\"" << stage << "\"}\n";
    return 1;
  }
}
