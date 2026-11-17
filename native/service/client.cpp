#include "client.h"
#include "pipe_io.h"
#include "traffic_client.h"
#include <bcrypt.h>

namespace liwetun {
Reply ServiceRequest(Command command, const std::string& profile, bool start_service, TrafficReply* traffic_reply) {
  Reply reply{};
  reply.code = Code::UntrustedInstallation;
  reply.core_state = UINT32_MAX;
  Image client;
  if (!OpenTrustedImage(SelfPath(), client)) return reply;
  if (start_service) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS) : nullptr;
    bool started = false;
    if (service) {
      started = StartServiceW(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
      if (started) {
        SERVICE_STATUS_PROCESS status{};
        DWORD bytes = 0;
        started = false;
        for (unsigned i = 0; i < 30; ++i) {
          if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes)) break;
          if (status.dwCurrentState == SERVICE_RUNNING) { started = true; break; }
          if (status.dwCurrentState == SERVICE_STOPPED) break;
          Sleep(100);
        }
      }
      CloseServiceHandle(service);
    }
    if (manager) CloseServiceHandle(manager);
    if (!started) { reply.code = Code::ServiceUnavailable; return reply; }
  }
  Handle pipe = OpenControlPipe();
  reply.code = Code::ServiceUnavailable;
  if (!pipe || pipe.get() == INVALID_HANDLE_VALUE) return reply;
  if (!VerifyServer(pipe.get(), client)) { reply.code = Code::Denied; return reply; }
  Request request{};
  request.command = command;
  if (profile.size() > kMaxPayload) { reply.code = Code::Malformed; return reply; }
  request.length = static_cast<uint32_t>(profile.size());
  if (BCryptGenRandom(nullptr, reinterpret_cast<BYTE*>(&request.nonce), sizeof(request.nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !Valid(request)) {
    reply.code = Code::Malformed; return reply;
  }
  if (!PipeIo(pipe.get(), nullptr, &request, sizeof(request), true) ||
      (!profile.empty() && !PipeIo(pipe.get(), nullptr, const_cast<char*>(profile.data()), request.length, true)) ||
      !PipeIo(pipe.get(), nullptr, &reply, sizeof(reply), false)) {
    reply = Reply{}; reply.code = Code::Timeout; reply.core_state = UINT32_MAX; return reply;
  }
  if (reply.magic != kMagic || reply.version != kVersion || reply.nonce != request.nonce ||
      static_cast<uint32_t>(reply.code) > static_cast<uint32_t>(Code::UntrustedInstallation) ||
      static_cast<uint32_t>(reply.state) > static_cast<uint32_t>(State::Error) || reply.runtime_ready > 1 ||
      (reply.core_state != UINT32_MAX && reply.core_state > 5)) {
    reply = Reply{}; reply.code = Code::Malformed; reply.core_state = UINT32_MAX;
  }
  if (command == Command::Traffic && traffic_reply) {
    reply = ConsumeTrafficTail(reply, *traffic_reply, [&](void* destination, uint32_t length) {
      return PipeIo(pipe.get(), nullptr, destination, length, false);
    });
  }
  return reply;
}
TrafficReply ServiceTrafficRequest() {
  TrafficReply result;
  result.status = ServiceRequest(Command::Traffic, {}, false, &result);
  return result;
}

}
