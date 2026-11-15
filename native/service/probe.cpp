// Explicit non-networking CI client. No real connection/profile input accepted.
#include "client.h"
#include "pipe_io.h"
#include <iostream>

using namespace liwetun;
int wmain(int argc, wchar_t** argv) {
  const std::wstring mode = argc == 2 ? argv[1] : L"";
  if (mode == L"--protocol") {
    Request request{};
    request.nonce = 7;
    if (!Valid(request)) return 1;
    request.length = 1;
    if (Valid(request)) return 2;
    request.command = Command::Start;
    request.length = kMaxPayload + 1;
    if (Valid(request)) return 3;
    std::cout << "protocol_checks_passed\n";
    return 0;
  }
  if (mode == L"--query" || mode == L"--stop" || mode == L"--invalid-profile") {
    const auto command = mode == L"--stop" ? Command::Stop : mode == L"--invalid-profile" ? Command::Start : Command::Query;
    const std::string profile = mode == L"--invalid-profile" ? "tt://?SYNTHETIC_INVALID_CANARY_261115" : "";
    const Reply reply = ServiceRequest(command, profile, true);
    std::cout << "{\"code\":" << static_cast<uint32_t>(reply.code)
              << ",\"state\":" << static_cast<uint32_t>(reply.state)
              << ",\"runtime_ready\":" << reply.runtime_ready
              << ",\"core_state\":" << reply.core_state << "}\n";
    return 0;
  }
  if (mode == L"--attack" || mode == L"--bad-frame") {
    Handle pipe(CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (!pipe || pipe.get() == INVALID_HANDLE_VALUE) { std::cout << "rejected\n"; return 0; }
    Request request{};
    request.nonce = 9;
    if (mode == L"--bad-frame") request.length = kMaxPayload + 1;
    Reply reply{};
    const bool response = PipeIo(pipe.get(), nullptr, &request, sizeof(request), true) &&
        PipeIo(pipe.get(), nullptr, &reply, sizeof(reply), false);
    if (mode == L"--attack") {
      std::cout << (response ? "unexpected_acceptance\n" : "rejected\n");
      return response ? 1 : 0;
    }
    return response && reply.code == Code::Malformed ? 0 : 1;
  }
  return 4;
}
