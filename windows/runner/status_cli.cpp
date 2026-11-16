#include "status_cli.h"
#include "client.h"
#include <windows.h>
#include <string>

int PrintServiceStatus() {
  auto reply = liwetun::ServiceRequest(liwetun::Command::Query);
  const bool known = reply.code == liwetun::Code::Ok || reply.code == liwetun::Code::CoreFailure;
  const std::string state = known ? std::to_string(static_cast<uint32_t>(reply.state)) : "null";
  const std::string runtime = known ? (reply.runtime_ready ? "true" : "false") : "null";
  const std::string core = known && reply.core_state <= 5 ? std::to_string(reply.core_state) : "null";
  const std::string output = "{\"code\":" + std::to_string(static_cast<uint32_t>(reply.code)) +
      ",\"state\":" + state + ",\"runtime_ready\":" + runtime + ",\"core_state\":" + core + "}\n";
  // Use the caller's inherited output pipe before any console/Flutter setup.
  // No environment, path, caller identity, profile or raw errors are emitted.
  HANDLE standard = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD written = 0;
  if (!standard || standard == INVALID_HANDLE_VALUE ||
      !WriteFile(standard, output.data(), static_cast<DWORD>(output.size()), &written, nullptr) ||
      written != output.size()) return 10; // Output unavailable, never silent success.
  return static_cast<int>(reply.code);
}
