#pragma once
#include <cstdint>

namespace liwetun {
constexpr wchar_t kServiceName[] = L"LiWeTun";
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\LiWeTun.Control.v1";
constexpr uint32_t kMagic = 0x3154574c;
constexpr uint32_t kVersion = 1;
constexpr uint32_t kMaxPayload = 8192;
enum class Command : uint32_t { Ping = 1, Query = 2, Start = 3, Stop = 4 };
enum class Code : uint32_t {
  Ok, Malformed, Denied, Busy, RuntimeUnavailable, ProfileRejected, CoreFailure,
  ServiceUnavailable, Timeout, UntrustedInstallation
};
enum class State : uint32_t { Disconnected, Connecting, TunnelReady, Recovering, Error };
// TunnelReady is NOT verified working internet; no Connected state is inferred.
struct Request {
  uint32_t magic = kMagic;
  uint32_t version = kVersion;
  Command command = Command::Ping;
  uint32_t length = 0;
  uint64_t nonce = 0;
};
struct Reply {
  uint32_t magic = kMagic;
  uint32_t version = kVersion;
  Code code = Code::Ok;
  State state = State::Disconnected;
  uint64_t nonce = 0;
  uint32_t runtime_ready = 0;
  uint32_t core_state = 0;
};
static_assert(sizeof(Request) == 24);
static_assert(sizeof(Reply) == 32);
inline bool Valid(const Request& r) {
  const auto command = static_cast<uint32_t>(r.command);
  return r.magic == kMagic && r.version == kVersion && r.nonce != 0 &&
      command >= 1 && command <= 4 && r.length <= kMaxPayload &&
      (r.command == Command::Start ? r.length >= 20 : r.length == 0);
}
}  // namespace liwetun
