#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace liwetun::probe {
constexpr uint64_t kMaximum = static_cast<uint64_t>(INT64_MAX);
constexpr uint32_t kSupported = 1, kArmed = 2, kEndpointTx = 4, kEndpointRx = 8;
constexpr uint32_t kOtherPath = 16, kMigrated = 32, kExpired = 64, kFault = 128;
constexpr uint32_t kEpochChanged = 256, kSocketChanged = 512;
enum class ArmResult : uint32_t { Rejected = 0, Armed = 1, Busy = 2, Invalid = 3, NotReady = 4, SocketRejected = 5 };
struct Request {
  uint32_t abi = 1;
  uint32_t size = 32;
  uint32_t ttl_ms = 5000;
  uint32_t reserved = 0;
  uint64_t token = 0;
  uint64_t epoch = 0;
};
// No socket, interface, connection ID, address, domain or string crosses this ABI.
// Counts are observations only while Armed; no DNS/HTTPS/Internet claim.
struct Snapshot {
  uint32_t abi = 1;
  uint32_t size = 56;
  uint32_t flags = kSupported;
  uint32_t reserved = 0;
  uint64_t token = 0;
  uint64_t epoch = 0;
  uint64_t at_ms = UINT64_MAX;
  uint64_t tx = 0;
  uint64_t rx = 0;
};
inline bool ValidRequest(const Request& r) {
  return r.abi == 1 && r.size == sizeof(Request) && r.reserved == 0 &&
      r.ttl_ms >= 500 && r.ttl_ms <= 10000 && r.token && r.token <= kMaximum &&
      r.epoch && r.epoch <= kMaximum;
}
static_assert(sizeof(Request) == 32 && offsetof(Request, token) == 16);
static_assert(sizeof(Snapshot) == 56 && offsetof(Snapshot, tx) == 40);
static_assert(std::is_standard_layout_v<Request> && std::is_trivially_copyable_v<Request>);
static_assert(std::is_standard_layout_v<Snapshot> && std::is_trivially_copyable_v<Snapshot>);
} // namespace liwetun::probe
