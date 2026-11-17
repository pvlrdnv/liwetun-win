#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

// LiWeTun aggregate-only ABI: no pointers, connection identifiers or strings.
namespace liwetun::traffic {
constexpr uint32_t kAbi = 1;
constexpr uint32_t kSupported = 1;
constexpr uint32_t kValid = 2;
constexpr uint32_t kOverflow = 4;
constexpr uint32_t kClockError = 8;
constexpr uint32_t kStateError = 16;
constexpr uint32_t kObservationGap = 32;
constexpr uint64_t kAbsent = UINT64_MAX;
constexpr uint64_t kMaximum = static_cast<uint64_t>(INT64_MAX);
struct Snapshot {
  uint32_t abi = kAbi;
  uint32_t size = 64;
  uint32_t flags = 0;
  uint32_t state = UINT32_MAX;
  uint64_t epoch = 0;
  uint64_t at_ms = 0;
  uint64_t tx = 0;
  uint64_t rx = 0;
  uint64_t last_tx_ms = kAbsent;
  uint64_t last_rx_ms = kAbsent;
};
static_assert(sizeof(Snapshot) == 64);
static_assert(offsetof(Snapshot, epoch) == 16);
static_assert(offsetof(Snapshot, last_rx_ms) == 56);
static_assert(std::is_standard_layout_v<Snapshot> && std::is_trivially_copyable_v<Snapshot>);
}  // namespace liwetun::traffic
