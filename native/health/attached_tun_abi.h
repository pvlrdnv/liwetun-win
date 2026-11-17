#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace liwetun::health {
// Internal path-selection prerequisite, not proof of ownership or traversal.
// Never put the interface index/LUID in a journal or support report.
struct AttachedTun {
  uint32_t abi = 1;
  uint32_t size = 40;
  uint32_t flags = 1; // supported=1, current ready-state attachment=2
  uint32_t index = 0;
  uint64_t luid = 0;
  uint64_t epoch = 0;
  uint64_t at_ms = UINT64_MAX;
};
static_assert(sizeof(AttachedTun) == 40);
static_assert(offsetof(AttachedTun, luid) == 16);
static_assert(offsetof(AttachedTun, at_ms) == 32);
static_assert(std::is_standard_layout_v<AttachedTun> && std::is_trivially_copyable_v<AttachedTun>);
} // namespace liwetun::health
