#pragma once
#include "attached_tun_abi.h"
#include "traffic_abi.h"

namespace liwetun::health {
inline AttachedTun AttachedSnapshot(const traffic::Snapshot& before,
    const traffic::Snapshot& after, bool attached, uint32_t index, uint64_t luid) noexcept {
  AttachedTun result;
  if (!attached || !index || !luid || before.abi != traffic::kAbi || after.abi != traffic::kAbi ||
      before.size != sizeof(traffic::Snapshot) || after.size != sizeof(traffic::Snapshot) ||
      before.flags != 3 || after.flags != 3 ||
      before.state != 2 || after.state != 2 || !before.epoch ||
      before.epoch != after.epoch || after.epoch > traffic::kMaximum ||
      before.at_ms > after.at_ms || after.at_ms > traffic::kMaximum ||
      before.tx > after.tx || before.rx > after.rx ||
      after.tx > traffic::kMaximum || after.rx > traffic::kMaximum) return result;
  result.flags = 3;
  result.index = index;
  result.luid = luid;
  result.epoch = after.epoch;
  result.at_ms = after.at_ms;
  return result;
}
} // namespace liwetun::health
