#pragma once
#include "attached_tun_abi.h"
#include "../traffic/traffic_validate.h"

namespace liwetun::health {
// CI observation fence only. No ownership, route selection or Internet proof.
inline bool MatchesReadyCounter(const AttachedTun& attachment, const traffic::Snapshot& counter) {
  return attachment.abi == 1 && attachment.size == sizeof(AttachedTun) &&
      attachment.flags == 3 && attachment.index != 0 && attachment.luid != 0 &&
      traffic::Valid(counter) && counter.flags == 3 &&
      attachment.epoch == counter.epoch &&
      attachment.at_ms <= traffic::kMaximum && attachment.at_ms >= counter.at_ms &&
      attachment.at_ms - counter.at_ms <= 5000;
}
} // namespace liwetun::health
