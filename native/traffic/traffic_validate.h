#pragma once
#include "traffic_abi.h"

namespace liwetun::traffic {
inline bool Valid(const Snapshot& s) {
  if (s.abi != kAbi || s.size != sizeof(Snapshot) || (s.flags & ~uint32_t{63}) ||
      (s.state != UINT32_MAX && s.state > 5) || s.epoch > kMaximum ||
      s.at_ms > kMaximum || s.tx > kMaximum || s.rx > kMaximum ||
      (s.last_tx_ms != kAbsent && s.last_tx_ms > s.at_ms) ||
      (s.last_rx_ms != kAbsent && s.last_rx_ms > s.at_ms)) return false;
  if (!(s.flags & kSupported)) {
    return s.flags == 0 && s.state == UINT32_MAX && s.epoch == 0 && s.at_ms == 0 &&
        s.tx == 0 && s.rx == 0 && s.last_tx_ms == kAbsent && s.last_rx_ms == kAbsent;
  }
  if ((s.tx == 0) != (s.last_tx_ms == kAbsent) || (s.rx == 0) != (s.last_rx_ms == kAbsent)) return false;
  return !(s.flags & kValid) ||
      (s.state == 2 && s.epoch > 0 && !(s.flags & (kOverflow | kClockError | kStateError | kObservationGap)));
}
}  // namespace liwetun::traffic
