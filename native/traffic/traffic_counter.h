#pragma once
#include "traffic_abi.h"
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <utility>

namespace liwetun::traffic {
class Counter {
 public:
  using Clock = std::function<uint64_t()>;
  explicit Counter(Clock clock = SteadyMillis) : clock_(std::move(clock)) {
    value_.flags = kSupported;
    value_.epoch = 1;
  }
  void State(int state) noexcept {
    try {
      std::lock_guard lock(mutex_);
      ObserveTime();
      if (state < 0 || state > 5) {
        value_.state = UINT32_MAX;
        value_.flags |= kStateError;
        return;
      }
      if (value_.state != static_cast<uint32_t>(state)) {
        if (value_.epoch == kMaximum) value_.flags |= kOverflow;
        else ++value_.epoch;
        value_.state = static_cast<uint32_t>(state);
      }
    } catch (...) { gap_ = true; }
  }
  void Add(uint64_t tx, uint64_t rx) noexcept {
    try {
      std::lock_guard lock(mutex_);
      ObserveTime();
      if (value_.flags & (kOverflow | kClockError)) return;
      // A rejected delta must not partially change a total.
      if (tx > kMaximum - value_.tx || rx > kMaximum - value_.rx) {
        value_.flags |= kOverflow;
        return;
      }
      value_.tx += tx;
      value_.rx += rx;
      if (tx) value_.last_tx_ms = value_.at_ms;
      if (rx) value_.last_rx_ms = value_.at_ms;
    } catch (...) { gap_ = true; }
  }
  Snapshot Read() noexcept {
    try {
      std::lock_guard lock(mutex_);
      ObserveTime();
      Snapshot result = value_;
      if (gap_) result.flags |= kObservationGap;
      if (result.state == 2 && !(result.flags & (kOverflow | kClockError | kStateError | kObservationGap))) {
        result.flags |= kValid;
      }
      return result;
    } catch (...) {
      gap_ = true;
      Snapshot result;
      result.flags = kSupported | kObservationGap;
      return result;
    }
  }
 private:
  static uint64_t SteadyMillis() {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return ms < 0 ? kAbsent : static_cast<uint64_t>(ms);
  }
  void ObserveTime() {
    // Time is read under the state/counter lock so a waiting reader cannot
    // mistake another thread's later callback for a monotonic clock regression.
    const uint64_t now = clock_();
    if (now > kMaximum || now < value_.at_ms) {
      value_.flags |= kClockError;
      return;
    }
    value_.at_ms = now;
  }
  Clock clock_;
  std::mutex mutex_;
  Snapshot value_;
  std::atomic<bool> gap_{false};
};
}  // namespace liwetun::traffic
