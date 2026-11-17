#pragma once
#include "probe_abi.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <utility>

namespace liwetun::probe {
// Internal, derived from the caller's held exclusive TCP socket. Never exported.
struct Key {
  uint32_t family = 0; // 4 or 6, address bytes in network order, ports in host order.
  std::array<uint8_t, 16> source{}, destination{};
  uint16_t source_port = 0, destination_port = 0;
  bool operator==(const Key&) const = default;
};
inline bool ValidKey(const Key& k) {
  if ((k.family != 4 && k.family != 6) || !k.source_port || !k.destination_port) return false;
  const size_t count = k.family == 4 ? 4 : 16;
  const auto nonzero = [count](const auto& bytes) {
    return std::any_of(bytes.begin(), bytes.begin() + count, [](auto b) { return b != 0; });
  };
  if (!nonzero(k.source) || !nonzero(k.destination)) return false;
  if (k.family == 4) {
    if (k.source[0] >= 224 || k.destination[0] >= 224) return false;
    for (size_t i = 4; i < 16; ++i) if (k.source[i] || k.destination[i]) return false;
  } else if (k.source[0] == 0xff || k.destination[0] == 0xff) return false;
  return true;
}

class Slot {
 public:
  using Clock = std::function<uint64_t()>;
  explicit Slot(Clock clock = SteadyMillis) : clock_(std::move(clock)) {}
  bool Active() const noexcept { return armed_.load() && !fault_.load(); }
  ArmResult Arm(const Request& request, const Key& key) noexcept {
    if (!ValidRequest(request) || !ValidKey(key)) return ArmResult::Invalid;
    try {
      std::lock_guard lock(mutex_);
      uint64_t now = 0;
      if (!Time(now)) { Fail(kFault); return ArmResult::NotReady; }
      Expire(now);
      if (Active()) return ArmResult::Busy;
      if (request.token == last_token_) return ArmResult::Invalid;
      if (now > kMaximum - request.ttl_ms) { Fail(kFault); fault_ = true; return ArmResult::NotReady; }
      value_ = Snapshot{};
      value_.flags |= kArmed;
      value_.token = last_token_ = request.token;
      value_.epoch = request.epoch;
      value_.at_ms = now;
      deadline_ = now + request.ttl_ms;
      key_ = key;
      armed_ = true;
      return ArmResult::Armed;
    } catch (...) { fault_ = true; armed_ = false; return ArmResult::NotReady; }
  }
  void Bytes(const Key& key, bool endpoint, uint64_t tx, uint64_t rx) noexcept {
    if (!Active() || (!tx && !rx)) return;
    try {
      std::lock_guard lock(mutex_);
      if (!Active() || key != key_) return;
      uint64_t now = 0;
      if (!Time(now)) { Fail(kFault); return; }
      Expire(now);
      if (!Active()) return;
      if (!endpoint) { Fail(kOtherPath); return; }
      if (tx > kMaximum - value_.tx || rx > kMaximum - value_.rx) {
        Fail(kFault); fault_ = true; return;
      }
      value_.tx += tx; value_.rx += rx;
      value_.at_ms = now;
      if (tx) value_.flags |= kEndpointTx;
      if (rx) value_.flags |= kEndpointRx;
    } catch (...) { fault_ = true; armed_ = false; }
  }
  void Reject(const Key& key, uint32_t reason) noexcept {
    if (!Active()) return;
    try {
      std::lock_guard lock(mutex_);
      if (!Active() || key != key_) return;
      uint64_t now = 0;
      if (!Time(now)) { Fail(kFault); return; }
      Expire(now);
      if (Active()) Fail(reason == kMigrated ? kMigrated : kOtherPath);
    } catch (...) { fault_ = true; armed_ = false; }
  }
  Snapshot Read(uint64_t token, uint64_t epoch, const Key& key) noexcept {
    try {
      std::lock_guard lock(mutex_);
      if (fault_) { Fail(kFault); return value_; }
      if (!token || token != value_.token) return Snapshot{};
      uint64_t now = 0;
      if (!Time(now)) { Fail(kFault); return value_; }
      Expire(now);
      if (epoch != value_.epoch) Fail(kEpochChanged);
      else if (Active() && key != key_) Fail(kSocketChanged);
      value_.at_ms = now;
      return value_;
    } catch (...) { fault_ = true; armed_ = false; Snapshot r; r.flags |= kFault; return r; }
  }
  void Disarm(uint64_t token) noexcept {
    try {
      std::lock_guard lock(mutex_);
      if (token != value_.token) return;
      armed_ = false; key_ = Key{}; value_ = Snapshot{};
    } catch (...) { fault_ = true; armed_ = false; }
  }
 private:
  static uint64_t SteadyMillis() {
    const auto n = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return n < 0 ? UINT64_MAX : static_cast<uint64_t>(n);
  }
  bool Time(uint64_t& now) {
    if (fault_) return false;
    now = clock_();
    if (now > kMaximum || now < last_at_) { fault_ = true; return false; }
    last_at_ = now;
    return true;
  }
  void Fail(uint32_t reason) {
    armed_ = false;
    key_ = Key{};
    value_.flags = kSupported | reason;
    value_.tx = value_.rx = 0;
  }
  void Expire(uint64_t now) { if (Active() && now >= deadline_) Fail(kExpired); }
  Clock clock_;
  std::mutex mutex_;
  std::atomic<bool> armed_{false}, fault_{false};
  Key key_;
  Snapshot value_;
  uint64_t last_token_ = 0, last_at_ = 0, deadline_ = 0;
};
} // namespace liwetun::probe
