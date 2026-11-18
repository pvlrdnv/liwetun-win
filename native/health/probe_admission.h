#pragma once
#include <cstdint>

namespace liwetun::health {
// Closed CI preflight observations; never OS text, credentials or identifiers.
enum class ProbeInitialization : uint32_t {
  Unknown = 0, WinsockUnavailable = 1, Cancelled = 2, CoreUnavailable = 3,
  InstanceUnavailable = 4, StateNotReady = 5, TrafficUnavailable = 6,
  TrafficNotReady = 7, AttachmentUnavailable = 8, AttachmentNotReady = 9,
  EpochMismatch = 10, EntropyUnavailable = 11, EmptyToken = 12, Passed = 13
};
inline bool AdmissionMayBecomeReady(ProbeInitialization value) noexcept {
  return value == ProbeInitialization::StateNotReady || value == ProbeInitialization::TrafficNotReady ||
      value == ProbeInitialization::AttachmentNotReady || value == ProbeInitialization::EpochMismatch;
}
// read() borrows the current SDK under its lifetime lock, then releases it.
// pause() never runs inside read(). No socket/tuple registration/health proof.
template<class Read, class Clock, class Cancel, class Pause>
ProbeInitialization WaitForProbeAdmission(Read read, Clock clock, Cancel cancelled, Pause pause,
                                        uint64_t budget_ms) {
  using Result = ProbeInitialization;
  if (!budget_ms || budget_ms > 5000) return Result::Unknown;
  const uint64_t started = clock();
  Result last = Result::Unknown;
  for (unsigned observation = 0; observation < 251; ++observation) {
    if (cancelled()) return Result::Cancelled;
    uint64_t now = clock();
    if (now < started) return Result::Unknown;
    if (now - started >= budget_ms) return last;
    last = read();
    if (cancelled()) return Result::Cancelled;
    if (static_cast<uint32_t>(last) > static_cast<uint32_t>(Result::Passed)) return Result::Unknown;
    now = clock();
    if (now < started) return Result::Unknown;
    if (now - started >= budget_ms) return last == Result::Passed ? Result::Unknown : last;
    if (!AdmissionMayBecomeReady(last)) return last;
    pause();
  }
  return Result::Unknown; // Frozen/broken clock cannot cause an unbounded wait.
}
} // namespace liwetun::health
