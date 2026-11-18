#include "probe_admission.h"
#include <array>
#include <cassert>
#include <initializer_list>

using namespace liwetun::health;
using R = ProbeInitialization;
int main() {
  uint64_t time = 0;
  unsigned reads = 0, pauses = 0;
  bool cancel = false;
  auto clock = [&] { return time; };
  auto cancelled = [&] { return cancel; };
  auto pause = [&] { ++pauses; time += 20; };
  const std::array<R, 5> sequence{R::StateNotReady, R::TrafficNotReady,
      R::AttachmentNotReady, R::EpochMismatch, R::Passed};
  unsigned selected_epoch = 0;
  const auto eventually_ready = [&] {
    assert(reads < sequence.size());
    selected_epoch = reads + 1;
    return sequence[reads++];
  };
  assert(WaitForProbeAdmission(eventually_ready, clock, cancelled, pause, 5000) == R::Passed);
  assert(reads == 5 && pauses == 4 && selected_epoch == 5);
  time = 0; reads = 0; pauses = 0;
  const auto pending = [&] { ++reads; return R::StateNotReady; };
  assert(WaitForProbeAdmission(pending, clock, cancelled, pause, 100) == R::StateNotReady);
  assert(time == 100 && reads == 5);
  cancel = true; reads = 0;
  assert(WaitForProbeAdmission(pending, clock, cancelled, pause, 100) == R::Cancelled && !reads);
  cancel = false; time = 0;
  assert(WaitForProbeAdmission([&] { cancel = true; return R::Passed; }, clock, cancelled, pause, 100) == R::Cancelled);
  cancel = false;
  for (const auto terminal : {R::Unknown, R::CoreUnavailable, R::InstanceUnavailable,
       R::TrafficUnavailable, R::AttachmentUnavailable, R::EntropyUnavailable, R::EmptyToken}) {
    reads = 0; pauses = 0;
    assert(WaitForProbeAdmission([&] { ++reads; return terminal; }, clock, cancelled, pause, 5000) == terminal);
    assert(reads == 1 && !pauses);
  }
  time = 0;
  assert(WaitForProbeAdmission([&] { time = 100; return R::Passed; }, clock, cancelled, pause, 100) == R::Unknown);
  time = 100;
  assert(WaitForProbeAdmission([&] { time = 99; return R::Passed; }, clock, cancelled, pause, 100) == R::Unknown);
  time = 0; reads = 0;
  assert(WaitForProbeAdmission(pending, clock, cancelled, [] {}, 100) == R::Unknown);
  assert(reads == 251);
  reads = 0;
  assert(WaitForProbeAdmission(pending, clock, cancelled, pause, 0) == R::Unknown && !reads);
  assert(WaitForProbeAdmission(pending, clock, cancelled, pause, 5001) == R::Unknown && !reads);
  assert(WaitForProbeAdmission([] { return static_cast<R>(99); }, clock, cancelled, pause, 100) == R::Unknown);
}
