#include "traffic_counter.h"
#include <atomic>
#include <cstdlib>
#include <thread>
#include <vector>

using namespace liwetun::traffic;
void Check(bool condition) { if (!condition) std::abort(); }
int main() {
  uint64_t now = 100;
  Counter counter([&] { return now; });
  auto initial = counter.Read();
  Check(initial.flags == kSupported && initial.last_tx_ms == kAbsent && initial.epoch == 1);
  counter.State(2);
  auto ready = counter.Read();
  Check(ready.flags == (kSupported | kValid) && ready.tx == 0 && ready.rx == 0);
  counter.Add(3, 0); // Below upstream threshold; one-sided traffic is observed immediately.
  auto tx = counter.Read();
  Check(tx.tx == 3 && tx.rx == 0 && tx.last_tx_ms == now && tx.last_rx_ms == kAbsent);
  now += 20;
  counter.Add(0, 2);
  auto rx = counter.Read();
  Check(rx.tx == 3 && rx.rx == 2 && rx.last_rx_ms == now && rx.epoch == tx.epoch);
  counter.State(3);
  auto recovery = counter.Read();
  Check(!(recovery.flags & kValid) && recovery.epoch != rx.epoch && recovery.tx == rx.tx);
  counter.State(2);
  Check(counter.Read().epoch != recovery.epoch);
  Counter restarted([&] { return now; });
  Check(restarted.Read().tx == 0 && !(restarted.Read().flags & kValid));
  Counter overflow([&] { return now; });
  overflow.State(2);
  overflow.Add(kMaximum, 2);
  overflow.Add(1, 9);
  const auto saturated = overflow.Read();
  Check(saturated.tx == kMaximum && saturated.rx == 2 && (saturated.flags & kOverflow) && !(saturated.flags & kValid));
  Counter clock([&] { return now; });
  clock.State(2);
  --now;
  Check((clock.Read().flags & kClockError) && !(clock.Read().flags & kValid));
  Counter malformed;
  malformed.State(99);
  malformed.State(2);
  Check(!(malformed.Read().flags & kValid));
  Counter gap([]() -> uint64_t { throw 1; });
  gap.State(2);
  gap.Add(3, 4);
  Check((gap.Read().flags & kObservationGap) && !(gap.Read().flags & kValid));
  std::atomic<uint64_t> ticks{1};
  Counter concurrent([&] { return ticks.fetch_add(1); });
  concurrent.State(2);
  std::vector<std::thread> workers;
  for (int i = 0; i < 4; ++i) workers.emplace_back([&] {
    for (int j = 0; j < 10000; ++j) { concurrent.Add(1, 2); Check(concurrent.Read().flags & kValid); }
  });
  for (auto& worker : workers) worker.join();
  auto total = concurrent.Read();
  Check(total.tx == 40000 && total.rx == 80000 && (total.flags & kValid));
}
