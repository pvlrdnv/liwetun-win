#include "probe_slot.h"
#include <cstdlib>
#include <thread>
#include <vector>

using namespace liwetun::probe;
void Require(bool value) { if (!value) std::abort(); }
Key TestKey() {
  Key k;
  k.family = 4; k.source = {198, 18, 0, 1}; k.destination = {198, 18, 0, 9};
  k.source_port = 41000; k.destination_port = 38555;
  return k;
}
Request Attempt(uint64_t token = 11, uint64_t epoch = 3) {
  Request r; r.token = token; r.epoch = epoch; return r;
}
bool Evidence(const Snapshot& s) { return s.flags == (kSupported | kArmed | kEndpointTx | kEndpointRx); }
int main() {
  const auto key = TestKey();
  uint64_t now = 100;
  Slot slot([&] { return now; });
  Require(slot.Read(11, 3, key).flags == kSupported);
  Require(slot.Arm(Attempt(), key) == ArmResult::Armed);
  Require(slot.Arm(Attempt(12), key) == ArmResult::Busy);
  auto foreign = key; ++foreign.source_port;
  slot.Bytes(foreign, true, 90000, 90000);
  slot.Reject(foreign, kMigrated);
  auto first = slot.Read(11, 3, key);
  Require(first.tx == 0 && first.rx == 0 && !Evidence(first));
  slot.Bytes(key, true, 1, 0);
  Require(!Evidence(slot.Read(11, 3, key)));
  slot.Bytes(key, true, 0, 2);
  auto complete = slot.Read(11, 3, key);
  Require(Evidence(complete) && complete.tx == 1 && complete.rx == 2);
  Require(slot.Read(12, 3, key).flags == kSupported);
  slot.Disarm(12);
  Require(Evidence(slot.Read(11, 3, key)));
  slot.Reject(key, kMigrated);
  slot.Bytes(key, true, 1, 1);
  auto failed = slot.Read(11, 3, key);
  Require(failed.flags == (kSupported | kMigrated) && !failed.tx && !failed.rx);
  Require(slot.Arm(Attempt(), key) == ArmResult::Invalid); // No replay extends TTL.
  Require(slot.Arm(Attempt(12), key) == ArmResult::Armed);
  slot.Bytes(key, false, 1, 1);
  Require(slot.Read(12, 3, key).flags == (kSupported | kOtherPath));
  Require(slot.Arm(Attempt(13), key) == ArmResult::Armed);
  slot.Bytes(key, true, 1, 1);
  Require(slot.Read(13, 4, key).flags == (kSupported | kEpochChanged));
  Require(slot.Arm(Attempt(14), key) == ArmResult::Armed);
  slot.Bytes(key, true, 1, 1);
  Require(slot.Read(14, 3, foreign).flags == (kSupported | kSocketChanged));
  Require(slot.Arm(Attempt(15), key) == ArmResult::Armed);
  slot.Bytes(key, true, 1, 1);
  now += 5000;
  Require(slot.Read(15, 3, key).flags == (kSupported | kExpired));
  Require(slot.Arm(Attempt(16), key) == ArmResult::Armed);
  slot.Disarm(16);
  Require(slot.Read(16, 3, key).flags == kSupported);
  auto ipv6 = key;
  ipv6.family = 6; ipv6.source = {0xfd, 0, 0, 1}; ipv6.destination = {0x20, 1, 0xd, 0xb8};
  Require(slot.Arm(Attempt(17), ipv6) == ArmResult::Armed);
  slot.Bytes(key, true, 1, 1);
  Require(!Evidence(slot.Read(17, 3, ipv6)));
  slot.Bytes(ipv6, true, 1, 1);
  Require(Evidence(slot.Read(17, 3, ipv6)));
  slot.Disarm(17);
  for (unsigned test = 0; test < 7; ++test) {
    auto r = Attempt(17); auto k = key;
    switch (test) {
      case 0: r.abi = 2; break;
      case 1: r.size = 31; break;
      case 2: r.ttl_ms = 10001; break;
      case 3: r.token = 0; break;
      case 4: r.epoch = 0; break;
      case 5: r.reserved = 1; break;
      case 6: k.source[8] = 1; break;
    }
    Require(slot.Arm(r, k) == ArmResult::Invalid);
  }
  Slot overflow([&] { return now; });
  Require(overflow.Arm(Attempt(), key) == ArmResult::Armed);
  overflow.Bytes(key, true, kMaximum, 1);
  overflow.Bytes(key, true, 1, 0);
  Require(overflow.Read(11, 3, key).flags == (kSupported | kFault));
  Require(overflow.Arm(Attempt(12), key) == ArmResult::NotReady);
  Slot regressing([&] { return now; });
  Require(regressing.Arm(Attempt(), key) == ArmResult::Armed);
  --now;
  Require(regressing.Read(11, 3, key).flags == (kSupported | kFault));
  bool throws = false;
  Slot throwing([&]() -> uint64_t { if (throws) throw 1; return now; });
  Require(throwing.Arm(Attempt(), key) == ArmResult::Armed);
  throws = true;
  throwing.Bytes(key, true, 1, 1);
  Require(throwing.Read(11, 3, key).flags == (kSupported | kFault));

  std::atomic<bool> block_clock{false}, entered{false}, release{false};
  Slot callback_failure([&] {
    if (block_clock) {
      entered = true;
      while (!release) std::this_thread::yield();
    }
    return uint64_t{100};
  });
  Require(callback_failure.Arm(Attempt(), key) == ArmResult::Armed);
  callback_failure.Bytes(key, true, 1, 1);
  block_clock = true;
  Snapshot raced;
  std::thread reader([&] { raced = callback_failure.Read(11, 3, key); });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!entered && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
  Require(entered);
  callback_failure.ObservationFailure();
  release = true;
  reader.join();
  Require(raced.flags == (kSupported | kFault) && !raced.tx && !raced.rx);
  Require(callback_failure.Read(12, 3, key).flags == kSupported);

  Slot concurrent([] { return uint64_t{100}; });
  Require(concurrent.Arm(Attempt(), key) == ArmResult::Armed);
  std::vector<std::thread> workers;
  for (unsigned i = 0; i < 4; ++i) workers.emplace_back([&] {
    for (unsigned n = 0; n < 10000; ++n) {
      concurrent.Bytes(key, true, 1, 1);
      auto result = concurrent.Read(11, 3, key);
      Require(result.tx == result.rx);
    }
  });
  for (auto& worker : workers) worker.join();
  const auto counted = concurrent.Read(11, 3, key);
  Require(Evidence(counted) && counted.tx == 40000 && counted.rx == 40000);
  concurrent.Disarm(11);
  Require(concurrent.Arm(Attempt(12), foreign) == ArmResult::Armed);
  std::thread late([&] {
    for (unsigned n = 0; n < 10000; ++n) {
      concurrent.Bytes(key, true, 100, 100);
      concurrent.Disarm(11);
      Require(concurrent.Read(11, 3, key).flags == kSupported);
    }
  });
  for (unsigned n = 0; n < 10000; ++n) concurrent.Bytes(foreign, true, 1, 1);
  late.join();
  const auto fresh = concurrent.Read(12, 3, foreign);
  Require(Evidence(fresh) && fresh.tx == 10000 && fresh.rx == 10000);
  return 0;
}
