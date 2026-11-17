#include "attached_tun_snapshot.h"
#include "attached_tun_validate.h"
#include <cstdlib>

void Require(bool value) { if (!value) std::abort(); }
int main() {
  liwetun::traffic::Snapshot before;
  before.flags = 3; before.state = 2; before.epoch = 3; before.at_ms = 100;
  auto after = before; after.at_ms = 101; after.tx = 32; after.last_tx_ms = 101;
  const auto observe = [&](bool attached, uint32_t index, uint64_t luid) {
    return liwetun::health::AttachedSnapshot(before, after, attached, index, luid);
  };
  auto valid = observe(true, 7, 123);
  Require(valid.flags == 3 && valid.index == 7 && valid.luid == 123 &&
      valid.epoch == 3 && valid.at_ms == 101);
  const auto unknown = [](const auto& value) {
    Require(value.flags == 1 && value.index == 0 && value.luid == 0 &&
        value.epoch == 0 && value.at_ms == UINT64_MAX);
  };
  unknown(observe(false, 7, 123));
  unknown(observe(true, 0, 123));
  unknown(observe(true, 7, 0));
  after.epoch = 4; unknown(observe(true, 7, 123)); after.epoch = 3;
  after.flags = 1; unknown(observe(true, 7, 123)); after.flags = 3;
  before.flags = 1; unknown(observe(true, 7, 123)); before.flags = 3;
  after.state = 3; unknown(observe(true, 7, 123)); after.state = 2;
  after.abi = 2; unknown(observe(true, 7, 123)); after.abi = 1;
  after.size = 63; unknown(observe(true, 7, 123)); after.size = 64;
  before.epoch = 0; unknown(observe(true, 7, 123)); before.epoch = 3;
  after.at_ms = 99; unknown(observe(true, 7, 123)); after.at_ms = 101;
  before.tx = 33; unknown(observe(true, 7, 123)); before.tx = 0;
  after.rx = UINT64_MAX; unknown(observe(true, 7, 123));
  after.rx = 0;
  const auto context = observe(true, 7, 123);
  Require(liwetun::health::MatchesReadyCounter(context, after));
  for (unsigned test = 0; test < 8; ++test) {
    auto changed = context;
    switch (test) {
      case 0: changed.abi = 2; break;
      case 1: changed.size = 39; break;
      case 2: changed.flags = 1; break;
      case 3: changed.index = 0; break;
      case 4: changed.luid = 0; break;
      case 5: ++changed.epoch; break;
      case 6: --changed.at_ms; break;
      case 7: changed.at_ms += 5001; break;
    }
    Require(!liwetun::health::MatchesReadyCounter(changed, after));
  }
  after.flags = 1;
  Require(!liwetun::health::MatchesReadyCounter(context, after));
  return 0;
}
