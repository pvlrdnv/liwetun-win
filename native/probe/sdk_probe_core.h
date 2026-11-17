#pragma once
#include "probe_slot.h"

namespace ag {
struct Vpn;
// Internal C++ bridge, no public generic tuple registration export.
liwetun::probe::ArmResult liwetun_owned_probe_arm(Vpn*, const liwetun::probe::Request&, const liwetun::probe::Key&) noexcept;
liwetun::probe::Snapshot liwetun_owned_probe_read(Vpn*, uint64_t, uint64_t, const liwetun::probe::Key&) noexcept;
void liwetun_owned_probe_disarm(Vpn*, uint64_t) noexcept;
} // namespace ag
