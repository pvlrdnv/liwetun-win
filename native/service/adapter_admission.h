#pragma once
namespace liwetun {
// Refusal-only preflight for visible aliases, internal Wintun name and
// problematic/unknown Wintun PnP state, including non-present devices.
// Legacy root-enumerated Wintun nodes are refused conservatively as well.
// Absence does not establish ownership or exclude a subsequent creation race.
// No adapter is opened/configured by this call. It cannot prevent a foreign
// device becoming problematic later while original Wintun cleanup is queued.
bool ReservedAdapterNamesAbsent() noexcept;
}
