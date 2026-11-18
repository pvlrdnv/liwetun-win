#pragma once
namespace liwetun {
// Refusal-only preflight for visible aliases and the internal Wintun name.
// Absence does not establish ownership or exclude a subsequent creation race.
// No adapter is opened/configured by this call.
bool ReservedAdapterNamesAbsent() noexcept;
}
