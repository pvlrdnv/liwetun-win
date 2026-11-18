#pragma once
namespace liwetun {
// Refusal-only preflight. Alias absence does not establish adapter ownership
// or exclude a subsequent race. No adapter is opened/configured by this call.
bool ReservedAdapterAliasAbsent() noexcept;
}
