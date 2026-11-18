#include "adapter_admission.h"
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

namespace liwetun {
bool ReservedAdapterAliasAbsent() noexcept {
  MIB_IF_TABLE2* table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR || !table) return false;
  struct Release { MIB_IF_TABLE2* value; ~Release() { FreeMibTable(value); } } release{table};
  if (table->NumEntries > 4096) return false;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    // Stable ordinal comparison; never use an alias match as ownership proof.
    const int match = CompareStringOrdinal(table->Table[i].Alias, -1, L"LiWeTun", -1, TRUE);
    if (!match || match == CSTR_EQUAL) return false;
  }
  return true;
}
}
