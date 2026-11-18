#include "windows_fresh_adapter.h"
#include <ipifcons.h>
#include <cassert>

static void* WINAPI NeverCreate(LPCWSTR, LPCWSTR, const GUID*) { assert(false); return nullptr; }
static void WINAPI NeverClose(void*) { assert(false); }
static void WINAPI ZeroLuid(void*, NET_LUID* luid) { *luid = {}; }
int main() {
  liwetun::adapter::WindowsOps ops(&NeverCreate, &NeverClose, &ZeroLuid, L"LiWeTun");
  std::array<uint8_t, 32> first{}, second{};
  assert(ops.Random(first) && ops.Random(second) && first != second);
  liwetun::adapter::Observation observation{};
  assert(!ops.Observe(nullptr, observation));
  int sentinel = 0;
  assert(!ops.Observe(&sentinel, observation));
  assert(!observation.index && !observation.luid);
  MIB_IF_TABLE2* table = nullptr;
  assert(GetIfTable2(&table) == NO_ERROR && table && table->NumEntries);
  liwetun::adapter::Identity occupied{};
  std::memcpy(occupied.guid.data(), &table->Table[0].InterfaceGuid, sizeof(GUID));
  liwetun::adapter::Identity occupied_alias{};
  bool alias_testable = false;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const auto& row = table->Table[i];
    const size_t length = wcsnlen_s(row.Alias, IF_MAX_STRING_SIZE + 1);
    if (!length || length > liwetun::adapter::kAliasCharacters || row.Type == IF_TYPE_PROP_VIRTUAL) continue;
    for (size_t p = 0; p < length; ++p) occupied_alias.name[p] = row.Alias[p];
    alias_testable = true;
    break;
  }
  FreeMibTable(table);
  assert(!ops.Vacant(occupied)); // read-only actual OS collision binding
  assert(alias_testable && !ops.Vacant(occupied_alias)); // different adapter type, alias-only
  // Deliberately never call Create: no adapter/driver or network configuration.
}
