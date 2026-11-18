#include "windows_fresh_adapter.h"
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
  FreeMibTable(table);
  assert(!ops.Vacant(occupied)); // read-only actual OS collision binding
  // Deliberately never call Create: no adapter/driver or network configuration.
}
