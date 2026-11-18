// Disposable CI factory test only. Never linked into GUI/service/SDK.
#include "windows_fresh_adapter.h"
#include "../service/adapter_admission.h"
#include <algorithm>
#include <cstdio>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
using Create = void* (WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
using Close = void (WINAPI*)(void*);
using Luid = void (WINAPI*)(void*, NET_LUID*);
using Ops = liwetun::adapter::WindowsOps<Create, Close, Luid>;
using namespace liwetun::adapter;
struct Failure {};
void Check(bool value) { if (!value) throw Failure{}; }
struct Library { HMODULE value{}; ~Library() { if (value) FreeLibrary(value); } };
struct Adapter {
  void* value{}; Close close{};
  ~Adapter() { if (value) close(value); }
  void Release() { if (value) close(std::exchange(value, nullptr)); }
};
struct Table { void* value{}; ~Table() { if (value) FreeMibTable(value); } };
template<class Fn> Fn Symbol(HMODULE dll, const char* name) {
  const auto symbol = GetProcAddress(dll, name);
  Check(symbol != nullptr);
  Fn result{};
  static_assert(sizeof(result) == sizeof(symbol));
  std::memcpy(&result, &symbol, sizeof(result));
  return result;
}
bool Gone(uint64_t value) {
  for (unsigned i = 0; i < 100; ++i) {
    MIB_IF_ROW2 row{}; row.InterfaceLuid.Value = value;
    const auto status = GetIfEntry2(&row);
    if (status == ERROR_NOT_FOUND || status == ERROR_FILE_NOT_FOUND) return true;
    if (status != NO_ERROR) return false;
    Sleep(50);
  }
  return false;
}
struct Sample {
  std::wstring alias;
  std::array<uint8_t, 16> guid{};
  ULONG mtu = 0, metric = 0;
  BOOLEAN automatic = FALSE;
  std::vector<std::pair<ULONG, UCHAR>> addresses;
  bool operator==(const Sample&) const = default;
};
std::optional<Sample> Read(NET_LUID luid) {
  MIB_IF_ROW2 row{}; row.InterfaceLuid = luid;
  if (GetIfEntry2(&row) != NO_ERROR) return {};
  MIB_IPINTERFACE_ROW ip{}; ip.Family = AF_INET; ip.InterfaceLuid = luid;
  if (GetIpInterfaceEntry(&ip) != NO_ERROR) return {};
  MIB_UNICASTIPADDRESS_TABLE* addresses = nullptr;
  if (GetUnicastIpAddressTable(AF_INET, &addresses) != NO_ERROR || !addresses) return {};
  Table release{addresses};
  if (addresses->NumEntries > 4096) return {};
  Sample result{row.Alias, {}, ip.NlMtu, ip.Metric, ip.UseAutomaticMetric, {}};
  std::memcpy(result.guid.data(), &row.InterfaceGuid, sizeof(GUID));
  for (ULONG i = 0; i < addresses->NumEntries; ++i) {
    const auto& entry = addresses->Table[i];
    if (entry.InterfaceLuid.Value != luid.Value || entry.Address.si_family != AF_INET) continue;
    const auto value = entry.Address.Ipv4.sin_addr.S_un.S_addr;
    const auto* bytes = reinterpret_cast<const unsigned char*>(&value);
    if (bytes[0] == 169 && bytes[1] == 254) continue;
    result.addresses.emplace_back(value, entry.OnLinkPrefixLength);
  }
  std::sort(result.addresses.begin(), result.addresses.end());
  return result;
}
std::optional<Sample> AwaitSample(NET_LUID luid) {
  for (unsigned i = 0; i < 100; ++i) {
    auto result = Read(luid);
    if (result) return result;
    Sleep(50);
  }
  return {};
}
struct InjectedOps {
  using Handle = void*;
  Ops& os;
  std::array<uint8_t, 32> random{};
  Identity requested{};
  bool capture_only = false, reject_observation = false;
  unsigned creates = 0, closes = 0;
  uint64_t returned_luid = 0;
  bool Random(std::array<uint8_t, 32>& output) noexcept { output = random; return true; }
  bool Vacant(const Identity& identity) noexcept {
    requested = identity;
    return !capture_only && os.Vacant(identity);
  }
  Handle Create(const Identity& identity) noexcept { ++creates; return os.Create(identity); }
  bool Observe(Handle handle, Observation& output) noexcept {
    const bool observed = os.Observe(handle, output);
    returned_luid = output.luid;
    return observed && !reject_observation;
  }
  void Close(Handle handle) noexcept { ++closes; os.Close(handle); }
};
struct RaceOps {
  using Handle = void*;
  Ops& os;
  Adapter& inserted;
  Observation foreign_before{};
  bool inserted_observed = false;
  bool Random(std::array<uint8_t, 32>& output) noexcept { return os.Random(output); }
  bool Vacant(const Identity& identity) noexcept { return os.Vacant(identity); }
  Handle Create(const Identity& identity) noexcept {
    // CI-only equal-privilege injection after the real vacancy check. The
    // retained fixture belongs to this helper, never to another host process.
    Identity different = identity;
    different.guid[0] ^= 1;
    inserted.value = os.Create(different);
    if (!inserted.value) return nullptr;
    inserted_observed = os.Observe(inserted.value, foreign_before);
    if (!inserted_observed) return nullptr;
    return os.Create(identity);
  }
  bool Observe(Handle handle, Observation& output) noexcept { return os.Observe(handle, output); }
  void Close(Handle handle) noexcept { os.Close(handle); }
};
bool Disposable() {
  wchar_t enabled[8]{}, run[21]{};
  if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", enabled, 8) != 4 || std::wstring(enabled) != L"true") return false;
  const auto size = GetEnvironmentVariableW(L"GITHUB_RUN_ID", run, 21);
  if (!size || size > 20) return false;
  for (DWORD i = 0; i < size; ++i) if (run[i] < L'0' || run[i] > L'9') return false;
  return true;
}
}

int wmain(int argc, wchar_t** argv) {
  unsigned stage = 0;
  try {
    Check(Disposable() && argc == 2 && liwetun::ReservedAdapterNamesAbsent());
    stage = 1;
    Library library{LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
    Check(library.value != nullptr);
    const auto create = Symbol<Create>(library.value, "WintunCreateAdapter");
    const auto close = Symbol<Close>(library.value, "WintunCloseAdapter");
    const auto luid = Symbol<Luid>(library.value, "WintunGetAdapterLUID");
    Ops os(create, close, luid, L"LiWeTun.CI.CreateOnly");
    stage = 2;
    // A separate owner retains the ordinary logical-name adapter throughout.
    Adapter foreign{create(L"LiWeTun", L"LiWeTun.CI.ForeignOwner", nullptr), close};
    Check(foreign.value != nullptr);
    NET_LUID retained{}; luid(foreign.value, &retained);
    Check(retained.Value != 0);
    const auto baseline = AwaitSample(retained);
    Check(baseline.has_value());
    stage = 3;
    {
      const auto result = CreateFresh(os);
      Adapter owned{result.handle, close};
      Check(owned.value && result.authority.luid != retained.Value);
      Check(Read(retained) == baseline);
      owned.Release();
      Check(Gone(result.authority.luid) && Read(retained) == baseline);
    }
    stage = 4;
    // Force an observed exact physical-name/GUID collision on our own fixture.
    InjectedOps collision{os};
    Check(os.Random(collision.random));
    collision.capture_only = true;
    Check(!CreateFresh(collision).handle && collision.creates == 0);
    Adapter occupied{os.Create(collision.requested), close};
    Check(occupied.value != nullptr);
    Observation occupied_before{};
    Check(os.Observe(occupied.value, occupied_before));
    collision.capture_only = false;
    Check(!CreateFresh(collision).handle && collision.creates == 0 && collision.closes == 0);
    collision.random[0] ^= 1; // alias-only collision: requested GUID differs
    Check(!CreateFresh(collision).handle && collision.creates == 0 && collision.closes == 0);
    collision.random[0] ^= 1;
    collision.random[16] ^= 1; // GUID-only collision: requested alias differs
    Check(!CreateFresh(collision).handle && collision.creates == 0 && collision.closes == 0);
    Observation occupied_after{};
    Check(os.Observe(occupied.value, occupied_after) && Matches(occupied_after, occupied_before));
    occupied.Release();
    Check(Gone(occupied_before.luid) && Read(retained) == baseline);
    stage = 5;
    // Reject after actual Create/Observe; policy must remove only that attempt.
    InjectedOps rejected{os};
    Check(os.Random(rejected.random));
    rejected.reject_observation = true;
    Check(!CreateFresh(rejected).handle && rejected.creates == 1 && rejected.closes == 1);
    Check(rejected.returned_luid && Gone(rejected.returned_luid) && Read(retained) == baseline);
    stage = 6;
    std::array<Created<void*>, 4> concurrent{};
    std::vector<std::thread> workers;
    for (size_t i = 0; i < concurrent.size(); ++i)
      workers.emplace_back([i, &os, &concurrent] { concurrent[i] = CreateFresh(os); });
    for (auto& worker : workers) worker.join();
    // Close all owned handles even if a later observation fails.
    bool distinct = true, removed = true;
    for (size_t i = 0; i < concurrent.size(); ++i) {
      distinct = distinct && concurrent[i].handle && concurrent[i].authority.luid != retained.Value;
      for (size_t j = i + 1; j < concurrent.size(); ++j)
        distinct = distinct && concurrent[i].authority.luid != concurrent[j].authority.luid &&
            concurrent[i].authority.identity.guid != concurrent[j].authority.identity.guid &&
            concurrent[i].authority.identity.name != concurrent[j].authority.identity.name;
      if (concurrent[i].handle) close(concurrent[i].handle);
    }
    for (const auto& result : concurrent) removed = removed && result.authority.luid && Gone(result.authority.luid);
    Check(distinct && removed && Read(retained) == baseline);
    stage = 7;
    foreign.Release();
    Check(Gone(retained.Value) && liwetun::ReservedAdapterNamesAbsent());
    stage = 8;
    bool alias_changed = false, new_handle_accepted = false;
    {
      Adapter inserted{nullptr, close};
      RaceOps race{os, inserted};
      const auto result = CreateFresh(race);
      Adapter raced{result.handle, close};
      Check(race.inserted_observed);
      NET_LUID original{}; original.Value = race.foreign_before.luid;
      const auto after = Read(original);
      Check(after.has_value());
      alias_changed = after->alias != std::wstring(race.foreign_before.identity.name.data());
      new_handle_accepted = raced.value != nullptr;
      // Either an actual safe refusal or the known duplicate-alias exposure.
      // A passing reproduction is never complete ownership qualification.
      Check((!alias_changed && !new_handle_accepted) || (alias_changed && new_handle_accepted));
      raced.Release();
      Check(!new_handle_accepted || Gone(result.authority.luid));
      inserted.Release();
      Check(Gone(original.Value));
    }
    std::printf("{\"passed\":true,\"foreign_logical_adapter_preserved\":true,\"observed_collision_refused\":true,\"post_create_refusal_cleanup\":true,\"concurrent_created_handles_distinct\":true,\"created_adapters_removed\":true,\"race_control_ran\":true,\"race_foreign_alias_changed\":%s,\"race_new_handle_accepted\":%s,\"factory_only\":true,\"sdk_started\":false,\"session_started\":false,\"privileged_physical_name_race_qualified\":false,\"adapter_ownership_qualified\":false,\"release_ready\":false}\n", alias_changed ? "true" : "false", new_handle_accepted ? "true" : "false");
    return 0;
  } catch (...) {
    std::printf("{\"passed\":false,\"stage\":%u,\"factory_only\":true,\"adapter_ownership_qualified\":false,\"release_ready\":false}\n", stage);
    return 1;
  }
}
