// Disposable CI fixture only, never linked into the service or installed GUI.
#include <winsock2.h>
#include <ws2tcpip.h>
#include "security.h"
#include <iphlpapi.h>
#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <iostream>
#include <optional>
#include <utility>

namespace {
constexpr wchar_t kAlias[] = L"LiWeTun";
constexpr wchar_t kPreservedAlias[] = L"LiWeTun.CI.PreservedOwner";
static_assert(sizeof(kPreservedAlias) / sizeof(wchar_t) <= 128);
constexpr wchar_t kRenamedAlias[] = L"LiWeTun.CI.RenamedOwner";
constexpr ULONG kMarkerMtu = 1337;
constexpr ULONG kMarkerMetric = 427;
using Create = void* (WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
using Close = void (WINAPI*)(void*);
using Luid = void (WINAPI*)(void*, NET_LUID*);
struct Library { HMODULE value{}; ~Library() { if (value) FreeLibrary(value); } };
struct Adapter {
  void* value{};
  Close close{};
  ~Adapter() { if (value && close) close(value); }
};
struct Table { void* value{}; ~Table() { if (value) FreeMibTable(value); } };
struct Sample {
  std::wstring alias;
  ULONG mtu = 0, metric = 0;
  std::vector<std::pair<ULONG, UCHAR>> addresses;
};
std::optional<Sample> Read(NET_LUID luid) {
  MIB_IF_ROW2 adapter{};
  adapter.InterfaceLuid = luid;
  if (GetIfEntry2(&adapter) != NO_ERROR) return std::nullopt;
  MIB_IPINTERFACE_ROW interface_row{};
  interface_row.Family = AF_INET; interface_row.InterfaceLuid = luid;
  if (GetIpInterfaceEntry(&interface_row) != NO_ERROR) return std::nullopt;
  MIB_UNICASTIPADDRESS_TABLE* addresses = nullptr;
  if (GetUnicastIpAddressTable(AF_INET, &addresses) != NO_ERROR || !addresses) return std::nullopt;
  Table release{addresses};
  if (addresses->NumEntries > 4096) return std::nullopt;
  Sample result{adapter.Alias, interface_row.NlMtu, interface_row.Metric, {}};
  for (ULONG i = 0; i < addresses->NumEntries; ++i) {
    const auto& row = addresses->Table[i];
    if (row.InterfaceLuid.Value != luid.Value || row.Address.si_family != AF_INET) continue;
    const auto address = row.Address.Ipv4.sin_addr.S_un.S_addr;
    const auto* bytes = reinterpret_cast<const unsigned char*>(&address);
    if (bytes[0] == 169 && bytes[1] == 254) continue; // OS link-local autoconfiguration is not SDK proof.
    result.addresses.emplace_back(address, row.OnLinkPrefixLength);
    if (result.addresses.size() > 32) return std::nullopt;
  }
  std::sort(result.addresses.begin(), result.addresses.end());
  return result;
}
bool AliasAbsent(const wchar_t* alias) {
  MIB_IF_TABLE2* table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR || !table) return false;
  Table release{table};
  if (table->NumEntries > 4096) return false;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const auto* name = table->Table[i].Alias;
    if (wcsnlen_s(name, IF_MAX_STRING_SIZE + 1) > IF_MAX_STRING_SIZE) return false;
    const int comparison = CompareStringOrdinal(name, -1, alias, -1, TRUE);
    if (!comparison || comparison == CSTR_EQUAL) return false;
  }
  return true;
}
void Print(const Sample& baseline, const std::optional<Sample>& current) {
  if (!current) {
    std::cout << "{\"available\":false,\"alias_unchanged\":null,\"ipv4_changed\":null,"
        "\"mtu_changed\":null,\"metric_changed\":null,\"fixture_marker_present\":null,\"nonlink_ipv4_count\":null}" << std::endl;
    return;
  }
  const auto boolean = [](bool value) { return value ? "true" : "false"; };
  std::cout << "{\"available\":true,\"alias_unchanged\":" << boolean(current->alias == baseline.alias)
      << ",\"ipv4_changed\":" << boolean(current->addresses != baseline.addresses)
      << ",\"mtu_changed\":" << boolean(current->mtu != baseline.mtu)
      << ",\"metric_changed\":" << boolean(current->metric != baseline.metric)
      << ",\"fixture_marker_present\":" << boolean(current->mtu == kMarkerMtu && current->metric == kMarkerMetric)
      << ",\"nonlink_ipv4_count\":" << current->addresses.size() << "}" << std::endl;
}
bool Disposable() {
  wchar_t enabled[8]{}, identity[21]{};
  if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", enabled, 8) != 4 || std::wstring(enabled) != L"true") return false;
  const auto size = GetEnvironmentVariableW(L"GITHUB_RUN_ID", identity, 21);
  if (!size || size > 20) return false;
  for (DWORD i = 0; i < size; ++i) if (identity[i] < L'0' || identity[i] > L'9') return false;
  return true;
}
bool DriverDigest(const liwetun::Image& image) {
  liwetun::Digest actual{};
  if (!liwetun::HashFile(image.handle.get(), actual)) return false;
  constexpr liwetun::Digest expected{0xe5,0xda,0x84,0x47,0xdc,0x2c,0x32,0x0e,0xdc,0x0f,0xc5,0x2f,0xa0,0x18,0x85,0xc1,
      0x03,0xde,0x8c,0x11,0x84,0x81,0xf6,0x83,0x64,0x3c,0xac,0xc3,0x22,0x0d,0xaf,0xce};
  return actual == expected;
}
void Stage(HANDLE file, unsigned stage) {
  char line[48]{};
  const int size = std::snprintf(line, sizeof(line), "{\"stage\":%u}\n", stage);
  DWORD written = 0;
  if (size > 0 && static_cast<size_t>(size) < sizeof(line)) {
    if (WriteFile(file, line, static_cast<DWORD>(size), &written, nullptr)) FlushFileBuffers(file);
  }
}
}

int RunAdapterOwnerFixture(bool preserved_spare) {
  try {
    std::wstring preserved_name{kPreservedAlias};
    preserved_name.resize(127, L'x'); // refuse duplicate suffix before any foreign rename
    const auto* alias = preserved_spare ? preserved_name.c_str() : kAlias;
    if (!Disposable() || !AliasAbsent(alias)) return 90;
    liwetun::Image self, driver;
    if (!liwetun::OpenTrustedImage(liwetun::SelfPath(), self) ||
        !liwetun::OpenTrustedImage(liwetun::Directory(self.path) + L"\\wintun.dll", driver) || !DriverDigest(driver)) return 91;
    liwetun::Handle stage(CreateFileW((liwetun::Directory(self.path) + L"\\adapter-owner-native-stages.jsonl").c_str(),
        GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!stage || stage.get() == INVALID_HANDLE_VALUE) return 100;
    Stage(stage.get(), 1);
    Library library{LoadLibraryExW(driver.path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
    if (!library.value) return 92;
    const auto create = reinterpret_cast<Create>(GetProcAddress(library.value, "WintunCreateAdapter"));
    const auto close = reinterpret_cast<Close>(GetProcAddress(library.value, "WintunCloseAdapter"));
    const auto luid = reinterpret_cast<Luid>(GetProcAddress(library.value, "WintunGetAdapterLUID"));
    if (!create || !close || !luid) return 93;
    Stage(stage.get(), 2);
    // The fixture retains its own created handle. SDK is another owner and has
    // no authority to adopt/configure it. No pre-existing adapter is removed.
    Stage(stage.get(), 3);
    Adapter adapter{create(alias, L"LiWeTun.CI.ForeignOwner", nullptr), close};
    if (!adapter.value) return 94;
    NET_LUID retained{}; luid(adapter.value, &retained);
    if (!retained.Value) return 95;
    Stage(stage.get(), 4);
    MIB_IPINTERFACE_ROW marker{};
    marker.Family = AF_INET; marker.InterfaceLuid = retained;
    DWORD status = ERROR_NOT_FOUND;
    for (unsigned attempt = 0; attempt < 50; ++attempt) {
      status = GetIpInterfaceEntry(&marker);
      if (status == NO_ERROR) break;
      Sleep(50);
    }
    if (status != NO_ERROR) return 96;
    marker.NlMtu = kMarkerMtu; marker.Metric = kMarkerMetric;
    marker.UseAutomaticMetric = FALSE; marker.SitePrefixLength = 0;
    Stage(stage.get(), 5);
    if (SetIpInterfaceEntry(&marker) != NO_ERROR) return 97;
    Stage(stage.get(), 6);
    auto baseline = Read(retained);
    if (!baseline || baseline->alias != alias || baseline->mtu != kMarkerMtu ||
        baseline->metric != kMarkerMetric || !baseline->addresses.empty()) return 98;
    Stage(stage.get(), 7);
    std::cout << "{\"ready\":true,\"fixture_created_adapter\":true,\"retained_creation_handle\":true,"
        "\"marker_verified\":true,\"identifiers_exported\":false,\"release_ready\":false}" << std::endl;
    std::string command;
    for (unsigned call = 0; call < 256 && std::getline(std::cin, command); ++call) {
      if (command == "confirm-renamed") {
        if (preserved_spare) return 99;
        Stage(stage.get(), 8);
        const auto current = Read(retained);
        const bool valid = current && current->alias == kRenamedAlias && current->mtu == kMarkerMtu &&
            current->metric == kMarkerMetric && current->addresses == baseline->addresses;
        if (valid) baseline->alias = current->alias;
        std::cout << "{\"renamed_alias_confirmed\":" << (valid ? "true" : "false")
            << ",\"identifiers_exported\":false}" << std::endl;
        continue;
      }
      if (command != "sample") break;
      Stage(stage.get(), 8);
      Print(*baseline, Read(retained));
    }
    Stage(stage.get(), 9);
    close(std::exchange(adapter.value, nullptr));
    Stage(stage.get(), 10);
    bool removed = false;
    for (unsigned attempt = 0; attempt < 50; ++attempt) {
      MIB_IF_ROW2 row{}; row.InterfaceLuid = retained;
      const DWORD found = GetIfEntry2(&row);
      if (found == ERROR_FILE_NOT_FOUND || found == ERROR_NOT_FOUND) { removed = true; break; }
      Sleep(50);
    }
    std::cout << "{\"fixture_adapter_removed\":" << (removed ? "true" : "false")
        << ",\"release_ready\":false}" << std::endl;
    Stage(stage.get(), 11);
    FreeLibrary(std::exchange(library.value, nullptr));
    Stage(stage.get(), 12);
    return removed ? 0 : 99;
  } catch (...) { return 100; }
}
