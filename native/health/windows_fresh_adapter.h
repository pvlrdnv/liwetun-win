#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cstring>
#include <type_traits>
#include "fresh_adapter.h"

namespace liwetun::adapter {
template<class CreateFn, class CloseFn, class LuidFn> class WindowsOps {
 public:
  using Handle = std::invoke_result_t<CreateFn, LPCWSTR, LPCWSTR, const GUID*>;
  WindowsOps(CreateFn create, CloseFn close, LuidFn luid, LPCWSTR type) noexcept
      : create_(create), close_(close), luid_(luid), type_(type) {}
  bool Random(std::array<uint8_t, 32>& bytes) noexcept {
    return BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
  }
  bool Vacant(const Identity& identity) noexcept {
    MIB_IF_TABLE2* table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR || !table) return false;
    bool absent = table->NumEntries <= 4096;
    GUID requested{};
    std::memcpy(&requested, identity.guid.data(), sizeof(requested));
    for (ULONG i = 0; absent && i < table->NumEntries; ++i) {
      const auto& row = table->Table[i];
      const size_t length = wcsnlen_s(row.Alias, IF_MAX_STRING_SIZE + 1);
      if (length > IF_MAX_STRING_SIZE) { absent = false; break; }
      const int comparison = CompareStringOrdinal(row.Alias, -1, identity.name.data(), -1, TRUE);
      if (!comparison || IsEqualGUID(row.InterfaceGuid, requested) || comparison == CSTR_EQUAL)
        absent = false;
    }
    FreeMibTable(table);
    return absent;
  }
  Handle Create(const Identity& identity) noexcept {
    GUID requested{};
    std::memcpy(&requested, identity.guid.data(), sizeof(requested));
    return create_(identity.name.data(), type_, &requested);
  }
  bool Observe(Handle handle, Observation& output) noexcept {
    output = {};
    if (!handle) return false;
    NET_LUID luid{};
    luid_(handle, &luid);
    NET_IFINDEX index = 0;
    GUID guid{};
    if (!luid.Value || ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR || !index ||
        ConvertInterfaceLuidToGuid(&luid, &guid) != NO_ERROR) return false;
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = luid;
    if (GetIfEntry2(&row) != NO_ERROR || row.InterfaceLuid.Value != luid.Value ||
        row.InterfaceIndex != index || !IsEqualGUID(row.InterfaceGuid, guid) ||
        wcsnlen_s(row.Alias, IF_MAX_STRING_SIZE + 1) != 40) return false;
    std::memcpy(output.identity.guid.data(), &guid, sizeof(guid));
    for (size_t i = 0; i < output.identity.name.size(); ++i) output.identity.name[i] = row.Alias[i];
    output.index = index;
    output.luid = luid.Value;
    return true;
  }
  void Close(Handle handle) noexcept { close_(handle); }
 private:
  CreateFn create_;
  CloseFn close_;
  LuidFn luid_;
  LPCWSTR type_;
};
} // namespace liwetun::adapter
