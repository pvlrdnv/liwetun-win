#include "adapter_admission.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <devpropdef.h>
#include <setupapi.h>

namespace liwetun {
namespace {
constexpr GUID kNetworkClass{0x4d36e972,0xe325,0x11ce,{0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18}};
// Original Wintun DEVPKEY_Wintun_Name, used by its open-by-name routine.
constexpr DEVPROPKEY kWintunName{{0x3361c968,0x2f2e,0x4660,{0xb4,0xe7,0x69,0x9c,0xdc,0x4c,0x32,0xb9}},
                               DEVPROPID_FIRST_USABLE + 1};
bool Reserved(const wchar_t* name) {
  const int match = CompareStringOrdinal(name, -1, L"LiWeTun", -1, TRUE);
  return !match || match == CSTR_EQUAL;
}
bool InternalNameAbsent() {
  HDEVINFO devices = SetupDiGetClassDevsW(&kNetworkClass, nullptr, nullptr, DIGCF_PRESENT);
  if (devices == INVALID_HANDLE_VALUE) return false;
  struct Release { HDEVINFO value; ~Release() { SetupDiDestroyDeviceInfoList(value); } } release{devices};
  for (DWORD i = 0; i < 4096; ++i) {
    SP_DEVINFO_DATA device{}; device.cbSize = sizeof(device);
    if (!SetupDiEnumDeviceInfo(devices, i, &device)) return GetLastError() == ERROR_NO_MORE_ITEMS;
    wchar_t name[256]{};
    DEVPROPTYPE type = 0;
    DWORD size = 0;
    if (!SetupDiGetDevicePropertyW(devices, &device, &kWintunName, &type,
          reinterpret_cast<BYTE*>(name), sizeof(name), &size, 0)) {
      if (GetLastError() == ERROR_NOT_FOUND) continue; // Other network device, not Wintun.
      return false; // Unknown/oversized/removed/denied observation cannot authorize Start.
    }
    if (type != DEVPROP_TYPE_STRING || size < sizeof(wchar_t) || size > sizeof(name) ||
        size % sizeof(wchar_t) || name[size / sizeof(wchar_t) - 1] != L'\0' || Reserved(name)) return false;
  }
  return false;
}
}
bool ReservedAdapterNamesAbsent() noexcept {
  MIB_IF_TABLE2* table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR || !table) return false;
  struct Release { MIB_IF_TABLE2* value; ~Release() { FreeMibTable(value); } } release{table};
  if (table->NumEntries > 4096) return false;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    // Stable ordinal comparison; never use an alias match as ownership proof.
    if (Reserved(table->Table[i].Alias)) return false;
  }
  return InternalNameAbsent();
}
}
