#include "adapter_admission.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <devpropdef.h>
#include <setupapi.h>
#include <cfgmgr32.h>

namespace liwetun {
namespace {
constexpr GUID kNetworkClass{0x4d36e972,0xe325,0x11ce,{0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18}};
constexpr DEVPROPKEY kWintunName{{0x3361c968,0x2f2e,0x4660,{0xb4,0x7e,0x69,0x9c,0xdc,0x4c,0x32,0xb9}},
                               DEVPROPID_FIRST_USABLE + 1};
Code EnumeratorState(const wchar_t* enumerator, bool refuse_any) {
  const Code unavailable = refuse_any ? Code::AdapterRootUnavailable : Code::AdapterSwdUnavailable;
  HDEVINFO devices = SetupDiGetClassDevsW(&kNetworkClass, enumerator, nullptr, 0);
  if (devices == INVALID_HANDLE_VALUE) return unavailable;
  struct Release { HDEVINFO value; ~Release() { SetupDiDestroyDeviceInfoList(value); } } release{devices};
  for (DWORD i = 0; i < 4096; ++i) {
    SP_DEVINFO_DATA device{}; device.cbSize = sizeof(device);
    if (!SetupDiEnumDeviceInfo(devices, i, &device))
      return GetLastError() == ERROR_NO_MORE_ITEMS ? Code::Ok : unavailable;
    if (refuse_any) return Code::AdapterRootPresent;
    ULONG status = 0, problem = 0;
    if (CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0) != CR_SUCCESS) return unavailable;
    if (status & DN_HAS_PROBLEM) return Code::AdapterSwdProblem;
  }
  return unavailable;
}
Code InternalNameAdmission() {
  // Include non-present/problem nodes just as original Wintun cleanup does.
  HDEVINFO devices = SetupDiGetClassDevsW(&kNetworkClass, nullptr, nullptr, 0);
  if (devices == INVALID_HANDLE_VALUE) return Code::AdapterInventoryUnavailable;
  struct Release { HDEVINFO value; ~Release() { SetupDiDestroyDeviceInfoList(value); } } release{devices};
  for (DWORD i = 0; i < 4096; ++i) {
    SP_DEVINFO_DATA device{}; device.cbSize = sizeof(device);
    if (!SetupDiEnumDeviceInfo(devices, i, &device))
      return GetLastError() == ERROR_NO_MORE_ITEMS ? Code::Ok : Code::AdapterInventoryUnavailable;
    wchar_t name[256]{};
    DEVPROPTYPE type = 0;
    DWORD size = 0;
    if (!SetupDiGetDevicePropertyW(devices, &device, &kWintunName, &type,
          reinterpret_cast<BYTE*>(name), sizeof(name), &size, 0)) {
      if (GetLastError() == ERROR_NOT_FOUND) continue;
      return Code::AdapterPropertyUnavailable;
    }
    if (type != DEVPROP_TYPE_STRING || size < sizeof(wchar_t) || size > sizeof(name) ||
        size % sizeof(wchar_t) || name[size / sizeof(wchar_t) - 1] != L'\0') return Code::AdapterPropertyInvalid;
    const int match = CompareStringOrdinal(name, -1, L"LiWeTun", -1, TRUE);
    if (!match) return Code::AdapterPropertyInvalid;
    if (match == CSTR_EQUAL) return Code::AdapterNameConflict;
    ULONG status = 0, problem = 0;
    if (CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0) != CR_SUCCESS) return Code::AdapterStateUnavailable;
    if (status & DN_HAS_PROBLEM) return Code::AdapterProblem;
  }
  return Code::AdapterInventoryUnavailable;
}
}
Code ObserveAdapterAdmission() noexcept {
  MIB_IF_TABLE2* table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR || !table) return Code::AdapterInterfaceUnavailable;
  struct Release { MIB_IF_TABLE2* value; ~Release() { FreeMibTable(value); } } release{table};
  if (table->NumEntries > 4096) return Code::AdapterInterfaceUnavailable;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const int match = CompareStringOrdinal(table->Table[i].Alias, -1, L"LiWeTun", -1, TRUE);
    if (!match) return Code::AdapterInterfaceUnavailable;
    if (match == CSTR_EQUAL) return Code::AdapterAliasConflict;
  }
  Code result = EnumeratorState(L"SWD\\Wintun", false);
  if (result != Code::Ok) return result;
  result = EnumeratorState(L"ROOT\\Wintun", true);
  return result == Code::Ok ? InternalNameAdmission() : result;
}
bool ReservedAdapterNamesAbsent() noexcept { return ObserveAdapterAdmission() == Code::Ok; }
}
