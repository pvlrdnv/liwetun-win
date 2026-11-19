// Synthetic OS failures only; never opens/creates/configures an adapter.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <devpropdef.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <cwchar>
#include "adapter_admission.h"
namespace {
liwetun::Code scenario = liwetun::Code::Ok;
MIB_IF_TABLE2 interfaces{};
ULONG FakeGetIfTable2(MIB_IF_TABLE2** output) {
  if (scenario == liwetun::Code::AdapterInterfaceUnavailable) return ERROR_ACCESS_DENIED;
  interfaces = {}; interfaces.NumEntries = 1;
  wcscpy_s(interfaces.Table[0].Alias, scenario == liwetun::Code::AdapterAliasConflict ? L"LiWeTun" : L"synthetic");
  *output = &interfaces; return NO_ERROR;
}
void FakeFreeMibTable(void*) {}
HDEVINFO FakeSetupDiGetClassDevsW(const GUID*, PCWSTR enumerator, HWND, DWORD) {
  const bool swd = enumerator && wcscmp(enumerator, L"SWD\\Wintun") == 0;
  const bool root = enumerator && !swd;
  if ((swd && scenario == liwetun::Code::AdapterSwdUnavailable) ||
      (root && scenario == liwetun::Code::AdapterRootUnavailable) ||
      (!enumerator && scenario == liwetun::Code::AdapterInventoryUnavailable)) return INVALID_HANDLE_VALUE;
  return reinterpret_cast<HDEVINFO>(static_cast<uintptr_t>(swd ? 1 : root ? 2 : 3));
}
BOOL FakeSetupDiDestroyDeviceInfoList(HDEVINFO) { return TRUE; }
BOOL FakeSetupDiEnumDeviceInfo(HDEVINFO list, DWORD index, SP_DEVINFO_DATA* device) {
  const auto kind = reinterpret_cast<uintptr_t>(list);
  const bool found = index == 0 && ((kind == 1 && scenario == liwetun::Code::AdapterSwdProblem) ||
      (kind == 2 && scenario == liwetun::Code::AdapterRootPresent) ||
      (kind == 3 && scenario >= liwetun::Code::AdapterPropertyUnavailable));
  if (!found) { SetLastError(ERROR_NO_MORE_ITEMS); return FALSE; }
  device->DevInst = static_cast<DWORD>(kind); return TRUE;
}
BOOL FakeSetupDiGetDevicePropertyW(HDEVINFO, SP_DEVINFO_DATA*, const DEVPROPKEY*, DEVPROPTYPE* type,
                                  PBYTE output, DWORD capacity, PDWORD size, DWORD) {
  if (scenario == liwetun::Code::AdapterPropertyUnavailable) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  *type = scenario == liwetun::Code::AdapterPropertyInvalid ? DEVPROP_TYPE_UINT32 : DEVPROP_TYPE_STRING;
  const wchar_t* name = scenario == liwetun::Code::AdapterNameConflict ? L"LiWeTun" : L"synthetic";
  *size = static_cast<DWORD>((wcslen(name) + 1) * sizeof(wchar_t));
  if (*size > capacity) std::abort();
  std::memcpy(output, name, *size); return TRUE;
}
CONFIGRET FakeCMGetStatus(PULONG status, PULONG problem, DEVINST, ULONG) {
  if (scenario == liwetun::Code::AdapterStateUnavailable) return CR_FAILURE;
  *status = scenario == liwetun::Code::AdapterSwdProblem || scenario == liwetun::Code::AdapterProblem ? DN_HAS_PROBLEM : 0;
  *problem = *status ? CM_PROB_DISABLED : 0; return CR_SUCCESS;
}
}
#define GetIfTable2 FakeGetIfTable2
#define FreeMibTable FakeFreeMibTable
#define SetupDiGetClassDevsW FakeSetupDiGetClassDevsW
#define SetupDiDestroyDeviceInfoList FakeSetupDiDestroyDeviceInfoList
#define SetupDiEnumDeviceInfo FakeSetupDiEnumDeviceInfo
#define SetupDiGetDevicePropertyW FakeSetupDiGetDevicePropertyW
#define CM_Get_DevNode_Status FakeCMGetStatus
#include "adapter_admission.cpp"
int main() {
  for (auto code : {liwetun::Code::Ok, liwetun::Code::AdapterInterfaceUnavailable,
       liwetun::Code::AdapterAliasConflict, liwetun::Code::AdapterSwdUnavailable,
       liwetun::Code::AdapterSwdProblem, liwetun::Code::AdapterRootUnavailable,
       liwetun::Code::AdapterRootPresent, liwetun::Code::AdapterInventoryUnavailable,
       liwetun::Code::AdapterPropertyUnavailable, liwetun::Code::AdapterPropertyInvalid,
       liwetun::Code::AdapterNameConflict, liwetun::Code::AdapterStateUnavailable,
       liwetun::Code::AdapterProblem}) {
    scenario = code;
    if (liwetun::ObserveAdapterAdmission() != code ||
        liwetun::ReservedAdapterNamesAbsent() != (code == liwetun::Code::Ok)) std::abort();
  }
  if (liwetun::AdapterRefusal(liwetun::Code::CoreFailure) || !liwetun::AdapterRefusal(liwetun::Code::AdapterPreflightRejected)) std::abort();
}
