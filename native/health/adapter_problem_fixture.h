#pragma once
// Disposable CI lifecycle experiment only; never linked into SDK/service/GUI.
#include "windows_fresh_adapter.h"
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <objbase.h>
#include <cstdio>
#include <string>
#include <utility>

namespace {
using Create = void* (WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
using Close = void (WINAPI*)(void*);
using Luid = void (WINAPI*)(void*, NET_LUID*);
using Ops = liwetun::adapter::WindowsOps<Create, Close, Luid>;
struct Failure {};
void Check(bool value) { if (!value) throw Failure{}; }
struct Library { HMODULE value{}; ~Library() { if (value) FreeLibrary(value); } };
struct Adapter {
  void* value{}; Close close{};
  ~Adapter() { if (value) close(value); }
  void Release() { if (value) close(std::exchange(value, nullptr)); }
};
template<class Fn> Fn Symbol(HMODULE dll, const char* name) {
  const auto symbol = GetProcAddress(dll, name); Check(symbol != nullptr);
  Fn result{}; static_assert(sizeof(result) == sizeof(symbol));
  std::memcpy(&result, &symbol, sizeof(result)); return result;
}
bool Disposable() {
  wchar_t enabled[8]{}, identity[21]{};
  if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", enabled, 8) != 4 || std::wstring(enabled) != L"true") return false;
  const auto size = GetEnvironmentVariableW(L"GITHUB_RUN_ID", identity, 21);
  if (!size || size > 20) return false;
  for (DWORD i = 0; i < size; ++i) if (identity[i] < L'0' || identity[i] > L'9') return false;
  return true;
}
struct NodeState { bool present{}; ULONG status{}, problem{}; };
struct Device {
  HDEVINFO list = INVALID_HANDLE_VALUE;
  SP_DEVINFO_DATA device{sizeof(SP_DEVINFO_DATA)};
  std::array<wchar_t, MAX_DEVICE_ID_LEN> identity{};
  bool disabled_by_fixture = false;
  ~Device() {
    if (disabled_by_fixture) {
      try { if (Read().present) Change(DICS_ENABLE); } catch (...) { }
    }
    if (list != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(list);
  }
  NodeState Read() const {
    DEVINST current{};
    const auto located = CM_Locate_DevNodeW(&current, const_cast<wchar_t*>(identity.data()), CM_LOCATE_DEVNODE_NORMAL);
    if (located == CR_NO_SUCH_DEVNODE) return {};
    Check(located == CR_SUCCESS && current == device.DevInst);
    ULONG status = 0, problem = 0;
    Check(CM_Get_DevNode_Status(&status, &problem, current, 0) == CR_SUCCESS);
    return {true, status, problem};
  }
  void Locate(const GUID& guid) {
    wchar_t expected[40]{}; Check(StringFromGUID2(guid, expected, 40) == 39);
    list = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
    Check(list != INVALID_HANDLE_VALUE);
    bool found = false, exhausted = false;
    for (DWORD i = 0; i < 4096; ++i) {
      SP_DEVINFO_DATA entry{sizeof(SP_DEVINFO_DATA)};
      if (!SetupDiEnumDeviceInfo(list, i, &entry)) {
        Check(GetLastError() == ERROR_NO_MORE_ITEMS); exhausted = true; break;
      }
      HKEY key = SetupDiOpenDevRegKey(list, &entry, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
      if (key == INVALID_HANDLE_VALUE) continue;
      wchar_t value[40]{}; DWORD bytes = sizeof(value);
      const auto status = RegGetValueW(key, nullptr, L"NetCfgInstanceId", RRF_RT_REG_SZ, nullptr, value, &bytes);
      RegCloseKey(key);
      if (status != ERROR_SUCCESS || wcsnlen_s(value, 40) != 38 ||
          CompareStringOrdinal(value, -1, expected, -1, TRUE) != CSTR_EQUAL) continue;
      Check(!found); found = true; device = entry;
    }
    Check(exhausted && found);
    Check(CM_Get_Device_IDW(device.DevInst, identity.data(), static_cast<ULONG>(identity.size()), 0) == CR_SUCCESS);
    const auto state = Read(); Check(state.present && !(state.status & DN_HAS_PROBLEM));
  }
  void Change(DWORD change) {
    Check(Read().present);
    SP_PROPCHANGE_PARAMS params{};
    params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    params.StateChange = change; params.Scope = DICS_FLAG_GLOBAL;
    Check(SetupDiSetClassInstallParamsW(list, &device, &params.ClassInstallHeader, sizeof(params)) != FALSE);
    Check(SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, list, &device) != FALSE);
  }
};
}

