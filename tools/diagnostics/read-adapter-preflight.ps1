# Read-only Windows 10/11 diagnostic. No service/driver load or network mutation.
# Emits only closed stages and numeric status; no device identifiers or names.
# This observation never authorizes a later Start or proves a working tunnel.
$ErrorActionPreference = 'Stop'
try {
    $source = @'
using System;
using System.Runtime.InteropServices;
public static class LiwetunAdapterReadOnly {
    [StructLayout(LayoutKind.Sequential)] struct Device {
        public uint Size; public Guid Class; public uint Instance; public UIntPtr Reserved;
    }
    [StructLayout(LayoutKind.Sequential)] struct Key { public Guid Format; public uint Id; }
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr SetupDiGetClassDevsW(ref Guid cls, string enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern bool SetupDiEnumDeviceInfo(IntPtr list, uint index, ref Device device);
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr list);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiGetDevicePropertyW(IntPtr list, ref Device device, ref Key key,
        out uint type, byte[] value, uint length, out uint required, uint flags);
    [DllImport("cfgmgr32.dll")]
    static extern uint CM_Get_DevNode_Status(out uint status, out uint problem, uint instance, uint flags);
    public static string Stage = "unavailable";
    public static uint NativeCode;
    static bool Refuse(string stage, uint code) { Stage = stage; NativeCode = code; return false; }
    static bool Inventory(string enumerator, bool refuseAny, bool names) {
        string prefix = names ? "internal" : (refuseAny ? "root" : "swd");
        Guid cls = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
        IntPtr list = SetupDiGetClassDevsW(ref cls, enumerator, IntPtr.Zero, 0);
        if (list == new IntPtr(-1)) return Refuse(prefix + "_inventory_unavailable", (uint)Marshal.GetLastWin32Error());
        try {
            for (uint i=0; i<4096; i++) {
                Device d = new Device(); d.Size = (uint)Marshal.SizeOf(typeof(Device));
                if (!SetupDiEnumDeviceInfo(list, i, ref d)) {
                    uint error = (uint)Marshal.GetLastWin32Error();
                    if (error == 259) return true;
                    return Refuse(prefix + "_enumeration_unavailable", error);
                }
                if (refuseAny) return Refuse("root_present", 0);
                if (names) {
                    Key key = new Key(); key.Format = new Guid("3361c968-2f2e-4660-b47e-699cdc4c32b9"); key.Id = 3;
                    byte[] value = new byte[512]; uint type, required;
                    if (!SetupDiGetDevicePropertyW(list, ref d, ref key, out type, value, (uint)value.Length, out required, 0)) {
                        uint error = (uint)Marshal.GetLastWin32Error();
                        if (error == 1168) continue;
                        return Refuse("internal_property_unavailable", error);
                    }
                    if (type != 18 || required < 2 || required > value.Length || required % 2 != 0 ||
                        value[required-1] != 0 || value[required-2] != 0) return Refuse("internal_property_invalid", 0);
                    string name = System.Text.Encoding.Unicode.GetString(value, 0, (int)required-2);
                    if (String.Equals(name, "LiWeTun", StringComparison.OrdinalIgnoreCase)) return Refuse("internal_reserved_name", 0);
                }
                uint status, problem;
                uint result = CM_Get_DevNode_Status(out status, out problem, d.Instance, 0);
                if (result != 0) return Refuse(prefix + "_state_unavailable", result);
                if ((status & 1024) != 0) return Refuse(prefix + "_problem", problem);
            }
            return Refuse(prefix + "_inventory_limit", 0);
        } finally { SetupDiDestroyDeviceInfoList(list); }
    }
    public static bool Read() {
        Stage = "passed"; NativeCode = 0;
        return Inventory(@"SWD\Wintun", false, false) && Inventory(@"ROOT\Wintun", true, false) && Inventory(null, false, true);
    }
}
'@
    Add-Type -TypeDefinition $source -ErrorAction Stop
    $aliases = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    if ($aliases.Count -gt 4096) {
        $stage = 'alias_inventory_limit'; $code = 0; $admitted = $false
    } elseif (@($aliases | Where-Object { $_.Name -ieq 'LiWeTun' }).Count -gt 0) {
        $stage = 'reserved_alias'; $code = 0; $admitted = $false
    } else {
        $admitted = [LiwetunAdapterReadOnly]::Read()
        $stage = [LiwetunAdapterReadOnly]::Stage
        $code = [LiwetunAdapterReadOnly]::NativeCode
    }
    [ordered]@{schema_version=1;read_only=$true;stage=$stage;native_code=$code;admitted=$admitted;identifiers_exported=$false;proves_tunnel=$false} | ConvertTo-Json -Compress
} catch {
    # Never return exception text; Windows provider errors may contain identifiers.
    '{"schema_version":1,"read_only":true,"stage":"probe_unavailable","native_code":null,"admitted":null,"identifiers_exported":false,"proves_tunnel":false}'
}
