# Read-only adapter preflight observation

`read-adapter-preflight.ps1` is a Windows PowerShell diagnostic for Windows 10/11.
It reads the adapter inventory and repeats the service's SWD/ROOT/internal-name
SetupAPI/CM predicates without loading Wintun or opening any adapter. The initial
alias observation uses `Get-NetAdapter -IncludeHidden`, whereas the service uses
`GetIfTable2`; this is a diagnostic aid, not an interchangeable authorization gate.
No service/driver/trust installation or firewall/DNS/route/device changes occur.
PowerShell's built-in Add-Type compiles a small P/Invoke helper; no development
toolchain installation or downloaded assembly is needed.

From Windows PowerShell in a directory containing the repository:

```powershell
.\tools\diagnostics\read-adapter-preflight.ps1
```

It prints one JSON object: schema version, read-only flag, closed stage,
numeric native code, admission observation and explicit `proves_tunnel=false`.
Device names, IDs, IPs, connection links and raw errors never enter the output.
If local policy prevents script execution, retain the policy and report that it
was blocked; do not change execution policy or install additional trusted roots.

The stage distinguishes a reserved alias, SWD problem/unknown state, legacy ROOT
presence, unavailable inventory/property, invalid name property and an internal
reserved name. `passed` means only that this read-only observation passed at that
instant. It cannot explain an earlier refusal or authorize a later Start, and
it does not establish ownership safety or working connectivity.

Do not disable/re-enable a corporate tunnel, alter devices or attempt a LiWeTun
connection on a corporate/development PC to generate a snapshot. Future manual
connection acceptance remains on a separate approved Windows 10 PC.

Actual local Windows execution compiled the helper and returned a typed `passed`
observation, without network configuration changes. This does not reproduce the
owner's earlier refusal. No new CI or desktop connection test was run for this
script. Temporary owner reports belong under ignored `/temp/`, never in Git.
