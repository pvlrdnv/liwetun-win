param([ValidateSet(30,60,120)][int]$DeadlineSeconds=30)
# Independent disposable-CI deadline; only this job's exact registered service.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_RUN_ID -notmatch '^[0-9]{1,20}$') { throw 'Disposable CI required' }
$expectedPath = Join-Path $env:ProgramFiles ('LiWeTun-CI-' + $env:GITHUB_RUN_ID + '\liwetun_service.exe')
$done = [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,('Local\LiWeTun.CI.GeneralDone.' + $env:GITHUB_RUN_ID))
$triggered = $false
$clean = $true
$method = 'not_needed'
$target = $null
$controller = $null
try {
    [Console]::Out.WriteLine('ready')
    [Console]::Out.Flush()
    if (!$done.WaitOne($DeadlineSeconds * 1000)) {
        $triggered = $true
        $configuration = Get-CimInstance Win32_Service -Filter "Name='LiWeTun'"
        $expected = '"' + $expectedPath + '" --service '
        if (!$configuration -or !$configuration.ProcessId -or !$configuration.PathName.StartsWith($expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected fixture service identity' }
        $target = Get-Process -Id $configuration.ProcessId
        # Retain the verified process object while stopping; never kill by a
        # later unverified PID lookup or enumerate unrelated processes.
        $retained = $target.SafeHandle
        if (!$retained -or ![string]::Equals($target.Path,$expectedPath,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected fixture process image' }
        $controller = Get-Service LiWeTun
        $controller.Stop()
        $method = 'service_stop'
        if (!$target.WaitForExit(15000)) {
            $target.Kill()
            if (!$target.WaitForExit(5000)) { throw 'Owned service did not end' }
            $method = 'owned_process_termination'
        }
    }
} catch { $clean = $false; $method = 'guard_failed' }
finally {
    if ($controller) { $controller.Dispose() }
    if ($target) { $target.Dispose() }
    $done.Dispose()
    @{triggered=$triggered; action_completed=$clean; method=$method; release_ready=$false} |
        ConvertTo-Json | Set-Content -Encoding utf8 build/service-evidence/general-watchdog.json
}
if (!$clean) { exit 1 }
