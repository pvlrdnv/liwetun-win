# Production configuration, synthetic refused loopback endpoint, no traffic claim.
param([Parameter(Mandatory)][string]$Client)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_RUN_ID -notmatch '^[0-9]{1,20}$') { throw 'Disposable CI required' }
$expected = Join-Path $env:ProgramFiles ('LiWeTun-CI-' + $env:GITHUB_RUN_ID + '\liwetun.exe')
if (![string]::Equals($Client,$expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected lifecycle client path' }
$evidence = 'build/service-evidence'
New-Item -ItemType Directory -Force $evidence | Out-Null
$passed = $false
$stage = 'refused_endpoint_preflight'
$adapterSeen = $false
$dnsConfigured = $false
$prefixCounts = @{}
$ipv4RoutesSeen = $false
$ipv6RoutesSeen = $false
$coreObserved = $false
$nativeClean = $false
$nativeExit = $null
$restored = $false
$probe = $null
$watchdog = $null
$done = $null
$probeStarted = $false
$watchdogStarted = $false
function SnapshotGeneral {
    return @{
        dns=(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4 -Compress)
        routes=(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | ConvertTo-Json -Compress)
        adapter=[bool](Get-NetAdapter -IncludeHidden | Where-Object Name -eq 'LiWeTun')
    }
}
function RouteCovers([string]$Address, $Routes) {
    $candidate = [Net.IPAddress]::Parse($Address).GetAddressBytes()
    foreach ($route in $Routes) {
        $parts = $route.DestinationPrefix.Split('/')
        $network = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        if ($candidate.Length -ne $network.Length) { continue }
        $bits = [int]$parts[1]
        $whole = [int][Math]::Floor($bits / 8)
        $remainder = $bits % 8
        $matches = $true
        for ($i=0; $i -lt $whole; $i++) {
            if ($candidate[$i] -ne $network[$i]) { $matches = $false; break }
        }
        if ($matches -and $remainder) {
            $mask = (0xff -shl (8 - $remainder)) -band 0xff
            $matches = ($candidate[$whole] -band $mask) -eq ($network[$whole] -band $mask)
        }
        if ($matches) { return $true }
    }
    return $false
}
$before = SnapshotGeneral
if ($before.adapter) { throw 'Preexisting task adapter' }
$listeners = @(Get-NetTCPConnection -State Listen -LocalPort 9 -ErrorAction SilentlyContinue)
@{loopback_profile_port=9; listener_present=($listeners.Count -gt 0); sdk_started=$false; release_ready=$false} |
    ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidence 'general-preflight.json')
if ($listeners.Count) { throw 'Refused loopback endpoint required' }
try {
    $done = [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,('Local\LiWeTun.CI.GeneralDone.' + $env:GITHUB_RUN_ID))
    $watchdog = [Diagnostics.Process]::new()
    $watchdog.StartInfo = [Diagnostics.ProcessStartInfo]::new('pwsh')
    $watchdog.StartInfo.UseShellExecute = $false
    foreach ($argument in @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'general-watchdog.ps1'))) { $watchdog.StartInfo.ArgumentList.Add($argument) }
    $watchdog.StartInfo.RedirectStandardOutput = $true
    $watchdog.StartInfo.RedirectStandardError = $true
    if (!$watchdog.Start()) { throw 'Lifecycle watchdog launch failed' }
    $watchdogStarted = $true
    $readyLine = $watchdog.StandardOutput.ReadLineAsync()
    if (!$readyLine.Wait(15000) -or $readyLine.Result -cne 'ready') { throw 'Independent deadline was not armed' }
    $stage = 'production_refused_endpoint_lifecycle'
    $probe = [Diagnostics.Process]::new()
    $probe.StartInfo = [Diagnostics.ProcessStartInfo]::new($Client)
    $probe.StartInfo.UseShellExecute = $false
    foreach ($argument in @('--native-lifecycle',(Join-Path (Get-Location).Path 'build/service-local-uri.txt'))) { $probe.StartInfo.ArgumentList.Add($argument) }
    $probe.StartInfo.RedirectStandardOutput = $true
    $probe.StartInfo.RedirectStandardError = $true
    if (!$probe.Start()) { throw 'Lifecycle probe launch failed' }
    $probeStarted = $true
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (!$probe.WaitForExit(100)) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Lifecycle probe deadline exceeded' }
        $adapter = @(Get-NetAdapter -IncludeHidden -Name LiWeTun -ErrorAction SilentlyContinue)
        if ($adapter.Count -gt 1) { throw 'Ambiguous task adapter' }
        if ($adapter.Count -eq 1) {
            $adapterSeen = $true
            $index = $adapter[0].ifIndex
            $routes = @(Get-NetRoute -InterfaceIndex $index)
            foreach ($route in $routes) {
                $family = if ($route.DestinationPrefix.Contains(':')) { 'v6/' } else { 'v4/' }
                $key = $family + $route.DestinationPrefix.Split('/')[-1]
                $prefixCounts[$key] = 1
            }
            $v4Covered = $true
            foreach ($sample in @('1.1.1.1','128.1.1.1','198.51.100.1','203.0.113.1')) {
                $v4Covered = $v4Covered -and (RouteCovers $sample $routes)
            }
            $ipv4RoutesSeen = $ipv4RoutesSeen -or $v4Covered
            $ipv6RoutesSeen = $ipv6RoutesSeen -or ((RouteCovers '2001:db8::1' $routes) -and (RouteCovers '3001:db8::1' $routes))
            if (@(Get-DnsClientServerAddress -InterfaceIndex $index | Where-Object { $_.ServerAddresses.Count -gt 0 }).Count) { $dnsConfigured = $true }
        }
    }
    $nativeExit = $probe.ExitCode
    $raw = $probe.StandardOutput.ReadToEnd()
    if ($raw.Length -gt 2048) { throw 'Oversized closed lifecycle reply' }
    try { $reply = $raw | ConvertFrom-Json } catch { throw 'Invalid closed lifecycle reply' }
    $coreObserved = $reply.core_state_observed -eq $true
    $nativeClean = $reply.stopped_and_cleaned -eq $true
    $adapterSeen = $adapterSeen -or $reply.adapter_seen -eq $true
    $stage = 'verify_original_network_restored'
    for ($attempt=0; $attempt -lt 10; $attempt++) {
        $after = SnapshotGeneral
        $restored = !$after.adapter -and $after.dns -ceq $before.dns -and $after.routes -ceq $before.routes
        if ($restored) { break }
        Start-Sleep -Milliseconds 200
    }
    $passed = $nativeExit -eq 0 -and $coreObserved -and $nativeClean -and $restored -and $ipv4RoutesSeen -and $ipv6RoutesSeen
} finally {
    $bodyPassed = $passed
    $passed = $false
    if ($probe) {
        try { if ($probeStarted -and !$probe.HasExited) { $probe.Kill(); [void]$probe.WaitForExit(5000) } } finally { $probe.Dispose() }
    }
    try {
        $after = SnapshotGeneral
        $restored = !$after.adapter -and $after.dns -ceq $before.dns -and $after.routes -ceq $before.routes
        # Do not disarm the independent deadline until the exact baseline is back.
        if ($restored -and $done) { [void]$done.Set() }
        if ($watchdogStarted) {
            if (!$watchdog.WaitForExit(55000)) { throw 'Independent watchdog did not finish' }
            if ($watchdog.ExitCode -ne 0) { throw 'Independent watchdog failed' }
        }
        $guard = Get-Content (Join-Path $evidence 'general-watchdog.json') -Raw | ConvertFrom-Json
        $after = SnapshotGeneral
        $restored = !$after.adapter -and $after.dns -ceq $before.dns -and $after.routes -ceq $before.routes
        $passed = $bodyPassed -and $restored -and $watchdogStarted -and !$guard.triggered -and $guard.action_completed
    } finally {
        if ($watchdog) { $watchdog.Dispose() }
        if ($done) { $done.Dispose() }
        @{passed=$passed; stage=$stage; native_exit=$nativeExit; core_state_observed=$coreObserved; adapter_seen=$adapterSeen; adapter_dns_configured_seen=$dnsConfigured; adapter_route_prefix_lengths=@($prefixCounts.Keys | Sort-Object); ipv4_sample_route_coverage_seen=$ipv4RoutesSeen; ipv6_sample_route_coverage_seen=$ipv6RoutesSeen; routes_dns_adapter_restored=$restored; network_test_modes_enabled=$false; internet_delivery_tested=$false; profile='synthetic_refused_loopback'; release_ready=$false} |
            ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 (Join-Path $evidence 'general-lifecycle.json')
    }
}
if (!$passed) { throw 'Production refused-endpoint lifecycle did not qualify' }
