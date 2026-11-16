# ONLY for a disposable GitHub runner, never an installer for the owner's PC.
param([string]$Build = 'build/service/Release', [string]$Sdk = '', [switch]$Network, [switch]$ProductionLifecycle, [switch]$ProductionTraffic)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or !$env:GITHUB_RUN_ID) { throw 'Disposable GitHub runner required' }
if ($Network -and !$Sdk) { throw 'Network qualification requires actual SDK' }
if ($ProductionLifecycle -and (!$Sdk -or $Network)) { throw 'Production lifecycle requires SDK and excludes bounded network mode' }
if ($ProductionTraffic -and (!$Network -or $ProductionLifecycle)) { throw 'Production traffic requires its own live endpoint fixture' }
$cache = Get-Content (Join-Path (Split-Path $Build -Parent) 'CMakeCache.txt')
$expectedNoGlobal = if (!$Network -and !$ProductionLifecycle) { 'ON' } else { 'OFF' }
$expectedTun = if ($Network -and !$ProductionTraffic) { 'ON' } else { 'OFF' }
if ($cache -notcontains ('LIWETUN_TEST_NO_GLOBAL_ROUTES:BOOL=' + $expectedNoGlobal) -or $cache -notcontains ('LIWETUN_TEST_TUN_NETWORK:BOOL=' + $expectedTun)) { throw 'Service compilation mode mismatch' }
$root = Join-Path $env:ProgramFiles ('LiWeTun-CI-' + $env:GITHUB_RUN_ID)
if (Test-Path $root) { throw 'Fresh isolated installation directory required' }
$service = Join-Path $root 'liwetun_service.exe'
$client = Join-Path $root 'liwetun.exe'
$ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$certs = @()
$installed = $false
$checks = [System.Collections.Generic.List[string]]::new()
function DnsSnapshot { return (Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4 -Compress) }
function DefaultRoutes { return (Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Sort-Object InterfaceIndex,DestinationPrefix,NextHop | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric | ConvertTo-Json -Compress) }
$dnsBefore = DnsSnapshot
$routesBefore = DefaultRoutes

function Cert([string]$Name) {
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=' + $Name) -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy NonExportable -NotAfter ([DateTime]::UtcNow.AddDays(1))
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    $store.Open('ReadWrite')
    try { $store.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate.Export('Cert'))) } finally { $store.Close() }
    return $certificate
}
function Sign([string]$Path, $Certificate) {
    signtool sign /q /fd SHA256 /sm /s My /sha1 $Certificate.Thumbprint $Path
    if ($LASTEXITCODE -ne 0) { throw 'Test signature failed' }
}
function Protect([string]$Path) {
    icacls $Path /reset /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Test file ACL reset failed' }
    icacls $Path /setowner '*S-1-5-32-544' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Test file ownership failed' }
}
function Install([string]$Sid) {
    & $service --install $Sid
    if ($LASTEXITCODE -ne 0) { throw 'Test service installation failed' }
    $script:installed = $true
    Start-Service LiWeTun
    $controller = Get-Service LiWeTun
    try { $controller.WaitForStatus('Running',[TimeSpan]::FromSeconds(15)) } finally { $controller.Dispose() }
}
function Uninstall {
    if ($script:installed) {
        & $service --uninstall
        if ($LASTEXITCODE -ne 0) { throw 'Test service cleanup failed' }
        $script:installed = $false
    }
}
function Reject([string]$Executable) {
    $answer = & $Executable --attack
    if ($LASTEXITCODE -ne 0 -or $answer.Trim() -ne 'rejected') { throw 'Unauthorized client accepted' }
}
function SaveFailure([string]$Stage, $Reply) {
    # Only closed numeric probe fields; never a raw exception/core message.
    $failure = @{stage=$Stage;native_exit=$LASTEXITCODE;code=$Reply.code;state=$Reply.state;core_state=$Reply.core_state;runtime_ready=$Reply.runtime_ready;core_state_observed=$Reply.core_state_observed;adapter_seen=$Reply.adapter_seen;stopped_and_cleaned=$Reply.stopped_and_cleaned}
    New-Item -ItemType Directory -Force build/service-evidence | Out-Null
    $failure | ConvertTo-Json | Set-Content -Encoding utf8 build/service-evidence/service-failure.json
}
try {
    $discard = & (Join-Path $Build 'liwetun_service_probe.exe') --disconnect-regression
    if ($LASTEXITCODE -ne 0 -or $discard.Trim() -ne 'unread_reply_discard_reproduced') { throw 'Unread pipe reply regression not reproduced' }
    $checks.Add('old_disconnect_discards_unread_reply_reproduced')
    & (Join-Path $Build 'liwetun_service_probe.exe') --protocol
    if ($LASTEXITCODE -ne 0) { throw 'Protocol bounds check failed' }
    $checks.Add('protocol_bounds')
    New-Item -ItemType Directory $root | Out-Null
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl $root $acl
    Copy-Item (Join-Path $Build 'liwetun_service.exe') $service
    Copy-Item (Join-Path $Build 'liwetun_service_probe.exe') $client
    Protect $service; Protect $client
    & $service --install $ownerSid
    if ($LASTEXITCODE -eq 0) { $installed = $true; throw 'Unsigned service unexpectedly installable' }
    $checks.Add('unsigned_service_denied')
    $certs += Cert ('LiWeTun-CI-' + $env:GITHUB_RUN_ID)
    $certs += Cert ('LiWeTun-Other-CI-' + $env:GITHUB_RUN_ID)
    Sign $service $certs[0]
    if ($Sdk) {
        Copy-Item (Join-Path $Sdk 'trusttunnel.dll') $root
        Copy-Item (Join-Path $Sdk 'wintun.dll') $root
        Protect (Join-Path $root 'trusttunnel.dll'); Protect (Join-Path $root 'wintun.dll')
        Sign (Join-Path $root 'trusttunnel.dll') $certs[0]
    }
    Install $ownerSid
    Reject $client
    $checks.Add('unsigned_client_denied_by_service')
    Sign $client $certs[0]
    $query = (& $client --query | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or $query.code -ne 0 -or $query.state -ne 0 -or $query.core_state -ne 4294967295) { SaveFailure 'signed_owner_query' $query; throw 'Signed owner query failed' }
    if ($Sdk -and $query.runtime_ready -ne 1) { throw 'Signed SDK failed admission' }
    if (!$Sdk -and $query.runtime_ready -ne 0) { throw 'Missing SDK incorrectly available' }
    $runtimeReady = $query.runtime_ready
    $checks.Add('signed_owner_query')
    $checks.Add('unknown_metrics_and_core_state_preserved')
    $holding = [System.Diagnostics.Process]::new()
    $holding.StartInfo = [System.Diagnostics.ProcessStartInfo]::new($client, '--hold-pipe')
    $holding.StartInfo.UseShellExecute = $false
    $holding.StartInfo.RedirectStandardOutput = $true
    try {
        if (!$holding.Start() -or $holding.StandardOutput.ReadLine() -ne 'held') { throw 'Busy-pipe fixture failed' }
        $queued = (& $client --query | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0 -or $queued.code -ne 0) { throw 'Busy-pipe query failed' }
        if (!$holding.WaitForExit(5000) -or $holding.ExitCode -ne 0) { throw 'Busy-pipe fixture did not close' }
    } finally {
        if (!$holding.HasExited) { $holding.Kill(); $holding.WaitForExit() }
        $holding.Dispose()
    }
    $checks.Add('busy_pipe_waits_without_resending')
    $delayed = & $client --delayed-read-query
    if ($LASTEXITCODE -ne 0 -or $delayed.Trim() -ne 'delayed_reply_received') { throw 'Delayed client lost its service reply' }
    $checks.Add('delayed_client_consumes_reply_before_disconnect')
    $invalid = (& $client --invalid-profile | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or $invalid.code -ne 5) { throw 'Malformed profile was not rejected before core execution' }
    $checks.Add('invalid_profile_denied')
    & $client --bad-frame
    if ($LASTEXITCODE -ne 0) { throw 'Oversized frame accepted' }
    $checks.Add('oversized_frame_denied')
    $stop = (& $client --stop | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or $stop.code -ne 0) { SaveFailure 'idempotent_stop' $stop; throw 'Idempotent stop failed' }
    $checks.Add('idempotent_stop')
    # Different trusted signer, same directory and filename: bypass client-side
    # admission in the attack helper to exercise the server check itself.
    Copy-Item (Join-Path $Build 'liwetun_service_probe.exe') $client -Force
    Protect $client
    Sign $client $certs[1]
    Reject $client
    $checks.Add('different_signer_denied_by_service')
    Copy-Item (Join-Path $Build 'liwetun_service_probe.exe') $client -Force
    Protect $client
    Sign $client $certs[0]
    Uninstall
    $other = Get-LocalUser | Where-Object { $_.SID.Value -ne $ownerSid -and $_.Name -in @('DefaultAccount','Guest') } | Select-Object -First 1
    if (!$other) { throw 'Existing foreign account fixture unavailable' }
    Install $other.SID.Value
    Reject $client
    $checks.Add('different_owner_sid_denied_even_to_admin')
    Uninstall
    $driver = $null; $lifecycle = $null
    if ($Sdk) {
        Install $ownerSid
        $privacy = @(& $client --sdk-privacy 2>&1)
        if ($LASTEXITCODE -ne 0 -or $privacy.Count -ne 1 -or $privacy[0].ToString().Trim() -ne 'privacy_profile_verified') { throw 'SDK raw logging suppression failed' }
        $checks.Add('sdk_canary_no_raw_logs_or_files')
        $driver = (& $client --driver-cycle | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0 -or !$driver.adapter_created -or !$driver.adapter_removed) { throw 'Actual Wintun adapter lifecycle failed' }
        $checks.Add('real_wintun_create_close')
        if ($ProductionLifecycle) {
            & (Join-Path $PSScriptRoot 'general-lifecycle.ps1') -Client $client
            $checks.Add('production_config_refused_endpoint_and_network_restoration')
            $lifecycle = @{verified_by='production_refused_loopback_lifecycle';internet_delivery_tested=$false}
        } elseif (!$Network) {
            $lifecycle = (& $client --native-lifecycle build/service-local-uri.txt | ConvertFrom-Json)
            if ($LASTEXITCODE -ne 0 -or !$lifecycle.core_state_observed -or !$lifecycle.stopped_and_cleaned) { SaveFailure 'sdk_refused_endpoint_lifecycle' $lifecycle; throw 'Actual SDK service lifecycle failed' }
            $checks.Add('real_sdk_start_observe_stop')
        }
        if ($Network) {
            if ($ProductionTraffic) { python tools/service/production_network.py --client $client }
            else { python tools/service/network.py --client $client }
            if ($LASTEXITCODE -ne 0) {
                if ($ProductionTraffic) { throw 'Production traffic fixture failed; see safe production-network.json' }
                throw 'Real TUN network qualification failed; see safe network.json'
            }
            if ($ProductionTraffic) {
                $checks.Add('production_single_unbound_https_dns_and_cleanup')
                $lifecycle = @{verified_by='production_single_unbound_ipv4_fixture';full_matrix_qualified=$false}
            } else {
                $checks.Add('tun_https_dns_transport_and_cleanup')
                $lifecycle = @{verified_by='live_endpoint_network_cases';refused_endpoint_smoke='not_run'}
            }
        }
        Uninstall
    }
    $checks.Add('service_uninstalled')
    if ((DnsSnapshot) -ne $dnsBefore -or (DefaultRoutes) -ne $routesBefore) { throw 'DNS or default routes were not restored after CI fixture' }
    $checks.Add('dns_and_default_routes_unchanged')
    $result = @{checks=@($checks); core_runtime_ready=$runtimeReady; signed_service_ipc='verified'; driver_cycle=$driver; sdk_lifecycle=$lifecycle; test_mode_no_global_routes=(!$Network -and !$ProductionLifecycle); test_mode_tun_network=($Network -and !$ProductionTraffic); production_refused_endpoint_lifecycle=[bool]$ProductionLifecycle; production_single_traffic_fixture=[bool]$ProductionTraffic; dns_and_default_routes_unchanged=$true; release_ready=$false}
    New-Item -ItemType Directory -Force build/service-evidence | Out-Null
    $result | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 build/service-evidence/qualification.json
} finally {
    try { Uninstall } finally {
        # Exact task-created certificates only; no pre-existing trust changes.
        foreach ($certificate in $certs) {
            Remove-Item ('Cert:\LocalMachine\Root\' + $certificate.Thumbprint) -ErrorAction SilentlyContinue
            Remove-Item ('Cert:\LocalMachine\My\' + $certificate.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
        }
    }
}
