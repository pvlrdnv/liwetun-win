param([switch]$Installer)
# Disposable CI only. Production-mode binaries, read-only IPC; no tunnel start.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_RUN_ID -notmatch '^[0-9]{1,20}$') { throw 'Disposable GitHub runner required' }
$root = Join-Path $env:ProgramFiles ('LiWeTun-Package-CI-' + $env:GITHUB_RUN_ID)
$payload = 'build/package-payload'
$evidence = 'build/package-evidence'
if ((Test-Path $root) -or (Test-Path $payload) -or (Get-Service LiWeTun -ErrorAction SilentlyContinue)) { throw 'Fresh package fixtures required' }
$created = $false
$installed = $false
$certificate = $null
$stage = 'verify_gui_input'
$passed = $false
$installerPassed = $false
$checks = [System.Collections.Generic.List[string]]::new()
New-Item -ItemType Directory -Force $evidence | Out-Null
function Snapshot {
    return @{
        dns=(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4 -Compress)
        routes=(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | ConvertTo-Json -Compress)
        adapter=[bool](Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -eq 'LiWeTun' })
    }
}
function Sign([string]$Path) {
    signtool sign /q /fd SHA256 /sm /s My /sha1 $certificate.Thumbprint $Path
    if ($LASTEXITCODE -ne 0) { throw 'CI payload signature failed' }
}
function Status([string]$Executable) {
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new($Executable, '--service-status')
    $process.StartInfo.WorkingDirectory = $root
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    try {
        if (!$process.Start()) { throw 'GUI status launch failed' }
        if (!$process.WaitForExit(15000)) { $process.Kill(); $process.WaitForExit(); throw 'GUI status timeout' }
        $output = $process.StandardOutput.ReadToEnd()
        if ($output.Length -gt 2048 -or $process.ExitCode -ne 0) { throw 'GUI status query failed' }
        try { return $output | ConvertFrom-Json } catch { throw 'Invalid closed GUI status reply' }
    } finally { $process.Dispose() }
}
$before = Snapshot
if ($before.adapter) { throw 'Preexisting task adapter' }
try {
    foreach ($flag in @('LIWETUN_TEST_NO_GLOBAL_ROUTES', 'LIWETUN_TEST_TUN_NETWORK')) {
        if ((Get-Content build/package-service/CMakeCache.txt) -notcontains ($flag + ':BOOL=OFF')) { throw 'Unexpected test network mode in package service' }
    }
    $provenance = Get-Content build/gui-provenance/gui-runtime-provenance.json -Raw | ConvertFrom-Json
    $guiRoot = (Resolve-Path build/gui-runtime).Path
    $actual = @(Get-ChildItem $guiRoot -File -Recurse)
    if ($actual.Count -ne $provenance.files.Count) { throw 'Unexpected GUI artifact contents' }
    $expectedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $provenance.files) {
        $parts = $file.file.Split('/')
        if ($file.file -notmatch '^[A-Za-z0-9_.+/-]+$' -or $parts -contains '..' -or $parts -contains '.' -or $parts -contains '' -or $file.file.StartsWith('/') -or $file.sha256 -notmatch '^[0-9a-f]{64}$' -or !$expectedFiles.Add($file.file)) { throw 'Invalid GUI file manifest' }
        $path = Join-Path $guiRoot $file.file
        if ((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw 'GUI file digest mismatch' }
    }
    foreach ($file in $actual) {
        if (!$expectedFiles.Contains([IO.Path]::GetRelativePath($guiRoot,$file.FullName).Replace('\','/'))) { throw 'Unlisted GUI artifact file' }
    }
    if (Get-ChildItem $guiRoot -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Unexpected GUI reparse point' }
    $stage = 'assemble_pinned_payload'
    New-Item -ItemType Directory $payload | Out-Null
    Copy-Item (Join-Path $guiRoot '*') $payload -Recurse
    Copy-Item build/package-service/Release/liwetun_service.exe $payload
    $pinFile = if ($env:SOURCE_PINNED -eq 'true') { 'native/sdk/runtime-sources.json' } else { 'native/sdk/runtime.json' }
    $pin = Get-Content $pinFile -Raw | ConvertFrom-Json
    Copy-Item $pinFile (Join-Path $evidence 'sdk-runtime-input.json')
    foreach ($file in @('trusttunnel.dll','wintun.dll')) {
        $path = Join-Path build/sdk-runtime $file
        if ((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pin.files.PSObject.Properties[$file].Value) { throw 'SDK file digest mismatch' }
        Copy-Item $path $payload
    }
    $stage = 'original_microsoft_crt'
    $crt = Join-Path $env:VCToolsRedistDir 'x64/Microsoft.VC143.CRT'
    if (!(Test-Path $crt -PathType Container)) { throw 'MSVC app-local runtime unavailable' }
    $crtFiles = @(Get-ChildItem $crt -File -Filter '*.dll')
    if (!$crtFiles.Count) { throw 'MSVC app-local runtime is empty' }
    $crtInventory = @(foreach ($file in $crtFiles) {
        if ($file.Name -notmatch '^[A-Za-z0-9_.-]+\.dll$' -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected CRT file' }
        $signature = Get-AuthenticodeSignature $file.FullName
        $name = if ($signature.SignerCertificate) { $signature.SignerCertificate.GetNameInfo('SimpleName',$false) } else { '' }
        $publisher = switch -Exact ($name) {
            'Microsoft Corporation' { 'microsoft_corporation' }
            'Microsoft Windows Software Compatibility Publisher' { 'microsoft_windows_software_compatibility' }
            'Microsoft Windows' { 'microsoft_windows' }
            '' { 'none' }
            default { 'other' }
        }
        @{file=$file.Name; signature_status=[int]$signature.Status; publisher=$publisher; sha256=(Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    $crtInventory | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 (Join-Path $evidence 'crt-inputs.json')
    foreach ($file in $crtFiles) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected CRT reparse point' }
        $signature = Get-AuthenticodeSignature $file.FullName
        $trustedPublishers = @('Microsoft Corporation', 'Microsoft Windows Software Compatibility Publisher')
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo('SimpleName',$false) -cnotin $trustedPublishers) { throw 'Untrusted original CRT runtime' }
        $target = Join-Path $payload $file.Name
        if (Test-Path $target) { throw 'Duplicate CRT runtime in GUI payload' }
        Copy-Item $file.FullName $target
    }
    $checks.Add('original_microsoft_app_local_crt_staged')
    $stage = 'notices_and_native_architecture'
    $noticePin = Get-Content tools/sdk/client-notices.json -Raw | ConvertFrom-Json
    if ($provenance.flutter_framework_revision -ne $noticePin.flutter_framework_commit -or $provenance.flutter_engine_revision -ne $noticePin.flutter_engine_commit -or $provenance.notice_verification.application_bundle.engine_notice_sha256 -ne $noticePin.engine_notice_sha256 -or $provenance.notice_verification.application_bundle.engine_notice_bodies_preserved -ne $true -or $provenance.notice_verification.license_approval -ne $false) { throw 'GUI notice/engine provenance mismatch' }
    $noticeArgs = @()
    if ($env:SOURCE_PINNED -eq 'true') { $noticeArgs += '--source-pinned' }
    python tools/sdk/client_notices.py @noticeArgs --bundle (Join-Path $payload 'data/flutter_assets/NOTICES.Z') --report (Join-Path $evidence 'client-notice-bytes.json')
    if ($LASTEXITCODE -ne 0) { throw 'Packaged client notice bytes missing or changed' }
    $checks.Add('native_and_engine_notice_bytes_verified_not_legal_approval')
    New-Item -ItemType Directory (Join-Path $payload 'notices') | Out-Null
    Copy-Item third_party/sdk (Join-Path $payload 'notices') -Recurse
    Copy-Item third_party/rust (Join-Path $payload 'notices') -Recurse
    if ($env:SOURCE_PINNED -eq 'true') {
        Copy-Item native/sdk/notice-sources.json (Join-Path $payload 'notices/sdk/CANDIDATE_SOURCE_RECEIPT.json')
        Copy-Item native/sdk/source-pins.json (Join-Path $payload 'notices/sdk/SOURCE_PINS.json')
    }
    if ($Installer) {
        if (!$env:LIWETUN_NSIS_ROOT) { throw 'Pinned NSIS compiler was not prepared' }
        Copy-Item (Join-Path $env:LIWETUN_NSIS_ROOT 'COPYING') (Join-Path $payload 'notices/NSIS-COPYING.txt')
    }
    foreach ($file in Get-ChildItem $payload -File | Where-Object { $_.Extension -in @('.exe','.dll') }) {
        $stream = [IO.File]::OpenRead($file.FullName)
        $reader = [IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Invalid PE file' }
            $stream.Position = 0x3c
            $offset = $reader.ReadUInt32()
            if ($offset -lt 64 -or $offset -gt $stream.Length - 24) { throw 'Invalid PE header offset' }
            $stream.Position = $offset
            if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Non-x64 PE file in payload' }
        } finally { $reader.Dispose(); $stream.Dispose() }
    }
    $checks.Add('all_native_payload_images_are_x64')
    $checks.Add('gui_sdk_and_notice_inputs_verified')
    $stage = 'ci_signing'
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=LiWeTun-Package-CI-' + $env:GITHUB_RUN_ID) -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy NonExportable -NotAfter ([DateTime]::UtcNow.AddDays(1))
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    $store.Open('ReadWrite')
    try { $store.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate.Export('Cert'))) } finally { $store.Close() }
    foreach ($name in @('liwetun.exe','liwetun_service.exe','trusttunnel.dll')) { Sign (Join-Path $payload $name) }
    $checks.Add('common_ci_signer_only_for_owned_components')
    $checks.Add('original_wintun_bytes_preserved')
    $stage = 'protected_payload_directory'
    New-Item -ItemType Directory $root | Out-Null
    $created = $true
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl $root $acl
    Copy-Item (Join-Path $payload '*') $root -Recurse
    $probe = Join-Path $root 'liwetun_package_probe.exe'
    Copy-Item build/package-service/Release/liwetun_package_probe.exe $probe
    Sign $probe
    icacls $root /reset /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Payload child ACL reset failed' }
    # Reset only children above; restore the root's explicit private-write policy.
    Set-Acl $root $acl
    foreach ($entry in Get-ChildItem $root -Recurse -Force) {
        icacls $entry.FullName /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Payload ownership failed' }
    }
    $service = Join-Path $root 'liwetun_service.exe'
    $stage = 'production_mode_service_install'
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & $service --install $sid
    if ($LASTEXITCODE -ne 0) { throw 'Production-mode service installation failed' }
    $installed = $true
    Start-Service LiWeTun
    $controller = Get-Service LiWeTun
    try { $controller.WaitForStatus('Running',[TimeSpan]::FromSeconds(15)) } finally { $controller.Dispose() }
    $stage = 'signed_gui_query'
    $reply = Status (Join-Path $root 'liwetun.exe')
    if ($reply.code -ne 0 -or $reply.state -ne 0 -or $reply.runtime_ready -ne $true -or $null -ne $reply.core_state) { throw 'Signed GUI did not observe idle SDK' }
    $checks.Add('actual_signed_gui_queries_production_service')
    $stage = 'medium_integrity_query'
    $medium = & $probe | ConvertFrom-Json
    $exit = $LASTEXITCODE
    $medium | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidence 'medium-integrity.json')
    if ($exit -ne 0 -or !$medium.passed -or $medium.service_metadata_read_only -ne $true) { throw 'Restricted medium-integrity GUI could not query service' }
    $checks.Add('medium_integrity_without_enabled_admin_group')
    $checks.Add('owner_can_read_service_identity_but_not_write_process_or_duplicate_token')
    $after = Snapshot
    if ($after.adapter -or $after.dns -ne $before.dns -or $after.routes -ne $before.routes) { throw 'Read-only package qualification changed networking' }
    $checks.Add('no_tunnel_start_or_network_configuration_change')
    $payloadRoot = (Resolve-Path $payload).Path
    $files = @(Get-ChildItem $payload -File -Recurse | ForEach-Object {
        @{file=[IO.Path]::GetRelativePath($payloadRoot,$_.FullName).Replace('\','/'); sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    @{gui_source=$provenance.source_commit; sdk_source_run=$pin.source_run; service_source=$env:GITHUB_SHA; signing='ephemeral_ci_only'; release_ready=$false; network_test_modes_enabled=$false; tunnel_started=$false; files=$files} |
        ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $evidence 'payload-manifest.json')
    if ($Installer) {
        $stage = 'installer_qualification'
        & $service --uninstall
        if ($LASTEXITCODE -ne 0) { throw 'Payload fixture removal before installer failed' }
        $installed = $false
        Remove-Item $root -Recurse -Force
        $created = $false
        & (Join-Path $PSScriptRoot 'installer-test.ps1') -CertificateThumbprint $certificate.Thumbprint
        $installerPassed = $true
        $checks.Add('fresh_installer_rollback_medium_query_and_uninstall')
    }
    $passed = $true
} finally {
    $cleanup = $true
    if ($installed) {
        & $service --uninstall
        if ($LASTEXITCODE -ne 0) { $cleanup = $false }
    }
    if ($created) { try { Remove-Item $root -Recurse -Force } catch { $cleanup = $false } }
    if ($certificate) {
        foreach ($location in @('Root','My')) {
            try {
                $path = 'Cert:\LocalMachine\' + $location + '\' + $certificate.Thumbprint
                if (Test-Path $path) { Remove-Item $path -Force }
            } catch { $cleanup = $false }
        }
    }
    $after = Snapshot
    $restored = !$after.adapter -and $after.dns -eq $before.dns -and $after.routes -eq $before.routes
    @{passed=($passed -and $cleanup -and $restored); stage=$stage; checks=$checks.ToArray(); cleanup_passed=$cleanup; network_unchanged=$restored; release_ready=$false; installer_tested=$installerPassed} |
        ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $evidence 'qualification.json')
    if (!$cleanup -or !$restored) { throw 'Payload fixture cleanup or network restoration failed' }
}
