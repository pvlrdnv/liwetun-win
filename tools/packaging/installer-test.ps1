param([Parameter(Mandatory)][string]$CertificateThumbprint)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $CertificateThumbprint -cnotmatch '^[0-9A-Fa-f]{40}$') { throw 'Disposable signed CI required' }
$root = Join-Path $env:ProgramFiles 'LiWeTun'
$registry = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\LiWeTun'
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'LiWeTun.lnk'
$evidence = 'build/package-evidence'
$payload = (Resolve-Path build/package-payload).Path
$output = Join-Path (Resolve-Path build).Path 'installer-ci-only'
if ((Test-Path $root) -or (Test-Path $registry) -or (Test-Path $shortcut) -or (Test-Path $output) -or (Get-Service LiWeTun -ErrorAction SilentlyContinue)) { throw 'Fresh installer fixtures required' }
New-Item -ItemType Directory $output | Out-Null
$passed = $false
$stage = 'compiler_inputs'
$checks = [Collections.Generic.List[string]]::new()
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function InvokeInstaller([string]$Executable, [string]$Arguments) {
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new($Executable,$Arguments)
    $process.StartInfo.UseShellExecute = $false
    try {
        if (!$process.Start()) { throw 'Installer launch failed' }
        if (!$process.WaitForExit(120000)) { $process.Kill(); $process.WaitForExit(); throw 'Installer timeout' }
        return $process.ExitCode
    } finally { $process.Dispose() }
}
function VerifySignature([string]$Path) {
    $signature = Get-AuthenticodeSignature $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint) { throw 'Installer component signature mismatch' }
}
function VerifyAbsent {
    if ((Test-Path $root) -or (Test-Path $registry) -or (Test-Path $shortcut) -or (Get-Service LiWeTun -ErrorAction SilentlyContinue)) { throw 'Installer did not restore absent state' }
}
try {
    $manifest = Get-Content (Join-Path $evidence 'payload-manifest.json') -Raw | ConvertFrom-Json
    $actual = @(Get-ChildItem $payload -File -Recurse -Force)
    if ($actual.Count -ne $manifest.files.Count -or $manifest.network_test_modes_enabled -ne $false -or $manifest.tunnel_started -ne $false) { throw 'Unqualified installer payload' }
    if (Get-ChildItem $payload -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Unexpected installer payload reparse point' }
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('!macro RemovePayload FAILURE')
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $expectedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.files) {
        $relative = $file.file
        if ($relative -cnotmatch '^[A-Za-z0-9_.+/-]+$' -or $relative.StartsWith('/') -or $relative.Split('/') -contains '..' -or $relative.Split('/') -contains '.' -or $relative.Split('/') -contains '' -or !$expectedFiles.Add($relative)) { throw 'Unsafe installer file path' }
        if ((Get-FileHash (Join-Path $payload $relative) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw 'Installer payload digest mismatch' }
        $relative = $relative.Replace('/','\')
        $lines.Add('  IfFileExists "$INSTDIR\' + $relative + '" 0 +4')
        $lines.Add('  ClearErrors')
        $lines.Add('  Delete "$INSTDIR\' + $relative + '"')
        $lines.Add('  IfErrors ${FAILURE}')
        $parent = [IO.Path]::GetDirectoryName($relative)
        while ($parent) { [void]$directories.Add($parent); $parent = [IO.Path]::GetDirectoryName($parent) }
    }
    foreach ($file in $actual) {
        if (!$expectedFiles.Contains([IO.Path]::GetRelativePath($payload,$file.FullName).Replace('\','/'))) { throw 'Unlisted installer payload file' }
    }
    foreach ($directory in ($directories | Sort-Object Length -Descending)) { $lines.Add('  RMDir "$INSTDIR\' + $directory + '"') }
    $lines.Add('!macroend')
    $include = Join-Path $output 'payload-files.nsh'
    $lines | Set-Content -Encoding utf8 $include
    $installer = Join-Path $output 'LiWeTun-0.1.0-preview-ci-only.exe'
    $compiler = Join-Path $env:LIWETUN_NSIS_ROOT 'makensis.exe'
    $icon = (Resolve-Path windows/runner/resources/app_icon.ico).Path
    & $compiler /NOCONFIG /V2 "/DPAYLOAD=$payload" "/DDELETE_INCLUDE=$include" "/DOUTPUT_EXE=$installer" "/DICON_FILE=$icon" "/DSIGN_THUMBPRINT=$CertificateThumbprint" tools/packaging/liwetun.nsi
    if ($LASTEXITCODE -ne 0) { throw 'Pinned installer compile failed' }
    signtool sign /q /fd SHA256 /sm /s My /sha1 $CertificateThumbprint $installer
    if ($LASTEXITCODE -ne 0) { throw 'Installer CI signature failed' }
    VerifySignature $installer
    $checks.Add('pinned_compiler_and_signed_installer')

    $stage = 'preexisting_directory_denial'
    New-Item -ItemType Directory $root | Out-Null
    $sentinel = Join-Path $root 'synthetic-preserve.txt'
    [IO.File]::WriteAllText($sentinel,'synthetic-preserve')
    if ((InvokeInstaller $installer "/S /OWNER_SID=$sid") -ne 21 -or [IO.File]::ReadAllText($sentinel) -cne 'synthetic-preserve' -or (Get-Service LiWeTun -ErrorAction SilentlyContinue)) { throw 'Preexisting installation was changed' }
    Remove-Item $sentinel
    Remove-Item $root
    $checks.Add('preexisting_directory_preserved')

    $stage = 'invalid_owner_rollback'
    if ((InvokeInstaller $installer '/S /OWNER_SID=S-1-0-0') -ne 31) { throw 'Invalid owner installation was not rejected' }
    VerifyAbsent
    $checks.Add('invalid_owner_rolls_back_fresh_files_and_service')

    $stage = 'fresh_install'
    if ((InvokeInstaller $installer "/S /OWNER_SID=$sid") -ne 0) { throw 'Fresh installation failed' }
    if (!(Test-Path $registry) -or !(Test-Path $shortcut)) { throw 'Installer registration missing' }
    $service = Get-Service LiWeTun
    try {
        if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Manual') { throw 'Installer started or autostarted service' }
    } finally { $service.Dispose() }
    foreach ($file in $manifest.files) {
        if ((Get-FileHash (Join-Path $root $file.file) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw 'Installed file differs from signed payload' }
    }
    $uninstaller = Join-Path $root 'Uninstall.exe'
    VerifySignature $uninstaller
    $checks.Add('fresh_install_preserves_payload_and_signed_uninstaller')
    if ((InvokeInstaller $installer "/S /OWNER_SID=$sid") -ne 21) { throw 'Duplicate installer was admitted' }
    $checks.Add('duplicate_install_denied')

    $stage = 'installed_medium_query'
    $probe = Join-Path $root 'liwetun_package_probe.exe'
    Copy-Item build/package-service/Release/liwetun_package_probe.exe $probe
    signtool sign /q /fd SHA256 /sm /s My /sha1 $CertificateThumbprint $probe
    if ($LASTEXITCODE -ne 0) { throw 'Installed probe signature failed' }
    icacls $probe /setowner '*S-1-5-32-544' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installed probe ownership failed' }
    Start-Service LiWeTun
    $controller = Get-Service LiWeTun
    try { $controller.WaitForStatus('Running',[TimeSpan]::FromSeconds(15)) } finally { $controller.Dispose() }
    $medium = & $probe | ConvertFrom-Json
    $mediumExit = $LASTEXITCODE
    $medium | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidence 'installer-medium-integrity.json')
    if ($mediumExit -ne 0 -or !$medium.passed -or !$medium.service_metadata_read_only) { throw 'Installed medium-integrity query failed' }
    Remove-Item $probe
    $checks.Add('installed_gui_queries_production_service_at_medium_integrity')

    $stage = 'uninstall_preserves_unknown_file'
    $uninstallCopy = Join-Path $output 'uninstall-body-ci.exe'
    Copy-Item $uninstaller $uninstallCopy
    VerifySignature $uninstallCopy
    [IO.File]::WriteAllText($sentinel,'synthetic-preserve')
    if ((InvokeInstaller $uninstallCopy ("/S _?=" + $root)) -ne 41 -or [IO.File]::ReadAllText($sentinel) -cne 'synthetic-preserve' -or !(Test-Path $uninstaller) -or !(Test-Path $registry)) { throw 'Uninstaller removed unknown data or recovery entry' }
    $checks.Add('unknown_file_preserved_with_retry_uninstaller')
    Remove-Item $sentinel
    if ((InvokeInstaller $uninstallCopy ("/S _?=" + $root)) -ne 0) { throw 'Uninstall retry failed' }
    VerifyAbsent
    $checks.Add('uninstall_retry_after_service_removal')

    $stage = 'normal_uninstaller_bootstrap'
    if ((InvokeInstaller $installer "/S /OWNER_SID=$sid") -ne 0) { throw 'Second fresh install failed' }
    if ((InvokeInstaller $uninstaller '/S') -ne 0) { throw 'Normal uninstaller launch failed' }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ((Test-Path $root) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    VerifyAbsent
    $checks.Add('normal_uninstaller_bootstrap_and_removal')
    $passed = $true
    @{installer_sha256=(Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant(); source_commit=$env:GITHUB_SHA; signing='ephemeral_ci_only'; release_ready=$false} |
        ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidence 'installer-digest.json')
} finally {
    # This entire fixture is guarded before claiming any fixed path/name.
    # Remove only this invocation's fresh disposable installation/registration.
    $cleanup = $true
    try {
        $service = Get-Service LiWeTun -ErrorAction SilentlyContinue
        if ($service) {
            $service.Dispose()
            $configuration = Get-CimInstance Win32_Service -Filter "Name='LiWeTun'"
            $expected = '"' + (Join-Path $root 'liwetun_service.exe') + '" --service '
            if (!$configuration.PathName.StartsWith($expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected fixture service owner path' }
            Stop-Service LiWeTun -ErrorAction Stop
            sc.exe delete LiWeTun | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Fixture service cleanup failed' }
        }
        if (Test-Path $root) { Remove-Item $root -Recurse -Force }
        if (Test-Path $registry) { Remove-Item $registry -Recurse }
        if (Test-Path $shortcut) { Remove-Item $shortcut }
        VerifyAbsent
    } catch { $cleanup = $false }
    @{passed=($passed -and $cleanup); stage=$stage; checks=$checks.ToArray(); cleanup_passed=$cleanup; signing='ephemeral_ci_only'; tunnel_started=$false; desktop_owner_selection_tested=$false; release_ready=$false} |
        ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 (Join-Path $evidence 'installer-qualification.json')
    if (!$cleanup) { throw 'Installer fixture cleanup failed' }
}
