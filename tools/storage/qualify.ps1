# Disposable CI only. No production profiles, drivers or network changes.
param([string]$Build = 'build/storage/Release')
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_RUN_ID -notmatch '^[0-9]{1,20}$') { throw 'Disposable GitHub runner required' }
$userRoot = Join-Path $env:LOCALAPPDATA 'LiWeTun-Storage-CI'
$root = Join-Path $env:ProgramFiles ('LiWeTun-Storage-CI-' + $env:GITHUB_RUN_ID)
$name = 'LiWeTunStorageCI' + $env:GITHUB_RUN_ID
$probe = Join-Path $Build 'liwetun_storage_probe.exe'
$evidence = 'build/storage-evidence'
if ((Test-Path $userRoot) -or (Test-Path $root) -or (Get-Service $name -ErrorAction SilentlyContinue)) { throw 'Fresh isolated fixtures required' }
New-Item -ItemType Directory -Force $evidence | Out-Null
$createdRoot = $false
$createdService = $false
$userStarted = $false
$passed = $false
$stage = 'user_probe'
$checks = [System.Collections.Generic.List[string]]::new()
try {
    $userStarted = $true
    $answer = & $probe
    $exit = $LASTEXITCODE
    $user = $answer | ConvertFrom-Json
    $user | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $evidence 'user.json')
    if ($exit -ne 0 -or !$user.passed) { throw 'User storage qualification failed' }
    $checks.Add('user_probe_passed')
    $stage = 'protected_cross_context_fixture'
    New-Item -ItemType Directory $root | Out-Null
    $createdRoot = $true
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl $root $acl
    $installedProbe = Join-Path $root 'liwetun_storage_probe.exe'
    $ciphertext = Join-Path $root 'cross-user.bin'
    Copy-Item $probe $installedProbe
    Copy-Item (Join-Path $userRoot 'profiles.v1.bin') $ciphertext
    foreach ($file in @($installedProbe, $ciphertext)) {
        icacls $file /reset /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Fixture ACL reset failed' }
        icacls $file /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Fixture ownership failed' }
    }
    $before = (Get-FileHash $ciphertext -Algorithm SHA256).Hash
    if ($before -ne (Get-FileHash (Join-Path $userRoot 'profiles.v1.bin') -Algorithm SHA256).Hash) { throw 'Ciphertext copy mismatch' }
    $stage = 'system_context_denial'
    New-Service -Name $name -BinaryPathName ('"' + $installedProbe + '" --system-test') -StartupType Manual | Out-Null
    $createdService = $true
    # This helper exits as soon as it writes its result; do not require it to
    # remain Running after Start-Service's asynchronous SCM observation.
    sc.exe start $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'System fixture launch failed' }
    $resultPath = Join-Path $root 'system-result.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (!(Test-Path $resultPath) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    $system = Get-Content $resultPath -Raw | ConvertFrom-Json
    if (!$system.input_valid -or !$system.wrong_context_denied) { throw 'Current-user DPAPI boundary failed' }
    $system | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidence 'system.json')
    if ($before -ne (Get-FileHash $ciphertext -Algorithm SHA256).Hash) { throw 'Cross-context attempt changed ciphertext' }
    $checks.Add('valid_user_ciphertext_denied_to_local_system')
    $checks.Add('cross_context_ciphertext_unchanged')
    $stage = 'user_cleanup'
    $cleanup = (& $probe --cleanup | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or !$cleanup.passed -or (Test-Path $userRoot)) { throw 'User fixture cleanup failed' }
    $checks.Add('original_user_can_still_decrypt_and_remove')
    $userStarted = $false
    $passed = $true
} finally {
    $cleanupOk = $true
    if ($createdService) {
        try {
            $service = Get-Service $name -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne 'Stopped') { Stop-Service $name -Force }
            sc.exe delete $name | Out-Null
            if ($LASTEXITCODE -ne 0) { $cleanupOk = $false }
        } catch { $cleanupOk = $false }
    }
    if ($createdRoot) {
        try { Remove-Item $root -Recurse -Force } catch { $cleanupOk = $false }
    }
    if ($userStarted -and (Test-Path $userRoot)) {
        # Only the fresh fixed CI directory created by this invocation. Never
        # traverse a fixture symlink if a native adversarial test failed midway.
        try {
            foreach ($entry in Get-ChildItem $userRoot -Force) {
                if ($entry.PSIsContainer) { throw 'Unexpected fixture directory' }
                $entry.Delete()
            }
            Remove-Item $userRoot
        } catch { $cleanupOk = $false }
    }
    if ((Test-Path $root) -or (Test-Path $userRoot)) { $cleanupOk = $false }
    @{passed=($passed -and $cleanupOk); stage=$stage; checks=$checks.ToArray(); cleanup_passed=$cleanupOk; release_ready=$false} |
        ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $evidence 'qualification.json')
    if (!$cleanupOk) { throw 'Storage fixture cleanup failed' }
}
