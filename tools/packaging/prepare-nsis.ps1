$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Disposable CI required' }
$pin = Get-Content (Join-Path $PSScriptRoot 'nsis.json') -Raw | ConvertFrom-Json
$archive = Join-Path $env:RUNNER_TEMP 'liwetun-nsis.zip'
$destination = Join-Path $env:RUNNER_TEMP 'liwetun-nsis'
if ((Test-Path $archive) -or (Test-Path $destination)) { throw 'Fresh NSIS staging required' }
$attempts = [Collections.Generic.List[object]]::new()
$verified = $false
foreach ($url in (@($pin.url) + @($pin.fallback_urls))) {
    if (Test-Path $archive) { Remove-Item $archive }
    curl.exe --disable --fail --location --silent --show-error --connect-timeout 15 --max-time 60 --max-filesize 33554432 --output $archive $url
    $code = $LASTEXITCODE
    $digest = if (Test-Path $archive -PathType Leaf) { (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    $verified = $code -eq 0 -and $digest -ceq $pin.sha256
    $attempts.Add(@{attempt=$attempts.Count + 1; curl_exit=$code; sha256=$digest; matched=$verified})
    if ($verified) { break }
}
New-Item -ItemType Directory -Force build/package-evidence | Out-Null
$attempts | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 build/package-evidence/nsis-fetch.json
if (!$verified) { throw 'NSIS archive digest mismatch' }
Expand-Archive $archive $destination
$toolRoot = Join-Path $destination $pin.directory
$compiler = Join-Path $toolRoot 'makensis.exe'
$version = (& $compiler /VERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $version -cne ('v' + $pin.version)) { throw 'NSIS compiler version mismatch' }
if (!(Test-Path (Join-Path $toolRoot 'COPYING') -PathType Leaf)) { throw 'NSIS notice missing' }
"LIWETUN_NSIS_ROOT=$toolRoot" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
