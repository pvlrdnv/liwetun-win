$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Disposable CI required' }
$pin = Get-Content (Join-Path $PSScriptRoot 'nsis.json') -Raw | ConvertFrom-Json
$archive = Join-Path $env:RUNNER_TEMP 'liwetun-nsis.zip'
$destination = Join-Path $env:RUNNER_TEMP 'liwetun-nsis'
if ((Test-Path $archive) -or (Test-Path $destination)) { throw 'Fresh NSIS staging required' }
Invoke-WebRequest -Uri $pin.url -OutFile $archive
if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pin.sha256) { throw 'NSIS archive digest mismatch' }
Expand-Archive $archive $destination
$toolRoot = Join-Path $destination $pin.directory
$compiler = Join-Path $toolRoot 'makensis.exe'
$version = (& $compiler /VERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $version -cne ('v' + $pin.version)) { throw 'NSIS compiler version mismatch' }
if (!(Test-Path (Join-Path $toolRoot 'COPYING') -PathType Leaf)) { throw 'NSIS notice missing' }
"LIWETUN_NSIS_ROOT=$toolRoot" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
