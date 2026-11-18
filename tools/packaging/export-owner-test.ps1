param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_RUN_ID -notmatch '^[0-9]{1,20}$') { throw 'Disposable owner-test builder required' }
$output = 'build/owner-test-handoff'
if (Test-Path $output) { throw 'Fresh owner handoff directory required' }
$qualification = Get-Content build/package-evidence/qualification.json -Raw | ConvertFrom-Json
$installerQualification = Get-Content build/package-evidence/installer-qualification.json -Raw | ConvertFrom-Json
$digest = Get-Content build/package-evidence/installer-digest.json -Raw | ConvertFrom-Json
$payload = Get-Content build/package-evidence/payload-manifest.json -Raw | ConvertFrom-Json
if ($qualification.passed -ne $true -or $qualification.cleanup_passed -ne $true -or $qualification.network_unchanged -ne $true -or $qualification.installer_tested -ne $true -or $installerQualification.passed -ne $true) { throw 'Owner package qualifications incomplete' }
if ($digest.signing -ne 'dedicated_owner_test_certificate' -or $payload.signing -ne 'dedicated_owner_test_certificate' -or $payload.network_test_modes_enabled -ne $false -or $payload.release_ready -ne $false) { throw 'Owner package signing/mode mismatch' }
if ($Certificate.Subject -cne ('CN=LiWeTun Owner Test ' + $env:GITHUB_RUN_ID) -or $Certificate.Subject -cne $Certificate.Issuer) { throw 'Unexpected test publisher' }
$eku = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
if ($eku.Count -ne 1 -or $eku[0].EnhancedKeyUsages.Count -ne 1 -or $eku[0].EnhancedKeyUsages[0].Value -ne '1.3.6.1.5.5.7.3.3') { throw 'Test certificate must be code-signing only' }
$installer = 'build/installer-ci-only/LiWeTun-0.1.1-owner-test.exe'
$installerHash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($installerHash -ne $digest.installer_sha256 -or $digest.source_commit -ne $env:GITHUB_SHA) { throw 'Qualified installer digest mismatch' }
# CI trust has already been removed. Verify the retained signer identity and
# qualified file digest, rather than treating an untrusted chain as a success.
$signature = Get-AuthenticodeSignature $installer
if (!$signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $Certificate.Thumbprint) { throw 'Owner installer publisher mismatch' }
$publicBytes = $Certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$public = [Security.Cryptography.X509Certificates.X509Certificate2]::new($publicBytes)
if ($public.HasPrivateKey) { throw 'Private signing key export is forbidden' }
$certificateHash = $public.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
$notAfter = $public.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
New-Item -ItemType Directory $output | Out-Null
Copy-Item $installer (Join-Path $output 'LiWeTun-0.1.1-owner-test.exe')
[IO.File]::WriteAllBytes((Join-Path $output 'LiWeTun-Owner-Test.cer'),$publicBytes)
$manifest = @{
    kind='dedicated_owner_test'; version='0.1.1+2'; source_run=$env:GITHUB_RUN_ID; service_source=$env:GITHUB_SHA
    gui_source=$payload.gui_source; sdk_source_run=$payload.sdk_source_run
    installer_file='LiWeTun-0.1.1-owner-test.exe'; installer_sha256=$installerHash
    certificate_file='LiWeTun-Owner-Test.cer'; certificate_sha256=$certificateHash
    certificate_sha1=$public.Thumbprint; publisher=$public.Subject
    certificate_not_before_utc=$public.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    certificate_not_after_utc=$notAfter; certificate_eku='1.3.6.1.5.5.7.3.3'
    private_key_exported=$false; qualification_passed=$true; owner_desktop_acceptance_passed=$false
    connection_profiles_included=$false; network_test_modes_enabled=$false
    windows_10_qualified=$false; windows_11_qualified=$false; release_ready=$false
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $output 'TEST-MANIFEST.json')
$readme = Get-Content tools/packaging/OWNER_TEST_README_RU.txt -Raw
$readme = $readme.Replace('%CERT_SHA256%',$certificateHash).Replace('%INSTALLER_SHA256%',$installerHash).Replace('%CERT_SHA1%',$public.Thumbprint).Replace('%VALID_UNTIL%',$notAfter).Replace('%PUBLISHER%',$public.Subject)
[IO.File]::WriteAllText((Join-Path $output 'README_RU.txt'),$readme,[Text.UTF8Encoding]::new($true))
# The handoff contains exactly these four files. Never upload build directories,
# stores, signing keys, connection fixtures or the generic CI certificate.
$names = @((Get-ChildItem $output -File).Name | Sort-Object)
if (($names -join '|') -cne 'LiWeTun-0.1.1-owner-test.exe|LiWeTun-Owner-Test.cer|README_RU.txt|TEST-MANIFEST.json') { throw 'Unexpected owner handoff contents' }
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 build/package-evidence/owner-test-manifest.json
