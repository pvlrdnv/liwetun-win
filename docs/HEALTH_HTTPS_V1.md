# HTTPS probe candidate contract

Status: HTTP/socket contracts and Schannel preflight PASS (44165060837).
Real loopback TLS 1.2 matrix **13 cases PASS** (44168412480), with explicit
per-certificate revocation verification. [Closed evidence](evidence/health-tls-44168412480.json).
Live SDK-owned HTTPS remains unimplemented. This document does not enable
application health.

## Reserved fixture target and wire contract

The candidate request is `POST /liwetun/health/v1`, with a fixed reserved Host
`health.liwetun.invalid`. No production endpoint is selected or contacted.
The body is exactly eight random nonzero nonce bytes, carried only in the body,
never the URL, diagnostics, journal or report. This is not authentication or a
credential. The fixture responds HTTP/1.1 200 with that exact eight-byte body.
Both directions declare `Content-Type: application/octet-stream`,
`Content-Length: 8`, `Cache-Control: no-store` and `Connection: close`.
No cookies, client credentials, redirects or content compression are supported.

The response parser caps headers at 4096 bytes and 24 fields, rejects duplicate
critical headers, obsolete folding, control/non-ASCII header data, any transfer
encoding, content encoding, Set-Cookie or Location, wrong length/type/cache
policy, wrong nonce, non-200 status, truncation and already-observed extra data.
It handles arbitrary fragmentation including binary body bytes containing CR/LF
and NUL. Failure cannot be repaired by subsequently feeding a valid response.
It returns only a closed enum, never response/header strings.

This reserved-host builder is not a public arbitrary-URL service API. Production
admission needs a separately agreed fixed endpoint contract, privacy policy,
bootstrap/rotation policy and qualification. LikeWeb/server work is out of scope.

## TLS candidate boundary

Use the service-owned exclusive TCP socket, arm SDK correlation before any TLS
I/O, retain the descriptor through proof reading and disarm before close. TLS
record counts can include handshake bytes; they must not be reported as HTTP
payload byte counts. Verified HTTP alone is insufficient: current SDK path,
instance/epoch and deadline/freshness facts remain mandatory.

The transport must authenticate the peer name, certificate chain and leaf time
validity using Windows TLS, forbid implicit client credentials, and refuse
revocation-unknown/revoked certificates rather than ignoring errors. Certificate
network retrieval must not create hidden uncorrelated fallback traffic. Crypto
and I/O remain outside the SDK lifetime mutex. TLS, HTTP, deadline, cancellation
and path outcomes stay separate. No plaintext HTTP fallback or validation bypass.

The modern Windows credential API is available from Windows 10 1809; the first
desktop acceptance baseline remains Windows 10 22H2. Using that API would not
qualify earlier Windows builds or Windows 11. TLS 1.2/1.3 support and cancellation
need actual protocol-specific evidence. Fixture roots may be installed/removed
only inside disposable CI, never on the owner's device or in an owner package.

Primary Microsoft references inspected 2026-11-17:

- [Schannel credentials and Windows version boundary](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-sch_credentials)
- [TLS protocol restrictions](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-tls_parameters)
- [Client context and server-name validation](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel)
- [Incomplete and extra TLS buffers](https://learn.microsoft.com/en-us/windows/win32/secauthn/extra-buffers-returned-by-schannel)
- [TLS decryption and shutdown/post-handshake handling](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel)

DNS remains a distinct probe/design boundary: successful HTTPS, including a
response from a dedicated fixture, does not establish the Windows DNS resolver
path or Internet DNS health.


The initial transport candidate restricts negotiation to TLS 1.2, uses fresh
Schannel credentials with automatic validation, no default client certificates,
strong crypto and cache-only chain/revocation retrieval. Unknown/offline
revocation errors are not ignored. It separately checks the returned leaf's time
validity, supports incomplete/extra encrypted input, caps total wire data and
crypto iterations, and rejects renegotiation. Each context is used on one thread;
errors make the channel unusable. No trust store is mutated by the library.
The 13-case loopback matrix qualifies these focused TLS 1.2/HTTP and certificate
controls only, without SDK/TUN or production trust/revocation bootstrap.
TLS 1.3, graceful TLS shutdown, OS crypto-call cancellation/bounds and production
certificate/revocation behavior still require dedicated work/qualification.
The module is not linked into the shipped service/UI and has no public IPC entry.

An initial real Server 2022 test accepted a leaf with unavailable revocation
information despite Schannel flags. The implementation now additionally calls
[CertGetCertificateChain](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain)
against local-machine trust with server-auth usage, cache-only chain/revocation
lookup and automatic root update disabled. It accepts only zero chain errors;
unknown/offline/revoked status refuses HTTP. Automatic Schannel validation remains
enabled. The production policy for obtaining fresh revocation data is still open.

The zero-error chain gate alone also accepted the same self-issued but
non-self-signed missing-CRL control (44167719737). Each non-root certificate now
also requires explicit cache-only
[CertVerifyRevocation](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifyrevocation)
success with its verified issuer and the read-only local-machine CA store.
A separate CI-only CA/CRL pair tests valid and actually revoked issued leaves.
