# HTTPS probe candidate contract

Status: HTTP/socket contracts and Schannel preflight PASS (44165060837).
Real loopback TLS 1.2 matrix **16 cases PASS** (44169309801), with explicit
per-certificate revocation verification. [Closed evidence](evidence/health-tls-44169309801.json).
Service-owned synthetic HTTPS **16 focused CI cases PASS**, eight modes on each
of H2/H3. [Aggregate evidence](evidence/owned-https-requalification.json) includes
positive, wrong nonce, certificate refusal, deadline/cancel, actual migration,
actual epoch change and local bypass. No public application health capability
is enabled.

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
The 16-case loopback matrix qualifies these focused TLS 1.2/HTTP and certificate
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

The expanded matrix also refuses a required-client-certificate peer (which may
produce a generic fatal-alert outcome), a TLS-1.3-only peer and a truncated HTTP
body. Refusing TLS 1.3 is an intentional boundary, not TLS 1.3 qualification.
Only the fixture knows the server configuration; a generic TLS rejection is not
exported as a precise diagnosis of the peer's cause.

## Service-owned CI integration

`LIWETUN_TEST_OWNED_HTTPS` defaults OFF, requires the owned socket/attachment
profiles, and is excluded by ordinary package guards together with the six prior
test flags. The worker arms the fresh exclusive socket before TLS, validates the
reserved nonce reply, reads SDK proof on the retained descriptor/current epoch
and requires endpoint TX/RX covering this socket's actual wire totals. It disarms
before close and clears qualification on Stop or changed epoch.

The positive H2/H3 cases exactly matched 497 TX / 1703 RX to the SDK counters,
with CA/CRL/name verification, current epoch, disarm and restoration.
[Evidence](evidence/owned-https-positive-44173333723.json). These include encrypted
handshake/record bytes and are not HTTP payload counts. The extra typed HTTPS
receipt carries no name, address, token, socket or interface identifier.

This remains one startup request in disposable CI. It has no periodic freshness
controller, public service IPC, production endpoint or GUI admission. DNS and
Internet-wide health remain unproved.

The completed service matrix additionally confirms that verified HTTPS after
actual migration (flag 33, null proof counts) or local delivery outside the SDK
(flag 3, zero endpoint bytes) remains unqualified. Actual epoch change discards
prior proof. Every case requires disarm, independent receiver observations,
network/WFP restoration and exact fixture trust cleanup. H3 explicitly uses the
diagnostic reader-wakeup fixture; SDK recovery bypass selection remains unproved.

[Adapter ownership](ADAPTER_OWNERSHIP.md), production endpoint/revocation policy,
independent DNS correlation, periodic freshness, public IPC/UI admission, trusted
distribution and separate desktop acceptance remain open. The focused SDK
manifest records CI qualification only and remains excluded from normal packages.

CI HTTPS receipt schema 2 adds a closed `initialization_result` and nullable
`tls_result`. An unattempted TLS exchange must remain null with zero wire bytes
and no request/verification/qualification claims. It must not inherit the old
schema-1 default CredentialsUnavailable value merely because startup exited
before creating a socket. Original historical reports retain their actual schema.

Initialization outcomes: 0 unknown; 1 Winsock unavailable; 2 cancelled; 3 core
unavailable; 4 instance unavailable; 5 service state not ready; 6 traffic read
unavailable; 7 traffic not ready; 8 attachment read unavailable; 9 attachment not
ready; 10 epoch mismatch; 11 entropy unavailable; 12 empty token; 13 passed.
Only passed preflight may accompany attempted TLS. No OS message, address,
identifier or secret is added. This observation change does not make a failed
startup healthy or establish its cause without a matching typed result.

CI-owned admission now observes asynchronous readiness for at most five seconds,
before any socket/arm/TLS request. Only StateNotReady, TrafficNotReady,
AttachmentNotReady and EpochMismatch are re-observed; each successful read must
still match the exact current ready counter/attachment snapshot. The lifetime
lock is released before each 20 ms pause. Stop/cancellation, terminal API faults,
clock reversal/freeze or a late successful observation refuse admission. This
is not an HTTP/TLS retry or health qualification by SDK process start. Native
synthetic policy and actual Windows regressions are separate evidence.
