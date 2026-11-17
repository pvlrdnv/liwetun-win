# Bounded subscription HTTPS transport

Status: HTTPS transport passed Windows CI; refresh UI and startup/periodic
scheduling are implemented, with their Windows integration qualification pending. No LikeWeb route or production fetch is
assumed. The v1 subscription contract remains a client-side proposal.

`HttpSubscriptionTransport` accepts only an explicitly imported HTTPS source,
rejects TT QR wrappers/user-info/fragments, resolves once and validates the full
DNS answer before connecting. Only at most four distinct checked numeric addresses
may be attempted. `SecureSocket.secure` retains the original hostname for SNI and
certificate validation without a second lookup. TLS failures do not try another
address. Normal OS routing is preserved; there is no physical-interface bind,
route/DNS/driver/service or trust-store change.

The origin policy is a conservative subset of public unicast, not a claim that a
prefix is reachable. Reject loopback, private/shared/link-local, multicast,
reserved, documentation and transition/special-purpose ranges; reject a mixed
public/private DNS answer. IPv6 uses the global-unicast range with additional
special/documentation exclusions. NAT64 / mapped / 6to4 subscription origins and
some special globally reachable allocations are deliberately unsupported in
this initial policy. This is separate from synthetic IPv6 TUN qualification.
The classifications were reviewed 2026-11-16 against the IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) registries.

Each request has one 15-second absolute DNS/connect/TLS/header/body deadline,
4-second per-address TCP establishment bounds and a 1 MiB body limit. Require
HTTP 200, JSON/UTF-8 and identity content encoding. No redirects, cookies, added
HTTP credentials, compression, TLS exceptions or request-body forwarding.
401/403 or malformed/failed responses are not authoritative revocations and
must preserve the last accepted cache. Only the validated snapshot contract may
change access. The pinned Dart 3.10.9 HTTP parser separately bounds headers at
1 MiB; the real oversized-header test confirms that dependency behavior.

A fresh HttpClient is used for each request and closed on every outcome.
Explicit environment proxy configuration is reported as unsupported before DNS;
it is never silently bypassed. DIRECT here is the HTTP proxy decision, not a
bypass of the operating system/corporate tunnel. A proxy-aware pinned-origin
implementation remains separate work. HTTP timeline profiling is disabled before
request creation, avoiding debug retention of credential-bearing URLs; TLS key
logging and authentication callbacks remain unset. Failures expose only a closed
code, not URL/address/exception/body text. Early task error observers prevent
unhandled TLS errors before HttpClient subscribes to its socket future.

Close cancels active requests, socket tasks, pending DNS continuations and body
observation. No late DNS completion starts a connection. Per-request cancellation
state is removed after completion rather than accumulating global listeners.

Transport Windows CI passed 204 Dart + 6 Rust + 4 desktop tests. Current local
analyze + all 216 Dart tests PASS, including 6 actual loopback TLS/HTTP
cases: hostname verification, unknown CA refusal, real JSON/Host/no credentials,
redirect refusal and body/header bounds. Synthetic certificates are generated
fresh, loaded only into explicit fixture contexts, never installed as OS roots
or copied into GUI artifacts. The refresh integration adds an actual HTTPS/UI/DPAPI revoke case for Windows CI.
Installed Windows 10/11 desktop acceptance remains separate.


## Refresh scheduling

The controller enables automatic refresh after protected storage initialization.
Explicitly imported subscription sources refresh at startup, then every 15 minutes
plus 0–120 seconds jitter. A usable profile's earlier deadline moves the next
refresh to 30 seconds before expiry, with a minimum 30-second delay. Failures use
30/60/120/240/480/900 seconds plus 0–30 seconds jitter. Only one source refreshes
at a time, with a one-second gap; manual retries have a five-second cooldown.
Manual controls report a closed status for each source, alongside cache eligibility
and the last accepted update time. Replays use the normal cadence but never
renew timestamps or deadlines. Requests cancel on controller disposal.
