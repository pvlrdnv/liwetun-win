# Bounded subscription HTTPS transport

Status: implemented and tested as an independent client component. Refresh UI /
startup scheduling are not wired yet. No LikeWeb route or production fetch is
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

Local analyze + all 204 Dart tests PASS, including 6 actual loopback TLS/HTTP
cases: hostname verification, unknown CA refusal, real JSON/Host/no credentials,
redirect refusal and body/header bounds. Synthetic certificates are generated
fresh, loaded only into explicit fixture contexts, never installed as OS roots
or copied into GUI artifacts. Windows CI is prepared to run those same tests;
Windows execution and installed desktop acceptance are still separate.
