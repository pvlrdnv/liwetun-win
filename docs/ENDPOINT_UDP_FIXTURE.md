# Endpoint SOCKS5 UDP isolation

The ordinary-routing fixture exposed a UDP multi-flow failure in the official
endpoint's SOCKS5 path. It reproduces on native Linux without Windows, the SDK,
TUN, route changes or production access. This is a test-server forwarding path;
it is not evidence of a defect in the application's UDP adapter or a requirement
to change LikeWeb servers.

The official v1.1.0 binary is pinned by SHA256
`91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7`.
The fixed synthetic control verifies profile-scoped TLS, authenticates HTTP/1
CONNECT `_udp2`, sends the documented UDP frames, and requires exact source /
destination metadata and the synthetic DNS answer. It retains only booleans,
aggregate counts, completed-flow count and numeric OS errors.

| Native Ubuntu control | Result |
| --- | --- |
| One UDP source port on one TLS stream, run 43879172234 | PASS, exact reply |
| Two source ports on the same TLS stream, run 43879797921 | FAIL, first reply received; second timed out despite both answers sent |
| Hash-checked diagnostic source fix, run 43880327333 | PASS, both exact replies |

[Single-flow evidence](evidence/endpoint-udp-single-43879172234.json),
[two-flow failure](evidence/endpoint-udp-two-43879797921-failed.json).
The single-flow control also passed in WSL1 before the SDK started, while the
subsequent ordinary-mode SDK DNS case failed:
[run 43878904033 evidence](evidence/production-traffic-43878904033-failed.json).
Windows boundary UDP/epoll controls passed both before and during SDK operation.
Moving the relay from Windows to WSL1 did not resolve the failure.

The source hypothesis is stale readiness followed by an awaited receive from
an idle socket, blocking other associations. The
[SOCKS5 forwarder](https://github.com/TrustTunnel/TrustTunnel/blob/fab5b8353a19332f935fa30869307d37d4a898d1/lib/src/socks5_forwarder.rs)
awaits receive after readiness; the
[direct UDP forwarder](https://github.com/TrustTunnel/TrustTunnel/blob/fab5b8353a19332f935fa30869307d37d4a898d1/lib/src/udp_forwarder.rs)
uses nonblocking receive and returns to polling on WouldBlock.
The two-flow reproduction plus passing nonblocking source-fix comparison
confirms this cause in the diagnostic endpoint path.

`tools/service/endpoint_socks5.patch` changes only the SOCKS5 receive helper and
its caller to use nonblocking receive / WouldBlock polling. The exact source
commit/archive, patch and before/after file digests are recorded in
`tools/service/endpoint-source.json`. CI builds with Rust 1.95.0 and Cargo.lock;
the result is explicitly a modified diagnostic endpoint, not an upstream
release. A successful two-flow check is required before its artifact is uploaded.
Windows consumption additionally requires a reviewed run/commit/binary receipt.
That build and two-flow check passed on `646618e`,
[run 43880327333](https://github.com/pvlrdnv/liwetun-win/actions/runs/43880327333),
[safe evidence](evidence/endpoint-udp-fixed-43880327333.json).
`tools/service/endpoint-runtime.json` pins that run, workflow commit and the
downloaded binary digest. Windows ordinary-traffic reruns passed the same two-flow
preflight, then unbound HTTPS/DNS over H2 and H3 with exact 82-byte DNS exchanges:
[H2](evidence/production-traffic-43881857485.json),
[H3](evidence/production-traffic-43881865435.json).
All route/DNS/adapter/WFP baselines restored without watchdog action. These are
single positive CI cases, not desktop or full failure-matrix qualification.
The original released
endpoint remains available to the default bounded workflow and is not relabelled
as fixed. [CI source notice](../third_party/endpoint/README.md).

No application SDK, production endpoint or owner-machine configuration is
modified by this work. Successful fixture repair alone will not qualify
ordinary Windows DNS, IPv6, crash recovery, Windows 10/11 desktops or release.
## Separate shutdown-completion candidate

Fresh2 H3 epoch control [44304621614](evidence/fresh2-https-44304621614.json)
timed out with unchanged SDK epoch after the fixture reported graceful exit.
No stale proof/HTTP response was qualified. This does not establish the cause
of the missing state transition; the original failed result stays preserved.

Pinned endpoint `endpoint/src/main.rs` selects between listener completion and
the SIGINT task, which submits shutdown and waits for completion guards. The
listener can finish on the same shutdown notification and win that outer select,
followed immediately by `std::process::exit(0)`. Active connection shutdown may
therefore be cut short. This is a source hypothesis to test against the exact
original diagnostic binary behavior, not a production change.

The separate opt-in `shutdown_completion_fix` requires both existing diagnostic
profiles. It retains an independent shutdown handle and waits for its completion
after the original select has released all competing futures. Waiting is bounded
to two seconds; timeout exits nonzero. Input/output hashes and anchors are pinned
in `tools/service/endpoint-shutdown-inputs.json`. Existing UDP/reader candidate
binary pins remain immutable. Build success alone cannot qualify QUIC shutdown
or SDK epoch invalidation; actual controlled Windows comparisons remain required.
