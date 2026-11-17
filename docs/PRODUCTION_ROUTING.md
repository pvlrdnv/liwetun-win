# Production routing configuration and bounded traffic evidence

Production means both `LIWETUN_TEST_NO_GLOBAL_ROUTES` and
`LIWETUN_TEST_TUN_NETWORK` are OFF. It does not mean release qualification.
The opt-in `windows-service.yml` production lifecycle uses only a synthetic,
closed loopback endpoint and an independent armed deadline on a disposable VM.
No owner-device or production-server experiment is involved.

An actual defect was found when the first production-branch observation showed
only DNS/local/multicast routes. The pinned SDK documentation describes default
route arrays, but its [TOML parser](https://github.com/TrustTunnel/TrustTunnelClient/blob/a1ce3f9d2572e8c3fd6c31e6c31881d307131f40/trusttunnel/src/config.cpp#L389)
leaves omitted arrays empty. Its [listener](https://github.com/TrustTunnel/TrustTunnelClient/blob/a1ce3f9d2572e8c3fd6c31e6c31881d307131f40/trusttunnel/src/client.cpp#L357)
passes those arrays directly rather than copying the OS recommended defaults.
The service now supplies `0.0.0.0/0` and `2000::/3` explicitly, plus the pinned
SDK's recommended private/link-local/multicast IPv4 exclusions. Endpoint address
exclusions are additionally managed by the SDK. Local/private network exceptions
are an explicit policy, not a complete firewall/kill-switch implementation.
Existing bounded CI branches and core TLS/authentication remain unchanged.

The corrected route lifecycle **PASS** on `0c211b1`,
[run 43856182784](https://github.com/pvlrdnv/liwetun-win/actions/runs/43856182784):
18 service checks; own-adapter IPv4/IPv6 CIDRs covered fixed address samples,
adapter DNS was observed and all route/DNS/adapter snapshots returned to baseline.
The independent watchdog was armed but did not need intervention. The initial
three-second native observation was extended to six seconds. Only prefix-length
categories and booleans are retained, without interface identifiers/addresses,
usernames, endpoint credentials or core logs. [Evidence](evidence/general-routes-0c211b1.json).

The pinned Windows SDK's DNS setup also creates a WFP dynamic session. Source
inspection shows DNS rules use that session and its destructor closes the WFP
engine. A read-only CI-only probe now counts only the SDK-labelled sessions
belonging to the authenticated own service PID; other session names, SIDs,
usernames and IDs are not exported. The stricter lifecycle fixture requires
dynamic sessions to appear and return to baseline after SDK stop while the
service itself remains running. This additional check **PASS** on `fc60eb3`,
[run 43858170850](https://github.com/pvlrdnv/liwetun-win/actions/runs/43858170850):
SDK-owned dynamic sessions appeared, returned to baseline after SDK stop, and
the complete IPv4/IPv6 route/DNS restoration check passed without watchdog
intervention. [Evidence](evidence/general-wfp-fc60eb3.json). This is session
lifecycle evidence under the Windows dynamic-session contract, not an independent
enumeration of individual filters or an effective DNS-leak test.
[Windows dynamic-session semantics](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0).

The opt-in network production case uses the official endpoint's SOCKS5 forwarder
to separate server egress from client routes on the same disposable host. Its
fixed synthetic account and exact HTTPS/DNS destination allowlist are mandatory.
Only server egress binds the physical interface; client sockets remain unbound
and no test host routes are added. TCP control binds loopback; the UDP relay
binds the same-host private address, accepting only loopback or that exact host.
No payloads, DNS names or raw endpoint/core output are retained.

Run [43861649225](https://github.com/pvlrdnv/liwetun-win/actions/runs/43861649225)
passed ordinary HTTPS with normal TLS and TUN-selected source, but DNS return
failed despite a synthetic answer sent by the forwarder. Overall result **FAIL**;
all route/DNS/adapter and WFP session baselines restored without watchdog action.
Further Windows runs confirmed the private-address relay alone does not fix
DNS. Connected UDP and edge-triggered epoll boundary preflights passed before
and during SDK operation, while client DNS still timed out. H3 ordinary HTTPS
also passed on run 43875792983. These are partial observations, overall failures.
The report distinguishes timeout from a received invalid reply using closed
booleans and a numeric OS error only. Proc-table zero matches in WSL1 are unknown,
not proof of an empty endpoint queue.

The next pending fixture experiment places the endpoint's authenticated UDP
relay inside WSL1. HTTPS chains to the Windows physically bound exit; the only
direct UDP destination is the private same-host synthetic DNS fixture. Its
ordinary route must select the original physical interface, verified after TUN
start. Client probes still require TUN sources and actual HTTPS/DNS replies.
The endpoint binary and application routing are unchanged. Local five protocol
checks passed, including chained authenticated TCP. The two-source-flow control
isolated an idle-socket blocking defect in the endpoint's SOCKS5 path. A pinned
minimal diagnostic-server source fix passed that control; see
[endpoint diagnosis](ENDPOINT_UDP_FIXTURE.md). No application SDK or production
server changed.

Ordinary IPv4 positive cases **PASS** on `fe9ba3d` with the repaired diagnostic
endpoint: [H2 run 43881857485](https://github.com/pvlrdnv/liwetun-win/actions/runs/43881857485),
[H3 run 43881865435](https://github.com/pvlrdnv/liwetun-win/actions/runs/43881865435).
Unbound sockets selected TUN sources; normal-TLS HTTPS and exact DNS responses
arrived, with 82 DNS transport bytes on the selected protocol and zero on the
others. Two-flow endpoint preflight passed before routing; full route/DNS/adapter
and WFP session restoration passed without watchdog intervention. No test host
routes; both app network-test flags OFF. H3 has no H2 listener, so fallback cannot
pass. Per-synthetic-question relay counters are added for a stronger rerun;
unrelated runner DNS cannot satisfy those counters. That stronger rerun **PASS**
on `4653876`: [H2](evidence/production-traffic-43882488976.json),
[H3](evidence/production-traffic-43882496493.json). Each recorded exactly one
synthetic request/reply, 82 DNS bytes and complete network/WFP restoration.

The optional `production_termination=lease-death` fault closes no stdin and sends
no Stop command. It first confirms the exact owned lease-client process is live,
force-terminates it, requires a nonzero exit, and then observes the service's own
cleanup under the independent deadline. This native CI lease process is not an
installed visible GUI. That ordinary H2 case **PASS** on `b8d84cf`,
[run 43883087034](https://github.com/pvlrdnv/liwetun-win/actions/runs/43883087034),
[evidence](evidence/production-lease-death-43883087034.json): actual successful
traffic first, forced lease-client exit, then complete network/WFP restoration
without watchdog intervention.

The pending `production_termination=service-crash` case retains the authenticated,
signed System-service process before SDK start. Its CI-only `--wfp-watch` counts
only that retained identity's SDK sessions before/during/after the crash; it
does not accept a PID or reattribute observations to a restarted service. Only
query/synchronize access is used by the observer. Crash injection separately
verifies and retains the exact run-owned SCM/process image before terminating it.
Native Windows compilation and that crash case **PASS** on `383dfcb`,
[run 43883716213](https://github.com/pvlrdnv/liwetun-win/actions/runs/43883716213),
[evidence](evidence/production-service-crash-43883716213.json). Successful actual
traffic preceded verified original-process termination; its dynamic WFP session
returned to baseline and all network state restored without watchdog action.

Startup negatives use `production_profile=wrong-auth` or `wrong-ca`,
only H2 with normal Stop. They require a healthy endpoint wire preflight,
typed CoreFailure/Error, zero endpoint data/TCP egress and complete cleanup.
After refusal they make no ordinary direct HTTPS request and do not claim a
kill switch. Registry credential rejection can precede SOCKS5 authentication;
no SOCKS rejection count is invented as a server observation.
Both **PASS** on `e096b0d`: [wrong auth](evidence/production-refusal-43884507628.json),
[wrong CA](evidence/production-refusal-43884514904.json). They observed terminal
CoreFailure/Error and absent adapter, zero endpoint payload/TCP egress, and full
network/WFP restoration without watchdog action.

The [six-case receipt](evidence/production-basic-matrix.json) links both ordinary
positive transports, H2 lease death/service crash and both H2 startup refusals.
It deliberately keeps complete fault/IPv6/desktop/release qualification false.

Pending client IPv6 experiment: `production_family=synthetic-ipv6` sets the
generated synthetic profile's IPv6 capability and uses an unbound IPv6 HTTPS
socket plus a fixed IPv6 UDP echo, both requiring TUN-selected sources/routes.
The only synthetic destination is documentation address `2001:db8:1::1`.
The destination-allowlisted fixture translates HTTPS to the physically bound
IPv4 public origin and UDP to the private same-host fixed echo. Returned SOCKS5
UDP headers preserve the original IPv6 metadata; exact echo payload/relay counts
and transport bytes must agree. No client host routes, forced client interface
or TLS bypass. Existing IPv4 DNS proof remains separate and explicit.
Seven local protocol checks PASS, including IPv6 wire-header preservation,
fixed-destination mapping and denial of unrelated destinations/payloads. No
owner-machine IPv6 routes were changed. Native Windows proof is pending; even a
pass establishes client IPv6 packet handling, not native server IPv6 egress,
IPv6 DNS/leak policy or desktop readiness.
That client packet experiment **PASS** on `4ffe672`,
[H2 evidence](evidence/synthetic-ipv6-43891393542.json) and
[H3 evidence](evidence/synthetic-ipv6-43891403062.json): unbound IPv6 HTTPS and UDP
sources/routes selected TUN, one exact IPv6 echo request/reply and 54 transport
bytes, existing IPv4 DNS proof and complete network/WFP restoration without the
watchdog. The reports retain native IPv6 egress qualification false.
The next strengthened IPv6 case additionally requires an exact synthetic AAAA
answer through the SDK's ordinary IPv4 DNS path, TUN source, distinct AAAA
request/reply markers and at least 94 selected-transport bytes. The pinned SDK
default adapter DNS list is IPv4; an AAAA record does not imply IPv6 DNS wire
transport. Local DNS packet checks passed (49-byte A / 61-byte AAAA replies);
actual Windows AAAA qualification is pending.
That strengthened case **PASS** on `a430ac9`:
[H2 evidence](evidence/synthetic-aaaa-43900021100.json),
[H3 evidence](evidence/synthetic-aaaa-43900031136.json). Each recorded one exact
AAAA request/reply, 94 selected-transport bytes, working IPv6 TCP/UDP, and complete
network/WFP restoration without watchdog intervention. DNS wire transport remains
IPv4; native IPv6 Internet egress and desktop qualification stay open.

Remaining gates: wider ordinary-mode fault matrix, effective DNS leak prevention,
native IPv6 egress / DNS wire policy, crash/network-
change/suspend recovery and installed Windows 10/11 desktop acceptance. These
route/sample observations cannot establish any of those. Existing H2/H3/DNS
payload acceptance uses bounded, explicitly interface-bound sockets and is
documented separately in TUN_NETWORK_ACCEPTANCE.md. No fabricated connectivity
or release-ready state is derived from this negative lifecycle test.


## Endpoint restart recovery case — prepared, Windows result pending

Select `production_termination=endpoint-restart`, valid IPv4 profile and H2 or H3.
After ordinary HTTPS/DNS passes, the fixture terminates only its retained Popen
endpoint child, waits two seconds and launches the same pinned binary/config.
The original authenticated client lease and SDK stay alive; no second Start RPC.
Up to five attempts starting within a 75-second observation window require TUN source addresses, HTTPS payload, exact synthetic
DNS marker growth, at least 82 DNS bytes in the chosen protocol and no growth in
another protocol. Stop must restore the baseline network and WFP sessions without
watchdog action. The independent guard allows 120 seconds for this case only.
This tests a diagnostic endpoint interruption, not desktop sleep or a physical
interface change. There are no product/service recovery changes or production
connections in this experiment. Four observation guards and all 15 Python fixture
tests pass locally; initial H2 qualification passed (44029340084). H3 short-window run 44029344825
failed recovery evidence: HTTPS returned on the third observation, DNS did not;
Stop still restored routes/DNS/adapter/WFP without watchdog action. The original
report remains archived. The follow-up adds post-probe service state, elapsed
time and a longer bounded observation window; no SDK/product recovery changes.
Follow-up Windows execution remains pending.
