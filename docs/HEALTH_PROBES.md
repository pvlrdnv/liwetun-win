# Tunnel health: implementation boundary and next native slice

Status: application DNS/HTTPS health probes remain **unavailable**. Optional native
aggregate counters are implemented and qualified in a separate SDK candidate;
the service, GUI and summary v3 preserve unsupported/stale observations as
unknown. These counters do not prove Internet/DNS or selected-probe traversal.
The UI continues to distinguish TunnelReady from verified Internet. Do not wire
a generic HTTPS success into Connected.

## Findings from the pinned source and real interruption cases

SDK source: TrustTunnelClient a1ce3f9d2572e8c3fd6c31e6c31881d307131f40.
`platform/windows/include/trusttunnel/trusttunnel.h` exposes state and opaque
connection-information callbacks, not a public aggregate traffic snapshot.
`trusttunnel/src/client.cpp::vpn_handler` discards endpoint/tunnel statistics
notifications. `VpnCallbacks` does not forward those statistics. Copying an
opaque callback pointer into a guessed C++ layout is not an acceptable bridge.

The existing LiWeTun privacy preparation deliberately disables per-destination
connection-information generation and raw logger sinks. Preserve that policy.
A future native diagnostic export must aggregate inside the pinned SDK before
crossing the ABI, without domain/address/app/connection identifiers, logs or
configuration. It requires a new explicit SDK artifact and requalification;
neither current runtime receipt should be silently edited to admit it.

The core's `core/include/vpn/vpn.h` defines a three-second default postponement
window. `core/src/vpn_fsm.cpp::postponement_window_timer_cb` rejects postponed
connections with kill switch on and otherwise force-bypasses them. The current
service explicitly configures kill switch off. An ordinary socket sourced from
the TUN can therefore yield HTTPS during recovery without selected-endpoint
traffic proof. A TUN source address alone is insufficient to label the end-to-end
path healthy. This source behavior also explains why successful HTTPS without
endpoint bytes must remain unqualified; it is not proof of a particular bypass
flow without flow-correlated evidence.

Actual H3 interruption receipts illustrate the distinction:

- 44029344825: short observation window did not establish recovery; cleanup passed.
- 44030366734: early HTTPS succeeded while endpoint bytes/DNS did not prove the
  path. Only attempt five at 44,812 ms had HTTPS, exact DNS markers, 82 DNS H3
  bytes and a post-probe ready state. Stop restored the network and WFP.
- 44030999383: independent confirmation at 43,108 ms, with the same proof and
  cleanup requirements. No SDK/service recovery policy change.

These are same-host disposable Server 2022 fixtures. They do not establish a
service-level recovery deadline, desktop sleep or Wi-Fi/Ethernet acceptance.

## Required native contract before enabling the UI

1. A read-only, versioned, fixed-size aggregate snapshot, tied to a connection
   epoch and monotonic sample time. Explicit validity and observation-gap flags;
   saturating counters must invalidate rather than wrap. A new Start/recovery or
   reset must never subtract another epoch's counters.
2. TX/RX totals from actual tunnel statistics, separately from physical adapter
   totals and bypassed traffic. No event does not imply an observed zero. The
   existing `classifyTraffic` remains counter evidence only: idle, flowing,
   outgoing-without-reply, or unknown. None proves DNS or server availability.
3. Probe-specific path evidence beyond an adapter alias/source address. A future
   SDK bridge may reduce correlation of only the application's owned probe to a
   closed tunneled/bypassed/unknown result in memory. It must not restore general
   browsing instrumentation. Unknown, bypass, epoch change or missing correlation
   cannot yield verified-tunnel success.
4. Bounded DNS and HTTPS probes to a dedicated safe endpoint with no personal
   URI, credentials, cookies, redirects or raw response logging. No endpoint is
   chosen or contacted by the application in this slice. A production endpoint
   needs an explicit contract; LikeWeb/server changes remain outside this repo.
5. Serialize probes, cap their deadlines/frequency and cancel on Stop/disposal,
   network change, sleep or epoch change. Keep DNS, TLS, timeout, endpoint and path
   outcomes separate. One failed endpoint cannot establish server blocking or a
   general Internet outage. Direct checks, if later added, are explicit and must
   never silently bypass a kill switch.
6. Return only closed typed facts through authenticated service IPC and Flutter;
   attach monotonic age/attempt/epoch and unknown states to the local report.
   Enable Connected only with fresh successful evidence for the current epoch.

## Qualification sequence

First qualify the new SDK bridge with synthetic fixtures, missing/reset/overflow
and concurrent Stop cases. Then validate actual probes on disposable Windows CI:
selected transport, direct-bypass negative control, DNS failure, one failed
endpoint, recovery, idle and outgoing-without-reply. Preserve normal stop/crash
route/DNS/adapter/WFP checks. Only after that wire application states and perform
separate installed Windows 10 and Windows 11 desktop acceptance. No experiment
runs against the owner's corporate tunnel or production nodes.


## Aggregate instrumentation candidate — Windows CI qualified

The opt-in SDK workflow `traffic_metrics=true` requires `source_pins=true` and
builds version `1.1.12-liwetun.traffic1`. It applies the unchanged privacy profile,
then a separately guarded aggregate patch. Nine canonical-LF input digests plus
added-header digests are recorded in `native/sdk/traffic-inputs.json`; the output
`traffic-profile.json` records actual modified bytes, patcher and manifest hashes.
Current runtime receipts are not changed or automatically promoted.

`ConnectionStatisticsMonitor` gains an optional delta observer invoked for each
positive update to an already registered endpoint-routed client flow. Existing
thresholded per-connection notifications stay unchanged/ignored. This avoids the
100 KiB/100 ms threshold and the upstream close condition requiring both TX and
RX before residual reporting. The aggregate event contains only two byte deltas;
no per-connection identifier is copied or exported. Bypassed flows are not
registered by the existing TUN logic. Internal DNS listener traffic is not a
complete part of these client-flow totals, so they cannot establish DNS health.

The snapshot is 64 bytes, ABI v1, with signed-safe totals, monotonic last TX/RX
instants, core state and an epoch that changes on state transitions. Counters
remain per SDK instance; the service must add an instance token before comparing
snapshots across restarts. Unsupported/missing, overflow, clock regression,
invalid state and callback gap cannot become valid zero metrics. A callback-side
failure is latched and contained; it cannot escape into the routing callback.

Portable tests cover tiny one-sided deltas, absent last-receive time, state-epoch
changes, new-instance reset, atomic overflow rejection, clock regression,
callback failure and four concurrent update/read threads. Windows compilation, those counter tests, the full SDK and null-read export
checks passed in 44038398682; the separate runtime-traffic.json pins actual bytes.
Actual pinned-source preparation and four Python guards also passed locally.
The optional service read command / GUI observations passed Windows compilation
and tests: service 44057085561, GUI 44057954554 (227 Dart + 6 Rust + 6 desktop
cases). H2/H3 actual counter progress and concurrent teardown passed with ten
network/refusal/fault/recovery/synthetic-IPv6 cases; see sdk-traffic-requalification.
All network/WFP baselines restored without watchdog. GUI admission is tested on
an unsigned workspace; a live signed GUI displaying real tunnel counters is a
separate acceptance gate. No Internet/DNS Connected state is enabled.


## Service and report integration

The optional read-only IPC command 5 adds a 104-byte frame: the unchanged 32-byte
base reply, a per-instance random signed-safe token, and the 64-byte snapshot.
Existing command frames and protocol version remain unchanged. A 32-byte refusal
from an older service does not cause the client to wait for a nonexistent tail.
The service withdraws the borrowed SDK pointer before teardown and uses a short
mutex around snapshot access; it never holds that lock during slow SDK stop.
Unsupported or invalid data become nullable unknown values at the Flutter boundary.

Controller polls discard late results after Start/Stop changes their operation
epoch. A bounded 20-second rolling counter window clears on instance/state-epoch
changes, resets, monotonic regression or a gap over five seconds; observations
also expire after five wall-clock seconds. It classifies only the measured
registered endpoint-client payload. Bypassed/internal DNS/other adapter traffic
is outside these totals; TX-only is not evidence that the server is blocked.
Summary schema v3 adds those scoped facts; closed event schema stays v1. Current
state labels continue to require a separate Internet check, which is unavailable.
Window resets now retain one closed journal reason (stale sample, sampling gap,
instance/epoch change, clock/counter regression); ordinary polling does not create
per-tick log entries, including while the same reset condition repeats. A coherent
sample pair clears the episode latch. The observed current totals can remain valid while the
rolling classification is unknown and accumulating a new window.


## Tiny TX-only / idle observation fixture — H3 CI PASS, H2 unresolved

An explicit `traffic_pattern=tx-only` case uses a fixed benchmark TCP address
translated only by the diagnostic endpoint's local forwarder to its owned
loopback sink. The physical exit never admits that target. Twenty-one fixed small
frames are sent without a read; the sink must count all frames and send zero
payload bytes. Counter observations must span at least 20 seconds in one instance/
epoch, with no gap over five seconds, positive TX and unchanged RX. A subsequent
20-second window must have unchanged TX/RX. Both windows remain scoped aggregate
counter facts, not DNS/Internet proof. The independent guard permits 120 seconds
for this longer case; ordinary tests retain their original deadlines. Local sink,
allowlist and observation guards pass. Open-flow Windows H3 run 44066619081
passed +672 TX / zero RX followed by 20,998 ms unchanged TX/RX and unchanged sink
receipt. H2 run 44066611999 retained the exact sink receipt but aggregate TX grew
by 720 during sending and 48 during idle, so the complete case failed. Both
restored baseline routes/DNS/adapter/WFP without watchdog. These counters cover
all registered endpoint-client flows, not only the owned test socket. Their
source of additional bytes remains unestablished; the next fixture records only
closed per-window forwarded/denied TCP/UDP totals. No destination/body logs and
no SDK/oracle change. Original post-close failures and follow-up results remain
archived in docs/evidence/tx-only-*.json. This is disposable Server 2022 CI, not
Windows 10/11 desktop acceptance.

H2 diagnostic 44068421270 additionally measured exactly one rejected UDP payload
of 48 bytes in each window. Its sending interval had 672 forwarded owned TCP
bytes and 720 aggregate TX bytes; idle had zero forwarded TCP bytes and 48
aggregate TX bytes. This supports non-fixture activity as the source of the extra
TX, without identifying any process/destination or proving a counter defect.
The complete case still fails strict idle qualification; no SDK/oracle change.
Registered-flow TX observes attempted payload before remote delivery, so even a
positive aggregate cannot serve as a receiver receipt or path-health proof.


## SDK-held TUN attachment prerequisite — Windows build / null ABI PASS

A separate `attached_tun=true` SDK build (requires both `source_pins=true` and
`traffic_metrics=true`) prepares version `1.1.12-liwetun.attached1`. Its source
and header guards are in `native/sdk/attached-tun-inputs.json`; no runtime pin is
promoted. The 40-byte `liwetun_attached_tun_v1` export reads index/LUID through the
actual held Wintun adapter/session, verifies the OS index agrees with the SDK,
and fences the aggregate ready-state epoch and monotonic time before/after.
Missing/unstable observations clear identifiers rather than retaining an old
attachment. The caller must wait for SDK start to return and serialize against
stop/destruction, as for the existing traffic getter. A future service integration
must use its existing short borrowed-core lock, never hold it over SDK stop/join.

Index/LUID are internal socket-selection inputs, excluded from GUI/journal/support
reports. They do not prove that the SDK created an adapter, that routes remain
selected, or that a probe traversed the endpoint. Source inspection shows the
upstream adapter factory can reopen an existing alias and assign addresses before
starting a session. A held handle therefore must not be called exclusive ownership;
a foreign-adapter collision control remains required on disposable CI before
release. Nothing is installed/tested on the owner's corporate device.

Actual pinned-source preparation and five pre-write guard tests pass locally.
The portable contract covers missing attachment, empty identifiers, unsupported
ABI/layout, epoch/state changes, invalid metrics, time/counter regression and
unknown clearing. Windows C++ contract, full SDK build and both read-only null
exports **PASS** (44070100152). All eight emitted source/header hashes match local
preparation, and both downloaded DLL hashes match the build receipt. The separate
`runtime-attached.json` pins these exact bytes, with actual-interface, network,
service/package, desktop and release qualification false. Existing runtime pins
remain unchanged. [Build receipt](evidence/sdk-attached-44070100152.json).
There is no service command, actual attached-interface qualification, DNS/HTTPS
probe or verified-Internet state in this slice.


Additional source constraints for the next consumer (no behavior change here):

- NativeLibsCommon c546b329, `common/wfp_firewall.cpp::allow_self`, installs
  application-image permit rules when creating the SDK's firewall session.
  Socket protection also binds SDK-created endpoint sockets to the physical
  interface. A successful request made inside the service must therefore carry
  explicit owned-flow path proof; neither its process identity nor a permit rule
  proves TUN traversal. These rules alone do not prove that a particular request
  bypassed routing.
- [Wintun 0.14.1 adapter implementation](https://raw.githubusercontent.com/WireGuard/wintun/0.14.1/api/adapter.c)
  contains a duplicate-alias naming path that can rename a conflicting interface.
  Merely replacing the SDK's OpenAdapter call with CreateAdapter is not an
  established coexistence fix. A future ownership change needs controlled
  preexisting-adapter/race acceptance and exact preservation of foreign state.
  No Wintun source is copied, driver altered or owner-machine experiment run.
