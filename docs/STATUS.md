# Development checkpoint — 2026-11-17

## Active — native health prerequisites; aggregate SDK qualified

Work continues in this independent repository. LikeWeb, production and the
owner's corporate tunnel/network/trust configuration remain unchanged. No
owner-installable release has been produced.

Immutable-source SDK candidate **built and requalified on disposable Windows CI**.
Seven recipes pin exact commits / archive checksums, with exact input/output
recipe digests and Conan lock verification. Both archive preparations were
executed before the corrected full build:
[43918219945](https://github.com/pvlrdnv/liwetun-win/actions/runs/43918219945),
[build/source receipt](evidence/sdk-sources-43918219945.json).
`native/sdk/runtime-sources.json` records its actual DLL hashes separately from
the unchanged original `runtime.json`. All 15 packaged notice sets match archived
bodies; 13 explicit source supplements remain. Candidate notice checks and the
unchanged 60-text offline GUI bundle PASS; distribution rights remain open.

[Candidate qualification and all run IDs](evidence/sdk-source-requalification.json):
18 service checks, 14 installer groups, H2/H3 ordinary HTTPS/DNS, service crash,
wrong-auth/CA, lease-client death and H2/H3 synthetic IPv6 TCP/UDP + AAAA PASS.
Every network case restored routes/DNS/adapter/WFP without watchdog action.
Installer includes the exact source-pin manifest, candidate notice receipt and
SDK modification notice; it still uses ephemeral CI signing only.

Two historical lease observations failed before WFP measurement because a
PowerShell network observation failed during adapter removal. Traffic and final
network cleanup had passed. The CI observer now avoids per-interface queries
while removing that interface and treats a failed observation as unknown within
the same bounded 20 attempts. It still requires exact baseline DNS/routes and
adapter absence before/after the snapshot; persistent errors cannot pass.
Four local guard tests PASS. Three independent lease-death confirmations plus
ordinary Stop PASS from `ebdce3c`, with final WFP restoration in each. Original
failed reports remain archived; no application/service/SDK cleanup change.

Current work moves to the missing client subscription path. Added an in-memory
cache codec retaining revision/revocation and original per-profile deadlines,
with strict atomic restoration and 100-profile partial-accumulation bounds.
Added the v2 protected profile envelope, source-scoped derived selection and
atomic controller reconciliation. Native/capacity/parse failures retain the old
list; restore never auto-starts; expired profiles cannot start. Revoke/expiry or
changed active URI queues Stop, including during a pending Start, without blind
resend of an uncertain Stop. The UI displays derived names and stale eligibility.
The protected-cache stage passed Windows CI with 150 Dart + 6 Rust + 4 desktop
channel tests: [43929885246](https://github.com/pvlrdnv/liwetun-win/actions/runs/43929885246).
[Cache receipt](evidence/windows-subscription-cache-b3ffc07.json).

The bounded HTTPS transport then passed Windows CI with **204 Dart + 6 Rust +
4 desktop tests**: [43935446923](https://github.com/pvlrdnv/liwetun-win/actions/runs/43935446923).
Six cases use actual synthetic loopback TLS/HTTP, including hostname/CA refusal,
redirect refusal and header/body bounds. [Receipt](evidence/windows-subscription-tls-1a88a42.json).
No system trust changes or fixture private keys in GUI artifacts.

Manual refresh, per-source status, startup refresh and a serial periodic scheduler
are now wired. Success uses 15 minutes plus jitter, earlier near a usable profile
expiry; failures back off from 30 seconds to 15 minutes plus jitter. Replayed
revisions never extend rights or the last-applied timestamp. Inner cache v2 adds
the application time while retaining v1 decoding. Transport failures preserve
accepted profiles and rights. **216 local Dart tests + analyze PASS**. Windows
qualification **PASS**: [44028234705](https://github.com/pvlrdnv/liwetun-win/actions/runs/44028234705),
216 Dart + 6 Rust + 5 desktop tests, including actual HTTPS → UI → DPAPI → revoke
without starting a tunnel. [Receipt](evidence/windows-subscription-refresh-183bc19.json).
Installer qualification with this GUI **PASS** (44029096943): 14 installer groups,
medium-integrity GUI/service query, rollback/uninstall/cleanup. Temporary CI signing only.

Country chips and combined name/country search now filter derived profiles while
keeping source refresh controls accessible. No-match text differs from an empty
library, and a removed country cannot leave the refreshed list hidden. Local
refresh/filter suite: **11 PASS**; analyze PASS. Windows qualification **PASS**
(44029335268): 217 Dart + 6 Rust + 5 actual desktop tests.
[Transport policy and limits](SUBSCRIPTION_TRANSPORT.md).

No production subscription fetch or LikeWeb API/server change. The v1 export
contract remains a client proposal; an existing general feed is not assumed
compatible. Other original-scope work includes route-bound health evidence,
sleep/network-change recovery, tray desktop qualification, Hysteria2/Xray and release update handling.
A readiness estimate for a basic manual-import TT client must not be presented
as completion of the full handoff. WSL evidence does not establish Windows readiness.

Tray lifecycle is implemented with an explicit close-to-tray switch, existing
icon resource, Open/Exit menu, Explorer re-registration and visible-window
fallback if the tray cannot be registered. The strict protected envelope v3
persists the setting while decoding v1/v2 as false and preserving subscription
revision/selection/deadlines. Default window close still exits. Exit releases
the service lease; hiding retains it. No startup/autoconnect. **220 local Dart
tests + analyze PASS**, including preference/cache failure and restoration.
Native Windows build and sixth capability-gated real tray/DPAPI test **PASS**
(44030695768): 220 Dart + 6 Rust + 6 desktop tests. This initial report did not
record which conditional tray branch ran. Follow-up **PASS** (44031775552)
explicitly reports tray available, real hide/restore and DPAPI preference tested.
The unavailable branch was not executed on that runner. Desktop/menu/DPI and
Explorer-restart acceptance remain open. Installer qualification with this GUI
**PASS** (44032587048): 14 groups, medium GUI/service query, rollback/uninstall
and cleanup; ephemeral signing only.
[Actual tray receipt](evidence/windows-tray-observed-c27c1f8.json),
[installer receipt](evidence/package-tray-44032587048.json). [Behavior and limits](DESKTOP_TRAY.md).

Pinned-source health audit confirms that the Windows SDK wrapper does not expose
aggregate counters and discards its underlying statistics events. The existing
privacy patch also disables per-destination events; do not undo it for a GUI
metric. Recovery can allow bypass with kill switch off, so even a TUN-sourced
HTTPS success cannot prove endpoint traversal. Application health remains
unavailable/unknown until a closed native bridge and probe-specific proof are
qualified. [Findings and required next slice](HEALTH_PROBES.md).

Aggregate traffic instrumentation is implemented as a separate opt-in SDK profile.
The existing upstream per-connection events throttle at 100 KiB / 100 ms and drop
one-sided residuals at close, so the new hook observes each positive byte update
for registered endpoint-routed client flows before that notification threshold.
It exports no address/domain/application/connection identifiers. The original
raw logger and per-destination suppression remain. A fixed 64-byte v1 snapshot
has signed-safe totals, last TX/RX monotonic instants, state epochs and explicit
overflow/clock/state/gap validity. Callback failures cannot escape into routing.

Nine exact canonical-LF baseline file digests and added-header digests are pinned;
all guards/anchors pass before vendor edits. Real pinned-source privacy + traffic
preparation PASS locally; four source-guard tests PASS. Local C++ compilation is
unavailable (no compiler installed). Windows counter/concurrency tests, full SDK
build and read-only ABI export checks **PASS** (44038398682), source 84f9da6.
[Receipt](evidence/sdk-traffic-44038398682.json). The DLL hash is recorded in
`native/sdk/runtime-traffic.json`, separate from both existing runtime pins. This is an opt-in
`traffic_metrics=true, source_pins=true` SDK workflow, with a distinct version and
receipt. Existing runtime/source candidate pins remain unchanged. That initial build
did not establish network/desktop/release qualification; later network evidence follows below.

The service now implements optional read-only command 5 with a 104-byte reply;
existing command replies stay 32 bytes / protocol v1. It borrows the active SDK
pointer under a short mutex, withdraws it before teardown, and adds a signed-safe
random instance token so a restart cannot alias another counter epoch. Unsupported
SDKs and missing/invalid data remain unknown. The GUI worker marshals only closed
numeric/boolean metadata; controller polling drops late snapshots after Stop.
A 20-second rolling counter window resets on restart, epoch/counter/clock change
or >5-second sample gaps. Actual Internet/DNS validation remains unavailable.
Diagnostic summary v3 includes scoped/fresh counter facts; events remain schema1.
**227 local Dart tests + analyze PASS**, including seven new observation/report/
late-reply cases. All 18 Python network fixture tests PASS. Actual Windows signed service **19 checks PASS** (44057085561), including an
inactive supported capability with null observations. H2/H3 ordinary traffic
**PASS** (44057092836 / 44057100839): same-instance/epoch monotonic totals grew
675 TX / 5428 RX bytes, separately proven HTTPS/DNS, and 479/487 concurrent
snapshot reads observed inactive state after Stop. Network/WFP restored without
watchdog. Native GUI run 44057078923 failed because the UI's revised unverified-
Internet wording still had an old literal test expectation; fixed in 0cc1512.
Repeat GUI **PASS** (44057954554): 227 Dart + 6 Rust + 6 desktop tests, including
actual untrusted-installation refusal of traffic reads. This is not a live signed
GUI traffic-counter acceptance test.

The remaining new-SDK matrix **PASS**: lease death 44057998261, service crash
44058004150, wrong-auth/CA 44058009712 / 44058016409, synthetic IPv6 H2/H3
44058022430 / 44058028697, endpoint-restart recovery H2/H3 44058035430 /
44058041002. Positive cases require real same-epoch TX/RX progress and concurrent
readers observing inactive/missing data at termination; refused profiles require
unknown counters. All ten cases restore routes/DNS/adapter/WFP without watchdog.
[Aggregate receipt](evidence/sdk-traffic-requalification.json). The separately
pinned traffic runtime is requalified only for that disposable-CI scope. Native
IPv6 Internet exit and installed Windows 10/11 acceptance remain open. Compatibility
of the new service with the old SDK **PASS** (44059841735): 19 checks, actual SDK
lifecycle, unsupported traffic capability with null counters. Original runtime receipts remain unchanged.

All 15 packaged dependency notice sets from the aggregate SDK match archived
bodies; 13 explicit source supplements remain. The separately guarded traffic
notice bridge and unchanged 60-text client bundle PASS locally; four notice tests
PASS. Package assembly supports this explicit SDK variant, requires network
requalification and includes its exact runtime/profile/notice receipts. Actual
installer qualification with the new SDK **PASS** (44060362433): 14 groups,
medium GUI/service query, rollback/uninstall/cleanup and preserved input receipts.
[Package receipt](evidence/package-traffic-44060362433.json). Ephemeral CI signing
only, no release approval.

Next focused fixture is implemented for a tiny one-sided flow followed by idle.
A task-owned loopback-only sink accepts only fixed synthetic frames and sends
no payload back; only an explicit endpoint-fixture mode admits its fixed benchmark
address, never the physical exit. It collects >=20-second monotonic same-instance/
epoch windows with <=5-second gaps, checks TX growth / zero RX growth then zero
TX/RX growth, and independently requires sink receipts / selected transport bytes.
All 21 Python fixture tests PASS locally. Initial Windows H2/H3 runs
44064465898 / 44064471948 each proved 672 TX / 0 RX bytes and 21 sink frames
under the notification threshold, but the attempted idle interval after closing
the stream observed another 96 TX bytes, so neither complete case passed. Cleanup
restored the baseline without watchdog. Original failed reports are retained.
Follow-up keeps the flow open for idle and extends only that exact diagnostic
forwarder's lifetime to 75 seconds (others retain 30); it also requires an
unchanged sink receipt across idle. Cause of the post-close bytes is not yet
established. Open-flow follow-up **H3 PASS** (44066619081): +672 TX / 0 RX,
then 20,998 ms of zero TX/RX growth with an unchanged sink receipt. **H2 FAIL**
(44066611999): sink still received exactly 672 bytes and sent none, but aggregate
TX grew by 720 during sending and another 48 during idle. Both restored network/
WFP without watchdog. [H2 receipt](evidence/tx-only-44066611999.json),
[H3 receipt](evidence/tx-only-44066619081.json). Cause remains unestablished;
no SDK change or relaxed idle oracle. The fixture now records closed window deltas
for forwarded/denied TCP and UDP payload totals, without destinations or payloads,
to distinguish other runner activity. **23 Python tests PASS**. Diagnostic H2
run 44068421270 still failed the strict idle oracle: each observation interval
independently recorded one rejected UDP payload of 48 bytes. The sending window
had 672 owned TCP bytes + 48 aggregate TX bytes; idle had zero forwarded TCP bytes
and +48 aggregate TX. This is consistent with non-fixture activity contributing
to the aggregate, not a quiet system; it does not identify the sender or prove a
counter defect. No arbitrary payloads/destinations were retained. Cleanup/WFP
restored without watchdog. [Receipt](evidence/tx-only-44068421270.json).
The independent deadline is 120 seconds only for this longer fixture.

Optional-tail parsing is factored for Windows contract tests: an old 32-byte
refusal must not read a tail or retain a previous snapshot; a partial/missing tail
is timeout/unknown, while malformed full data is malformed/unknown. Valid data
also requires admitted runtime state. Clock-error samples no longer expose an
unobserved monotonic instant. Counter/wire contract, Windows GUI build, 227 Dart + 6 Rust + 6 desktop tests
**PASS** (44064479119). [Receipt](evidence/windows-traffic-4b71e69.json).
This still does not exercise live signed GUI traffic display. Installer with this
GUI and the aggregate SDK **PASS** (44068126242): 14 groups, signed medium GUI /
service query, rollback/uninstall/cleanup. All four preserved SDK input-receipt
hashes match the previous qualified package. [Receipt](evidence/package-traffic-44068126242.json).
Ephemeral CI signing only; no tunnel start, owner package or desktop acceptance.

The traffic window now exposes a closed reset reason to the journal. Previously,
a valid sample after a missed interval/instance change discarded history without
retaining the reason. One `trafficWindowReset` event now records instance/state
change, monotonic clock/counter regression, sampling gap or wall-clock staleness;
steady polling does not add per-tick events. Repeated identical reset conditions
are coalesced until a coherent sample pair or changed reason starts another episode. Observations remain counter facts,
and a new full window must accumulate before classification. **230 local Dart
tests + analyze PASS**, including 26 metric/journal persistence cases and a
stuck-monotonic-clock regression (30 polls produce one reset event).
Windows GUI **PASS** (44073703263): 230 Dart + 6 Rust + 6 desktop tests,
release build, notice bytes and actual channel admission checks.
[Receipt](evidence/windows-traffic-reset-7f701e0.json). Event schema stays v1,
summary v3, with only closed enum additions and no new free-form metadata. UI
counter wording now avoids implying remote delivery and explicitly includes
background applications, consistent with the rejected-UDP fixture observation.
Installer with this GUI and the previously qualified aggregate SDK **PASS**
(44074698238): 14 groups, signed medium GUI/service query, rollback/uninstall /
cleanup and the same four exact SDK input receipts.
[Receipt](evidence/package-traffic-44074698238.json). Ephemeral CI signing only;
no tunnel start, live GUI counter-display qualification or owner release.

Next native prerequisite is implemented as another opt-in SDK preparation:
`attached_tun=true` requires source pins and the aggregate profile. Six exact
post-traffic/pristine source digests and two added-header hashes guard a fixed
40-byte read-only export. It derives index/LUID from the SDK-held Wintun handle,
checks the OS index against the SDK's index and fences ready-state epoch/time
before/after reading. Caller must exclude concurrent start/stop/destruction.
Internal interface identifiers never enter GUI/journal/report. Neither adapter
ownership nor probe/endpoint traversal is established; no health state, probe,
routing or existing runtime pin changes. Local real-source transformation and
five atomic guard tests PASS. Windows C++ contract, exact source preparation,
full SDK and both null-export checks **PASS** (44070100152). All eight emitted
source/header digests match local preparation; both downloaded DLL hashes match
CI. A separate `runtime-attached.json` initially pinned this build-only candidate
with all actual-interface/network/desktop/service/package/release qualifications
false; focused live-interface qualification follows below.
[Receipt](evidence/sdk-attached-44070100152.json). Existing runtime pins remain
unchanged; candidate is not admitted by normal service/package workflows. Source audit also records
self-image WFP permits and Wintun duplicate-alias rename behavior as constraints
on future probe/ownership work; no inferred bypass or foreign-adapter reproduction.

The CI-only live attachment observer is implemented and qualified on Windows. The
explicit `attached_tun=true` network input selects the separate reviewed build and
requires aggregate/source pins. `LIWETUN_TEST_ATTACHED_TUN` (default OFF) requires
its export and fences every otherwise-valid counter read against the actual
SDK-held context under the existing short borrowed-core lock. Mismatched ABI,
identifiers, epoch or bounded monotonic time invalidate the observation. Interface
identifiers remain on the service stack, never cross IPC or enter reports. No
new IPC command/GUI capability/probe or routing policy change. The report marks
this CI observer ON and both routing-test modes OFF. Package assembly explicitly
rejects this third test flag as well as the previous routing flags. **23 Python
fixture tests, syntax/YAML and diff checks PASS**. Windows C++ fence and actual
H2/H3 **PASS**: [44076452026](evidence/attachment-context-44076452026.json),
[44076458760](evidence/attachment-context-44076458760.json). Both admitted actual
SDK-held context at ready counter reads; Stop watchers made 481/497 reads with
478/495 inactive-after-active observations. HTTPS/DNS and all network/WFP baselines
passed without watchdog. This is a CI observation build, not all-test-flags-OFF
product acceptance. `runtime-attached.json` now marks only this focused live
attachment prerequisite qualified; full network/fault/recovery/IPv6 matrix,
normal service/package admission, probe traversal, ownership and desktop/release
remain unqualified. Original build/runtime input receipts remain historical.

Package exclusion with the unchanged qualified aggregate SDK **PASS**
(44076464374): all three CI flags OFF, 14 installer groups, medium GUI/service
query, rollback/uninstall/cleanup; exact SDK input receipts preserved.
[Package receipt](evidence/package-traffic-44076464374.json). Temporary CI signing
only. All 15 archived dependency notice sets of the attached build match previous
bodies; 13 source supplements remain; actual Conan lock PASS.
[Byte receipt](evidence/sdk-attached-notices-44070100152.json). No distribution approval.

The next owned-request source audit identifies three positive-byte hook sites
and endpoint/listener checks, plus client-ID swaps during migration. A future
reducer must derive the owned socket tuple, reject bypass/migration and retain
only short-lived closed path facts. No per-destination event/logger restoration.
This remains design-only: no owned-request arm/read API, DNS/HTTPS health probe
or dedicated health endpoint is implemented/selected. [Audit](HEALTH_PROBES.md).

Owned-socket correlation primitive is now implemented, not integrated into the
SDK/service/GUI yet. A fixed 32-byte arm request / 56-byte closed snapshot contain
no socket/interface/connection ID, address or string. One bounded in-memory slot
requires exact private socket-key matching and token/epoch/monotonic TTL fences;
other path, migration, changed socket, expiry or observer failure invalidate
facts. Tiny byte deltas are immediate; overflow is atomic/faulted. Late old-token
reads/disarm and foreign-flow bytes cannot alter a new attempt. Windows arm-key
helper reads a connected exclusive TCP socket and queries only its exact local
address entry against the supplied SDK-held LUID/index; it does not enumerate
interfaces or change configuration. The caller must hold a fresh socket and arm
before application I/O. Standalone Windows C++ concurrency and actual loopback socket boundary **PASS**
(44090062715), synthetic context without SDK/TUN or network configuration changes.
[Receipt](evidence/probe-contract-44090062715.json). No actual
SDK path, DNS/HTTPS health endpoint or application readiness is claimed.

A separate opt-in `owned_probe=true` SDK profile now integrates the slot with
seven exact post-attachment vendor inputs and six added files. It derives the
socket key from the held TCP descriptor and exact address membership, observes
three actual byte-transfer sites, checks endpoint/listener at every matching
update, and invalidates on migration/other selection. No per-destination events,
raw logs, generic tuple export or routing policy changes. Slot methods do not take
the core stop guard or dispatch synchronously onto its event loop; callers still
exclude SDK start/stop/destruction and never hold the lifetime lock over I/O.
Three fixed ABI socket-arm/read/disarm exports are implemented; global state/epoch
fences surround SDK access. A callback-failure-vs-read race is explicitly tested.
Local full-source guarded transformation, five new atomic guard tests, **14 SDK
profile tests**, Python/YAML and diff checks PASS. Full SDK, updated C++ race/family/socket contracts and all three null-export ABI
checks **PASS** (44092512284), source 7e35231. All 13 emitted file digests match
local preparation; both downloaded DLL hashes match CI. Separate build-only
`runtime-probe.json` preserves network/service/package/desktop/health gates false.
[Receipt](evidence/sdk-owned-probe-44092512284.json). No existing runtime pin, service protocol or GUI
capability is promoted; no actual owned-request path/HTTPS/DNS health is qualified.

A default-OFF fourth CI flag, `LIWETUN_TEST_OWNED_PROBE`, now creates a fresh
service-owned TCP socket to a single fixed synthetic receiver, rejects a connected
nonexclusive control socket, arms before application I/O, verifies a random nonce
echo, reads current SDK instance/epoch/path evidence and disarms before closing.
Its cancellable worker holds the borrowed-core lock only for brief SDK calls,
never network I/O, and joins before SDK stop/unload. A one-shot closed JSON receipt
contains booleans/enums/nullable counters, no socket/interface/flow IDs or tuples.
No service command or GUI capability is added. Only this CI mode gates ready
counter observations on successful owned-path evidence; the normal product path
is unchanged. The local server/allowlist/schema guards **27 Python tests PASS**;
YAML/Python/diff checks PASS. Actual H2/H3 producer, cancellation behavior and
four-flag package exclusion are pending on Windows. This is raw synthetic TCP
path qualification, not an application HTTPS/DNS/Internet check or release.

Focused service-owned raw TCP path **PASS** on disposable Server 2022 CI,
source `8056b95`: [H2 44113354047](https://github.com/pvlrdnv/liwetun-win/actions/runs/44113354047)
and [H3 44113385217](https://github.com/pvlrdnv/liwetun-win/actions/runs/44113385217).
Each observed exactly 24 endpoint TX / 24 endpoint RX bytes, matching nonce,
instance/epoch and disarm; the connected nonexclusive control was rejected.
Receiver independently recorded one exact request/reply, no rejected frames.
Ordinary HTTPS/DNS and concurrent Stop counter reads also passed; routes, DNS,
adapter and WFP restored with no watchdog action.
[Closed reports](evidence/owned-probe-live-44113354047.json).
The separate probe runtime pin now records only this focused CI path scope;
full network matrix, live bypass/migration negatives, cancellation during I/O,
normal service/package admission, application HTTPS/DNS health and both desktop
OS qualifications remain false/open. No Connected capability is added.

Four-flag exclusion package **PASS** (44113393613): 14 installer groups, medium
GUI/service query, rollback/uninstall/cleanup, all CI modes OFF. It still uses the
previous qualified aggregate SDK (44038398682) and GUI 44073703263; the owned
probe SDK is not packaged. Four pinned input receipt hashes are unchanged.
[Package receipt](evidence/package-traffic-44113393613.json). Temporary CI signing
only; no tunnel was started by the installer qualification.

A separate `owned_probe_mode=cancel` fixture now withholds the response after
receiving the exact owned request. Before Stop it requires an open waiting
receiver, unknown service counters and no completed worker receipt. Stop ACK,
worker cancellation receipt and remote EOF must complete within 1.5 s, with an
overall observation shorter than the native 4 s deadline. Cancelled evidence must
have no successful echo/epoch/path facts and null counters. Network/WFP baseline
restoration and no watchdog action remain mandatory. No SDK or product native
behavior changed. **29 local Python tests**, Python/YAML and diff checks PASS;
actual Windows cancellation qualification is pending. Live bypass/migration
negative controls and product health integration remain open.

Trusted common-leaf release signing, final distribution audit and separate
Windows 10/11 installed desktop acceptance remain open. Server 2022 / WSL tests
do not qualify those systems. New SDK artifacts retain for 14 days. Latest GUI
runtime/provenance expires 2026-12-01, its safe evidence/Rust notice candidates
2026-11-24; the repaired diagnostic endpoint expires 2026-11-30. Recheck availability
and preserve all source-run/digest guards before reuse.

Endpoint-restart recovery passed bounded disposable Windows CI for H2 and H3.
Only the owned diagnostic server is stopped for two seconds; the authenticated
client lease and SDK instance remain alive. Success requires fresh HTTPS and
exact synthetic DNS replies from TUN sources over the selected H2/H3 transport,
then Stop and baseline routes/DNS/adapter/WFP restoration. Initial H2 run 44029340084 PASS. Initial H3 run 44029344825 did not establish
recovery in its three-attempt window: HTTPS returned on attempt three, DNS did
not; Stop restored baseline network and WFP without watchdog. Both original
reports are archived. Follow-up observes post-probe state and elapsed time over
up to five attempts starting within 75 seconds; a 120-second independent watchdog
applies only to this case. No desktop
sleep/Wi-Fi-switch claim and no application recovery changes. Four oracle guards
cover false positives; all 15 Python fixture tests PASS. Follow-up H3 **PASS** (44030366734): fifth observation at 44,812 ms proves
HTTPS + exact synthetic DNS/82 bytes over H3, post-probe state ready, then full
network/WFP restoration without watchdog. Independent H3 confirmation 44030999383 **PASS**, including full restoration.
Earlier observations did not prove tunnel traffic even when HTTPS returned.
No product/SDK recovery policy change.

## Latest checkpoint — six basic ordinary IPv4 CI cases PASS

With both application network-test flags OFF and no client host routes, ordinary
unbound HTTPS/DNS passed over H2 and H3, with exact per-probe DNS transport proof.
H2 forced lease-client death, owned-service crash, wrong-auth and wrong-CA startup
refusal also passed, including complete route/DNS/adapter/WFP restoration without
watchdog action. [Six-case receipt](evidence/production-basic-matrix.json),
[method and remaining gates](PRODUCTION_ROUTING.md).
The DNS blocker was an endpoint SOCKS5 idle-socket read bug, reproduced on Linux
without SDK/TUN and repaired only in a pinned diagnostic CI server. No application
SDK or production endpoint change. [Diagnosis](ENDPOINT_UDP_FIXTURE.md).
This is Server 2022 CI, not installed Windows 10/11 desktop qualification.
Synthetic IPv6 TCP/UDP + AAAA subsequently passed H2/H3 CI (receipts below).
Native IPv6 egress / DNS wire transport, network-change/sleep recovery,
signing/distribution and desktop acceptance remain open. The owner corporate device and LikeWeb remain untouched.

## TUN network stage — bounded CI PASS

Full signed-service/network matrix passed on both pinned endpoint versions:
[1.1.0 run 43748675582](https://github.com/pvlrdnv/liwetun-win/actions/runs/43748675582),
[1.3.0-beta.2 run 43748678908](https://github.com/pvlrdnv/liwetun-win/actions/runs/43748678908).
Each passed 16 service/security checks plus 6 real network cases. H2/H3 HTTPS,
separately proven DNS transport, wrong-auth/CA denial and stop/UI-death/service-
crash cleanup passed. Multicast routing was corrected; idle data became zero,
with bounded sockets/CPU. [Method and evidence](TUN_NETWORK_ACCEPTANCE.md).

Owner clarified Windows 10/11 x64 targets and a separate Windows 10 PC for manual
acceptance. The corporate tunnel on the development device stays operating.
[Compatibility plan](WINDOWS_COMPATIBILITY.md). Windows Server CI is not desktop
acceptance and normal global routing/IPv6 remain open.

## Protected storage — native and GUI PASS

Current-user Windows DPAPI, private per-user ACLs, encrypted atomic replacement
and revision compare-and-swap passed actual Windows qualification on `a08114b`:
[run 43751590632](https://github.com/pvlrdnv/liwetun-win/actions/runs/43751590632).
GUI worker channel, bounded profile schema, serialized persistence and honest
failure states are implemented. Updated Windows application qualification on
`aa40380` **PASS**: [run 43752160848](https://github.com/pvlrdnv/liwetun-win/actions/runs/43752160848),
99 Dart + 6 Rust tests, analyze, release build and 2 actual desktop channel tests,
including DPAPI roundtrip and profile restoration without auto-connect.
[Storage design/evidence](PROFILE_STORAGE.md).

SDK build continuation: enforced Conan recipe input lock, output/graph drift
checks and bounded packaged-notice collection implemented; five local tests and
fresh-source preparation passed. Updated SDK build **PASS** on `37519a8`,
[run 43752644532](https://github.com/pvlrdnv/liwetun-win/actions/runs/43752644532).
Its downloaded DLL hashes are pinned in `native/sdk/runtime.json`; network
requalification **PASS** with service `dd566d9`,
[1.1 run 43814467138](https://github.com/pvlrdnv/liwetun-win/actions/runs/43814467138),
[1.3 run 43814471604](https://github.com/pvlrdnv/liwetun-win/actions/runs/43814471604):
18 service/security/transport checks + 6 real network cases each.
Notice collection found 13 missing
package notice sets out of 28 graph nodes, retained as explicit release blockers.
This does not qualify licenses or change the earlier network artifact. See
[dependency closure](DEPENDENCY_CLOSURE.md).

Owner-test preparation: safe report summary v2 adds bounded Windows API build /
application architecture and timestamped service response; failed observations
stay unknown. **102 Dart + 6 Rust + 2 actual desktop tests PASS**, analyze and
Windows release build PASS on `ddef944`:
[run 43753564027](https://github.com/pvlrdnv/liwetun-win/actions/runs/43753564027),
[build evidence](evidence/windows-report-ddef944.json).
[Prepared scenario](OWNER_WINDOWS_TEST.md), no installer available
yet.

Journal continuation: a separate current-user DPAPI slot is implemented in native
storage, with a different protection purpose and fixed bounded pending file.
Native profile/journal isolation, cross-purpose denial and crash-orphan checks
passed on `53bd51d`, [run 43754557047](https://github.com/pvlrdnv/liwetun-win/actions/runs/43754557047).
GUI persistence, seven-day/1000-event retention, serialized saves and explicit
clear **PASS** on Windows `c7b6f3d`,
[run 43812996533](https://github.com/pvlrdnv/liwetun-win/actions/runs/43812996533):
**118 Dart + 6 Rust + 3 actual desktop tests**, release build and analyze PASS.
[Journal design/evidence](JOURNAL_STORAGE.md).

New SDK network continuation on `e663c8c` failed: one preflight stop lost its reply;
the other run passed H2/H3/DNS and auth/CA negatives before failing at UI-death.
These runs do not establish complete new-SDK qualification. A server-side pipe
race was found: disconnect after completed write can discard unread reply bytes.
Bounded/cancellable peer-close waiting and a deliberately delayed-reader
regression check passed in both updated Windows runs above. Source notice
supplements now cover all 13 missing package sets; 38 SDK/Wintun/related files
and 22 Rust files have integrity/dependency checks. The Windows notice-check
workflow **PASS** on `a5f9d29`,
[run 43816739851](https://github.com/pvlrdnv/liwetun-win/actions/runs/43816739851).
Final distribution audit remains pending.

Package payload preparation: read-only GUI status command, manifest-checked GUI
artifact staging, production-mode service + app-local CRT and notice assembly,
and a restricted medium-integrity GUI query fixture are implemented. Windows
qualification is pending. This is not an installer or owner-machine test package;
see [PACKAGE_PAYLOAD.md](PACKAGE_PAYLOAD.md).

GUI continuation on `56f94e6`: analyze, 118 Dart tests, 6 Rust tests, release
build and all 3 actual desktop channel tests passed in
[run 43825848338](https://github.com/pvlrdnv/liwetun-win/actions/runs/43825848338),
including the unsigned GUI read-only status command. The overall workflow failed
at the subsequent runtime staging guard because of an unexpected build output;
its name was not captured. Added a bounded root build-file inventory and
failure-independent evidence upload to diagnose this without relaxing admission.
Payload qualification remains pending; no installer or desktop readiness claim.

Staging diagnosis on `ffa8262`,
[run 43837040458](https://github.com/pvlrdnv/liwetun-win/actions/runs/43837040458):
all application checks passed again; the captured inventory identified Flutter's
`native_assets.json` as the rejected root file. The pinned Flutter writer emits
format 1.0.0 with an empty native-assets mapping for this application. Staging
now requires that exact empty mapping (bounded to 1024 bytes), copies it and
includes it in the required files/hash manifest. Other JSON/native mappings
remain rejected. Corrected staging **PASS** on `9d891c8`,
[run 43837997739](https://github.com/pvlrdnv/liwetun-win/actions/runs/43837997739):
analyze, 118 Dart + 6 Rust + 3 actual desktop tests, release build and GUI runtime
artifacts all passed. [Safe GUI evidence](evidence/windows-payload-gui-9d891c8.json).
The production-mode signed payload qualification has been dispatched using that
GUI artifact. First payload run
[43838617523](https://github.com/pvlrdnv/liwetun-win/actions/runs/43838617523)
compiled the production-mode service and restricted-token helper successfully,
then failed at original CRT signature admission before installation. Cleanup and
unchanged network checks passed. Added a per-CRT filename/hash/numeric signature
status/closed publisher-category report to diagnose without lowering trust checks.
Diagnostic runs 43839005376/43839414368 showed all ten original CRT signatures
Valid; the actual certificate name is `Microsoft Windows Software Compatibility
Publisher`, rather than the originally assumed `Microsoft Corporation`. CRT
admission now accepts those two exact Microsoft publisher names with a Valid
Authenticode result; signatures/bytes are preserved. No generic trusted-signer
fallback or temporary Microsoft root was added. Payload recheck pending.

Payload run [43839769141](https://github.com/pvlrdnv/liwetun-win/actions/runs/43839769141)
passed original CRT/x64/notice/signature assembly and an actual signed GUI query
to the production-mode service. Restricted medium GUI returned Denied (code 2);
cleanup/network-unchanged passed. The client's live System-process/token proof
needs metadata access unavailable to that token. The service now grants its
configured owner only QUERY_LIMITED_INFORMATION/SYNCHRONIZE on its own process
and TOKEN_QUERY on its own token, preserving the existing DACL and the complete
client-side proof. It changes no other process/global ACL. A restricted-token
fixture also requires denial of seven process-control and eight token write/
duplication/impersonation rights. Windows qualification of this fix is pending.
Existing service/security regression **PASS** on `2c79109`,
[run 43840736350](https://github.com/pvlrdnv/liwetun-win/actions/runs/43840736350):
15 checks, without SDK/driver lifecycle. Unsigned/different-signer/different-owner
denials, bounded/delayed IPC, stop and uninstall remain enforced.
[Safe evidence](evidence/service-owner-query-2c79109.json). The separate signed
GUI/medium-token production-payload check is still pending.

Signed production-mode payload **PASS** on `2c79109`,
[run 43841410482](https://github.com/pvlrdnv/liwetun-win/actions/runs/43841410482),
using GUI `9d891c8` and pinned SDK run 43752644532. The actual GUI read-only query
passed both elevated and at restricted medium integrity with Administrators
disabled; all seven process-control and eight token-control rights remained
denied individually. Both network test modes were OFF, no tunnel was started,
network snapshots were unchanged, and fixture/service/trust cleanup passed.
[Safe payload evidence](evidence/package-payload-2c79109.json). This supersedes
the pending payload qualification above. It does not qualify an installer,
ordinary desktop account, Win10/11 or normal-mode traffic. The temporary CI
signer is not a release signer or an owner-test package.

Fresh-installer continuation: pinned NSIS 3.13 source, optional disposable
qualification, signed embedded uninstaller, fixed protected x64 installation,
fresh-only admission, explicit owner validation, native same-session Explorer
owner selection, owned rollback and exact-list uninstall are implemented as a
prototype. The fixture includes invalid-owner rollback, preserved unknown files,
installed medium-integrity GUI checks and normal uninstaller bootstrap. Native
uninstall now treats an absent service idempotently after trusted-image admission.
All new installer/native changes require Windows qualification; see
[installer boundaries](INSTALLER.md). No installer is uploaded for owner use.
Initial installer run 43844667848 compiled the new native source but stopped at
the NSIS download digest guard, before extracting/executing that tool. A fresh
local curl download independently matched the original pinned SHA256 and ZIP
size 2363925. CI fetch now uses bounded curl and official SourceForge mirror
fallbacks with the same mandatory digest; only numeric/hash attempt evidence is
retained. Qualification is still pending; the pin was not replaced.
Run 43845193769 fetched the exact pinned NSIS archive and built/signed setup.
Existing-directory preservation passed; invalid-owner rollback did not return
the expected closed exit code, so the matrix stopped and fixture cleanup passed.
Fixed registry command quoting, made explicit failure exits run rollback before
Quit, and enabled compiler warnings-as-errors. Closed invocation exit codes and
pre-cleanup presence facts now accompany failures. Installer qualification remains
pending, including normal uninstall and desktop owner selection.
Run 43845886814 identified the actual early failure: setup returned service-
preflight code 22 before creating any files. NSIS System's documented `?e`
must capture a Win32 last-error atomically; a separate plugin call can lose
ERROR_SERVICE_DOES_NOT_EXIST. Both service and mutex probes now use `?e`.
The fixture additionally tests mutex, preexisting stopped service, registry and
shortcut preservation. The core/service admission checks are unchanged.
Run 43846497536 passed compiler/signature and all five fresh-admission fixture
groups. Invalid-owner setup returned rollback-failure 50 even though its directory,
registration and shortcut were already absent before fixture cleanup. Rollback
was checking a stale error flag after deleting optional metadata that had never
been created. It now verifies those absences explicitly and isolates final
directory-removal errors; successful rollback tracking is idempotent. Native
process launch return slots are initialized to failure before ExecWait so launch
failure cannot reuse an old success value. Full installer matrix still pending.

Fresh installer matrix **PASS** on `d31a0bb`,
[run 43847087250](https://github.com/pvlrdnv/liwetun-win/actions/runs/43847087250):
12 installer check groups, enclosing production-mode payload checks, unchanged
DNS/routes/adapter snapshots and complete cleanup. Setup/uninstaller signatures,
preservation of existing objects, invalid-owner rollback, payload digests,
demand-start service registration, installed medium GUI query, unknown-file
preservation, retry and ordinary uninstaller bootstrap passed. Both native test
network flags were OFF and no tunnel was started. [Evidence](evidence/installer-d31a0bb.json).
This supersedes pending installer CI qualification above. Default Explorer owner
selection/alternate-admin UAC, in-use UI removal, upgrades/recovery and Win10/11
desktop acceptance remain open. Temporary CI signing is not release signing;
no installer was uploaded for owner use.

In-use removal continuation: GUI startup now briefly claims the existing global
setup gate before publishing a lifetime-only presence object. Uninstall holds
that gate, fails closed on any presence/unknown-probe result before mutations,
and asks to close the GUI. A subsequent GUI cannot pass startup while removal
holds the gate. Read-only status CLI bypasses UI presence and remains unchanged.
Namespace objects contain no secrets/commands and do not replace service IPC
authentication; name squatting can deny availability. Updated GUI compilation
and real installed-window medium-integrity qualification are pending.
The optional CI helper now has a fixed visible-GUI mode with the same restricted
medium token, explicit inherited handles and fresh user environment. It discards
GUI raw output, identifies only its own created child's visible Flutter window,
uses PID-scoped local ready/stop events, and closes that window with WM_CLOSE.
A kill-on-close job plus exact-child fallback bounds failure cleanup. Installer
fixture expects code 43 while the window is open and verifies every payload
digest, service running PID and registration remain unchanged before closing.
This is implemented but still requires the new GUI artifact and Windows proof.
Updated GUI **PASS** on `4ab70e9`,
[run 43850065637](https://github.com/pvlrdnv/liwetun-win/actions/runs/43850065637):
118 Dart + 6 Rust + 3 actual desktop tests, analyze, release build and staging.
[GUI evidence](evidence/windows-lifetime-4ab70e9.json).
Installed visible GUI/uninstall continuation **PASS** on `9688b98`,
[run 43850964866](https://github.com/pvlrdnv/liwetun-win/actions/runs/43850964866):
14 installer groups and enclosing payload qualification passed with that GUI.
A real visible Flutter window ran with Administrators disabled at medium
integrity; uninstall returned 43 before any payload digest, service running PID
or registration changed. WM_CLOSE ended the exact created GUI successfully and
released presence; subsequent full uninstall/retry/bootstrap passed. Both network
test modes were OFF, no tunnel was started, network snapshots and cleanup passed.
[Evidence](evidence/installer-visible-gui-9688b98.json). This establishes bounded
CI in-use rejection, not desktop acceptance, loader/antivirus sharing-race recovery,
a transactional uninstall, or Windows 10/11 qualification.

Production-routing continuation: optional service qualification now builds with
both network test modes OFF and exercises only a synthetic refused loopback
endpoint. It verifies exact original DNS/all-route/adapter restoration, observes
only its own adapter prefix-length categories and uses an independent 30-second
deadline that can stop only this job's image-verified service process. SDK source
run/commit and original DLL digests are enforced before CI signing. This new
fixture is pending Windows proof and explicitly does not test Internet delivery,
successful global routing, IPv6 traffic or a live server.
Initial production-lifecycle run 43854172525 compiled with the intended flags and
passed earlier service/SDK fixture steps, but stopped at the one-second TCP
preflight before the production lifecycle was launched. No lifecycle evidence
was produced. Preflight now records a closed no-listener observation for the
synthetic port instead of depending on async connection timing; the independent
watchdog must emit readiness before the SDK probe can start. Recheck pending.
Refused-endpoint lifecycle **PASS** on `7055a15`,
[run 43854899728](https://github.com/pvlrdnv/liwetun-win/actions/runs/43854899728):
18 service checks, actual adapter/DNS observation, complete route/DNS/adapter
snapshot restoration, no deadline intervention. [Evidence](evidence/general-lifecycle-7055a15.json).
However, only DNS/multicast/local route categories appeared. Source inspection
of pinned SDK `a1ce3f9` confirmed `parse_tun_listener_config` leaves omitted
route arrays empty and `make_tun_listener` passes them directly instead of the
documented OS defaults. The service was omitting them in its production branch.
This is an actual routing defect, not successful general-mode traffic evidence.
Production config now explicitly includes IPv4 0/0 and IPv6 2000::/3 with the
pinned SDK's recommended private/link-local/multicast IPv4 exclusions. Bounded
CI branches are unchanged. The new fixture requires own-adapter CIDRs covering
fixed IPv4/IPv6 samples; native lifecycle observation allows six seconds. This
fix and the stricter route criterion require fresh Windows qualification.
Explicit-route production lifecycle **PASS** on `0c211b1`,
[run 43856182784](https://github.com/pvlrdnv/liwetun-win/actions/runs/43856182784):
18 service checks, IPv4/IPv6 sample CIDR coverage, adapter DNS and complete
snapshot restoration, without watchdog intervention. This supersedes the
pending route fix above. [Evidence](evidence/general-routes-0c211b1.json).
Source inspection also confirmed SDK DNS restrictions use a dynamic WFP session;
a CI-only read-only probe now requires owned SDK dynamic sessions to appear and
return to baseline after stop. This extra check is pending. No Internet/IPv6
payload or DNS-leak prevention claim. [Routing boundaries](PRODUCTION_ROUTING.md).
WFP observation run 43857843576 stopped during compilation of the new CI probe:
its translation unit lacked the required windows.h include before fwpmu.h.
The service itself compiled; no new runtime qualification was obtained. Added
the explicit Windows header; WFP observation remains pending a fresh run.
Production route/DNS/WFP lifecycle **PASS** on `fc60eb3`,
[run 43858170850](https://github.com/pvlrdnv/liwetun-win/actions/runs/43858170850):
18 service checks; both IPv4/IPv6 sample route coverage and own adapter DNS;
SDK-owned dynamic WFP session appearance and return to baseline after stop;
exact route/DNS/adapter restoration without deadline intervention. The watchdog
was armed before SDK start. [Evidence](evidence/general-wfp-fc60eb3.json).
Internet payload, effective DNS-leak protection and desktop acceptance remain
open. The WFP probe is not linked into the shipped GUI or service.

Ordinary-traffic fixture continuation: the official endpoint's SOCKS5 forwarder
can separate its egress from the same-host Windows client's routing. Added a
same-host, synthetic-authenticated, destination-allowlisted test forwarder;
only its egress sockets bind the original physical interface. Four live local
TCP/UDP protocol tests PASS, including wrong auth, denied destinations and UDP
fragment rejection. A new opt-in single IPv4 case uses production service flags,
ordinary unbound client sockets, selected TUN route/source checks, normal HTTPS
TLS, synthetic DNS and a 60-second independently armed deadline. No test host
routes are added and the official endpoint binary is unchanged. This new fixture
does not qualify the full failure/IPv6/desktop
matrix. The existing bounded network workflow remains the default.

First ordinary-traffic run on `f2a1a74`,
[43861649225](https://github.com/pvlrdnv/liwetun-win/actions/runs/43861649225):
ordinary unbound HTTPS with normal TLS and a TUN source **PASS**. DNS **FAIL**:
the synthetic question reached the DNS fixture and the forwarder sent its reply,
but no reply bytes were observed at the endpoint/client. Overall case failed;
route/DNS/adapter and SDK WFP sessions restored, watchdog did not intervene.
Investigating the WSL1 connected-UDP return path: TCP control stays loopback,
UDP relay now advertises/binds the same-host private address and admits only
loopback or that exact host as source. No public relay, test client host routes,
TLS relaxation or app routing changes. Local four protocol tests PASS with a
connected UDP client; Python compilation PASS. Windows rerun pending.
Added a separate WSL1 connected-UDP boundary preflight before SDK start: exact
synthetic DNS answer through authenticated Windows SOCKS5, with only closed
booleans/numeric OS errors exported. A failure stops before the SDK can change
routes. This additional preflight has only passed syntax checking locally;
actual WSL1/Windows execution remains pending.

Follow-up runs: `855a69b` H2
[43875493554](https://github.com/pvlrdnv/liwetun-win/actions/runs/43875493554)
and `2bd6a68` H3
[43875792983](https://github.com/pvlrdnv/liwetun-win/actions/runs/43875792983)
both passed ordinary TLS HTTPS and TUN source selection; DNS timed out, so both
overall results remain **FAIL**. WFP/network restoration passed without watchdog
intervention. The H3 run additionally passed every WSL1 connected-UDP preflight
observation before SDK start. Private relay binding alone did not fix DNS.
Added the same boundary observation while the SDK is active to distinguish
fixture/routing interference from endpoint UDP handling; Windows check pending.
That comparison on `812a080`,
[43876331775](https://github.com/pvlrdnv/liwetun-win/actions/runs/43876331775),
passed the WSL1 connected-UDP boundary both before and during SDK operation.
Ordinary HTTPS passed again; client DNS timed out and the overall case failed.
Cleanup/WFP restoration passed. Next observation checks edge-triggered epoll
readiness and aggregates only the owned endpoint child's UDP receive queues;
it exports no addresses, inode IDs, descriptors or raw output. Local own-child
queue check PASS (queued then consumed, unrelated sender excluded), syntax PASS.
WSL1 execution of these additional observations is pending.
Run `1071e79`,
[43877097450](https://github.com/pvlrdnv/liwetun-win/actions/runs/43877097450),
passed edge-triggered epoll boundary checks before/during SDK operation; ordinary
HTTPS passed and DNS still timed out. Overall **FAIL**, cleanup/WFP restored.
WSL1 exposed zero matching endpoint UDP descriptors in its proc tables, which
does not prove an empty receive queue; zero matches are now explicitly unknown.
Next fixture experiment keeps the endpoint's UDP relay inside WSL1, chains only
HTTPS to the Windows physical exit, and requires the private synthetic DNS route
to select the physical interface. No client host routes or app network changes.
Five local protocol checks PASS, including authenticated chained TCP delivery;
Python syntax/diff checks PASS. Actual Windows experiment pending.
Local-relay experiment `84e76cb`,
[43878059292](https://github.com/pvlrdnv/liwetun-win/actions/runs/43878059292),
again passed HTTPS/TUN source, private DNS physical-route selection, boundary
preflights and restoration; DNS still timed out. Overall **FAIL**. The Linux-local
relay sent replies without errors, so relocating it did not fix the symptom.
Added a fixed synthetic HTTP/1 CONNECT `_udp2` wire preflight against the official
endpoint before SDK start (normal profile-scoped fixture TLS verification).
It requires exact returned metadata and DNS answer; failure stops before route
changes and records closed observations only. Syntax/diff PASS; CI pending.
Added a separate disposable Ubuntu endpoint-only control using that same fixed
wire probe, binary hash and synthetic relay/DNS fixture. It starts no SDK/TUN,
changes no routes and cannot establish Windows readiness. Comparing native Linux
with WSL1 should isolate a server/fixture problem from Windows SDK behavior.
Python syntax/diff checks PASS; actual CI execution pending.
Single-flow endpoint wire controls **PASS** on native Ubuntu
[43879172234](https://github.com/pvlrdnv/liwetun-win/actions/runs/43879172234)
and WSL1 before SDK start in
[43878904033](https://github.com/pvlrdnv/liwetun-win/actions/runs/43878904033).
The latter ordinary SDK DNS case still failed, with HTTPS/cleanup passing.
Source hypothesis: SOCKS5's datagram source awaits recv after readiness, unlike
the direct forwarder's nonblocking try_recv/WouldBlock path; stale readiness
could stall other associations behind an idle socket. Added a two-source-port
wire control on one TLS stream to test this without SDK/TUN. Not confirmed yet;
syntax/diff checks PASS, native Linux CI pending.
Two-flow reproduction on `86d516f`
[43879797921](https://github.com/pvlrdnv/liwetun-win/actions/runs/43879797921)
**FAIL** independently of Windows/SDK/TUN: first flow returned correctly, second
timed out, although both synthetic answers were sent by the relay. This confirms
the endpoint SOCKS5 path's multi-flow failure in the fixture; the precise
nonblocking-read hypothesis is pending a source-fix comparison.
Prepared a minimal two-file patch against endpoint commit
`fab5b8353a19332f935fa30869307d37d4a898d1`: use try_recv and return to polling on
WouldBlock rather than awaiting another datagram on an idle association.
Source archive, patch, input and resulting file digests are pinned. Local exact
patch/digest and Python syntax/diff checks PASS. Compilation and two-flow check
are pending on disposable Linux CI. This modified diagnostic server is not an
official released endpoint or application release, and changes no production.
Diagnostic endpoint source fix **PASS** on `646618e`,
[43880327333](https://github.com/pvlrdnv/liwetun-win/actions/runs/43880327333):
Rust compilation and both exact UDP-flow replies passed. This confirms the
stale-readiness/awaited-receive cause in the fixture's SOCKS5 path.
[Diagnosis and comparison](ENDPOINT_UDP_FIXTURE.md).
Downloaded binary and source/patch provenance verified; run/commit/SHA256 pinned
for optional Windows consumption. Original default bounded endpoint stays
unchanged. Windows ordinary-mode H2/H3 runs with the fixed diagnostic server and
two-flow preflight are pending. No application SDK or production server changed.
Ordinary IPv4 traffic **PASS** on `fe9ba3d` with that repaired diagnostic fixture:
[H2 43881857485](https://github.com/pvlrdnv/liwetun-win/actions/runs/43881857485),
[H3 43881865435](https://github.com/pvlrdnv/liwetun-win/actions/runs/43881865435).
Both passed unbound normal-TLS HTTPS, exact synthetic DNS answer, TUN source /
route selection, two-flow endpoint preflight, exact 82 DNS transport bytes, and
full route/DNS/adapter/WFP restoration without watchdog intervention. Test network
modes OFF; no client host routes added. These are single positive Server 2022
cases using the modified CI endpoint, not desktop/full-fault/IPv6 qualification.
Added exact synthetic-question request/reply counters at the endpoint relay and
per-probe deltas to exclude unrelated runner DNS from transport proof; require at
least 82 transport bytes. Five local protocol tests and syntax/diff checks PASS;
Windows reruns with these strengthened observations pending.
Strengthened ordinary-mode checks **PASS** on `4653876`:
[H2 43882488976](https://github.com/pvlrdnv/liwetun-win/actions/runs/43882488976),
[H3 43882496493](https://github.com/pvlrdnv/liwetun-win/actions/runs/43882496493).
Each observed exactly one synthetic question and reply through the endpoint
relay, exactly 82 DNS transport bytes, correct unbound TUN sources and full
network/WFP restoration without watchdog intervention. Both flags OFF and no
client host routes. IPv6/full fault matrix/desktop/release gates remain open.
Next fault case: force termination of the exact live authenticated lease-client
process after successful traffic, without Stop or stdin EOF. The service must
restore routes/DNS/adapter and WFP itself. This is a native CI lease process,
not a claim about an installed visible GUI crash. Syntax/YAML checks PASS;
actual ordinary-mode lease-death CI pending.
Ordinary H2 lease-client death **PASS** on `b8d84cf`,
[43883087034](https://github.com/pvlrdnv/liwetun-win/actions/runs/43883087034):
HTTPS/DNS and exact DNS marker passed first; the live native lease process was
then force-terminated with nonzero exit, without Stop/EOF. The service restored
all route/DNS/adapter and WFP baselines without watchdog intervention.
[Evidence](evidence/production-lease-death-43883087034.json).
Prepared the owned-service crash case. A CI-only WFP watcher authenticates the
live service, verifies its protected signed image/System identity, retains a
query/synchronize handle, and observes that same process's exact SDK-labelled
sessions after death. It accepts no PID/filter name and exports only counts /
an alive boolean. Crash injection retains and checks only this run's exact
service process before termination. No shipped service/GUI change. Python/YAML /
diff checks PASS; native Windows compilation and crash acceptance pending.
Ordinary H2 owned-service crash **PASS** on `383dfcb`,
[43883716213](https://github.com/pvlrdnv/liwetun-win/actions/runs/43883716213):
native Windows compilation, actual HTTPS/DNS with exact marker, dynamic WFP
session observed on the retained original service, verified force termination,
original-process death and return of its sessions to baseline; all routes/DNS /
adapter restored without watchdog intervention.
[Evidence](evidence/production-service-crash-43883716213.json).
Prepared separate wrong-auth/wrong-CA production startup controls (H2 Stop only):
calibrated healthy endpoint preflight, fixed generated negative profile, typed
terminal CoreFailure/Error, zero endpoint payload/TCP egress, then complete WFP /
network restoration. No ordinary direct HTTPS request is made after refusal;
this does not claim a kill switch. Endpoint registry may reject credentials
before SOCKS5, so SOCKS auth counters are not used as proof. Python/YAML/diff
checks PASS; actual negative Windows cases pending.
Ordinary negative startup cases **PASS** on `e096b0d`:
[wrong auth 43884507628](https://github.com/pvlrdnv/liwetun-win/actions/runs/43884507628),
[wrong CA 43884514904](https://github.com/pvlrdnv/liwetun-win/actions/runs/43884514904).
Both observed terminal CoreFailure/Error, absent adapter at refusal, zero endpoint
payload/TCP egress, and complete network/WFP restoration without watchdog action.
No post-refusal ordinary HTTPS probe was attempted; no kill-switch claim.
All six basic IPv4 scenarios now have explicit evidence; this does not qualify
the complete fault/IPv6/desktop/release matrix.
Distribution continuation: verified all 13 files of the earlier GUI artifact;
its Flutter notice bundle lacked the native SDK/Rust notices. Added a generated
offline license source with all 60 original notice bodies, a Support license-page
entry, build-time engine/native notice byte checks and package provenance guards.
Corrected stale UI text claiming TrustTunnel was unintegrated; Hysteria2/Xray,
tray/startup/autoconnect remain explicitly unavailable. Local analyze and 118
Dart tests PASS, generated bundle and all 1594 pinned engine license bodies
verified, old GUI without native notices rejected. Actual updated Windows GUI
and package checks pending. Byte integrity is not legal/release approval.
Updated actual Windows GUI qualification **PASS** on `eefbcf7`,
[43887262100](https://github.com/pvlrdnv/liwetun-win/actions/runs/43887262100):
analyze, 118 Dart + 6 Rust + 3 desktop channel tests, release build/runtime staging,
all 60 native notice bodies and 1594 pinned engine sections present unchanged.
[Build evidence](evidence/windows-offline-notices-eefbcf7.json),
[notice byte receipt](evidence/notice-bytes-eefbcf7.json).
Truncated compressed notices also reject with a fixed error rather than a raw
traceback. Updated installer/package qualification with this GUI is pending.
Positive ordinary-mode regression after the refusal-branch extraction **PASS**
on `7ed30cd`, [43886214455](https://github.com/pvlrdnv/liwetun-win/actions/runs/43886214455):
exact DNS marker/transport and full network/WFP restoration retained.
Updated notice-aware package/installer qualification **PASS** on `17d66b6`,
[43888747188](https://github.com/pvlrdnv/liwetun-win/actions/runs/43888747188):
all 14 installer groups and the enclosing signed production-mode payload checks,
actual visible medium-integrity GUI / uninstall admission, installed notice-byte
checks, unchanged network and cleanup. GUI input was `eefbcf7` run 43887262100.
[Evidence](evidence/installer-notices-17d66b6.json). Signing remains ephemeral CI
only; no owner package, release/legal approval or Windows 10/11 qualification.
Prepared synthetic IPv6 client TCP/UDP production-mode cases. A fixed
documentation IPv6 destination is translated only inside the allowlisted CI
server fixture to its existing physical IPv4 HTTPS exit / private fixed echo.
Client sockets remain unbound, must select TUN IPv6 sources/routes, and require
exact IPv6 UDP echo markers and selected transport bytes. Generated profiles
explicitly enable IPv6. IPv4 DNS is reported separately; native IPv6 Internet
egress/DNS/leak/desktop qualification stays false. Seven local protocol tests,
Python syntax/YAML/diff checks PASS; Rust/Windows execution pending. No local
routes, drivers or owner network changes.
Synthetic IPv6 client TCP/UDP **PASS** on `4ffe672`:
[H2 43891393542](https://github.com/pvlrdnv/liwetun-win/actions/runs/43891393542),
[H3 43891403062](https://github.com/pvlrdnv/liwetun-win/actions/runs/43891403062).
Both selected TUN IPv6 routes/sources for unbound HTTPS and UDP; one exact echo
request/reply with 54 selected-transport bytes, plus the existing IPv4 DNS proof.
Full route/DNS/adapter/WFP restoration passed without watchdog intervention.
[H2 evidence](evidence/synthetic-ipv6-43891393542.json),
[H3 evidence](evidence/synthetic-ipv6-43891403062.json). This qualifies synthetic
client packet handling only; the exit translates to IPv4. Native IPv6 egress,
IPv6 DNS transport/leak policy and desktop acceptance remain open.
Added a separate SDK modification notice documenting the existing privacy/build
changes; the 60 original upstream notice bodies and generated UI bundle remain
unchanged. Integrity check PASS; this does not approve final distribution rights.
The pinned SDK's default adapter DNS list contains IPv4 resolver addresses even
for IPv6-capable profiles; this does not prevent IPv6 AAAA resolution. Added an
exact synthetic AAAA reply and separate per-query relay/transport proof to the
IPv6 cases, through that ordinary IPv4 DNS path. Require exact IPv6 answer,
TUN source, one marked exchange and at least 94 transport bytes. IPv6 DNS wire
transport remains unqualified. Seven local protocol checks and direct synthetic
DNS wire checks (A 49-byte / AAAA 61-byte responses) PASS; Python/diff checks PASS.
Actual updated H2/H3 IPv6+AAAA Windows cases pending.
Strengthened IPv6 + AAAA cases **PASS** on `a430ac9`:
[H2 43900021100](https://github.com/pvlrdnv/liwetun-win/actions/runs/43900021100),
[H3 43900031136](https://github.com/pvlrdnv/liwetun-win/actions/runs/43900031136).
Both delivered IPv6 HTTPS/UDP plus the exact AAAA answer through the ordinary
IPv4 DNS path; one marked AAAA request/reply and exactly 94 selected-transport
bytes, with complete network/WFP restoration and no watchdog intervention.
[H2 evidence](evidence/synthetic-aaaa-43900021100.json),
[H3 evidence](evidence/synthetic-aaaa-43900031136.json). Native IPv6 egress / DNS
wire transport and Windows 10/11 desktop qualification remain open.

The unchanged bounded regression on `f797465`,
[43859092186](https://github.com/pvlrdnv/liwetun-win/actions/runs/43859092186),
passed 18 service checks and all six H2/H3/DNS/auth/CA/UI-death/crash network cases
with final restoration. It does not establish ordinary-mode DNS or desktop readiness.

## Current stage

LOCAL development in independent private repository
https://github.com/pvlrdnv/liwetun-win, branch `feat/windows-mvp`.
LikeWeb repositories and production unchanged. No owner-machine service,
certificate, driver, DNS or route installation in this stage.

CONFIRMED: official SDK built successfully on Windows CI. Signed service and
real authenticated IPC passed security checks. Flutter start/query/stop channel
and honest uncertain-state UI implemented in `e201352`. Joint SDK/service acceptance passed 15 checks on disposable Windows CI.
Updated native application compilation and actual desktop-channel acceptance
also passed on disposable Windows CI. See [service architecture](WINDOWS_SERVICE.md).

## Implemented

- Flutter Windows shell with three screens, system themes and own SVG/ICO mark.
- TT direct/QR import through official Rust parser and real Windows
  C++ channel; restricted TLS VLESS/HY2 import, HTTPS subscription-source parsing.
  TLS bypass and unsupported embedded TT subscriptions are rejected.
- Strict proposed subscription snapshot parser/store: atomic complete/partial
  updates, revocation, expiry, replay/version/type/size checks. Bounded HTTPS refresh, protected cache and GUI reconciliation are implemented.
  LikeWeb API/export integration remains outside this repository.
- Typed sanitized protected journal (seven days/1000 events), preview and ZIP export. No raw
  core strings or destination logs. Unknown metrics remain unknown.
- Full upstream SDK build with pinned SDK/Common/DNS revisions and guarded raw
  logging/destination instrumentation suppression. Source and binary hashes plus
  resolved Conan recipe lock enforced and archived; notice candidates collected
  and source supplements pinned. Final notices audit remains open. Development
  DLL is not a release artifact.
- LocalSystem service with bounded authenticated IPC, owner SID/session/logon
  lease, signer/ACL/image checks and server PID verification before transmitting
  secrets. Original Wintun signature and pinned hash required.
- UI service worker channel, serialized requests and bounded polling; timeouts
  preserve uncertain state and allow stop. Old observations cannot overwrite a
  newer stop. Tunnel-ready label does not claim working Internet.

## Actual checks

- Pinned Flutter 3.38.10 / Dart 3.10.9; Rust 1.95.0 in Windows CI. Local tools
  under `/tmp` are ephemeral and do not establish Windows readiness.
- Earlier service-channel baseline: `flutter analyze --no-pub`: PASS.
  `flutter test --no-pub --reporter expanded`:
  **75 PASS**, including timeout/stop, stale observation, duplicate commands,
  late disposal and raw-error canaries. Flutter's local test socket requires
  running outside the filesystem sandbox.
- Earlier real Windows import channel: **6 Rust + 65 Dart + 1 desktop test PASS**,
  [run 43717022021](https://github.com/pvlrdnv/liwetun-win/actions/runs/43717022021).
- Full SDK compilation PASS,
  [run 43721746165](https://github.com/pvlrdnv/liwetun-win/actions/runs/43721746165).
- Real signed service installation/security/uninstall: **11 checks PASS**,
  [run 43724352857](https://github.com/pvlrdnv/liwetun-win/actions/runs/43724352857),
  [safe evidence](evidence/service-b81ce09.json). This run had no SDK.
- Real SDK/service: **15 checks PASS**, adapter created/removed, SDK state
  observed and clean stop, raw logging canary denied;
  [run 43726594305](https://github.com/pvlrdnv/liwetun-win/actions/runs/43726594305),
  [safe evidence](evidence/service-sdk-1d727e9.json). DNS/default routes unchanged
  in deliberately bounded no-global-routes mode. This proves no full-mode routing.
- Updated Windows release shell and real desktop import/service worker channels
  PASS: **6 Rust + 75 Dart + 1 desktop test**, analyze PASS;
  [run 43726801060](https://github.com/pvlrdnv/liwetun-win/actions/runs/43726801060),
  [safe build evidence](evidence/windows-service-channel-5adc6b6.json). The actual
  unsigned workspace app correctly rejects query/start/stop before service side
  effects. This is separate from the signed service/probe test, not an end-to-end
  installed signed GUI traffic test.
- After bounded pipe-wait changes, Windows app build, **75 Dart + 6 Rust + 1
  desktop test** passed again on `c6d188d`: [safe build evidence](evidence/windows-ipc-c6d188d.json).
- Earlier separate Windows CLI POC verified actual HTTP/2 data and wrong-auth /
  wrong-CA denial. Requested HTTP/3 used HTTP/2 fallback in that older environment; the newer
  bounded service tests above separately prove H3.
  [Network evidence](NATIVE_NETWORK_POC.md). This developer harness is not called
  by the app and does not establish application TUN acceptance.

## Remaining gates

The client is not release-ready. Unsigned workspace builds fail service admission;
no service is installed on the owner's computer. Protected storage and actual
GUI integration passed disposable Windows CI. The fresh installer prototype
passed only disposable CI with temporary signing. No release-signed
installer/updater, recovery/startup, tray desktop acceptance, live signed GUI traffic-metric acceptance, route-bound
health probes, kill switch or Hysteria2/Xray connection adapter.

UNKNOWN until tested: clean Windows 10/11 installed GUI and ordinary-mode traffic,
ordinary default routing/DNS/IPv6 and restoration in normal installed mode,
non-elevated UI, cross-session/fake-server negative controls, release revocation
policy and full license closure. CI no-global-routes mode cannot prove these.

No production connections, messages, panel calls, migrations or deployment.
`main` remains the initial local baseline; no direct push to main.
