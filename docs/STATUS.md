# Development checkpoint — 2026-11-18

## Latest checkpoint — service-owned HTTPS CI complete, release gates open

Focused service-owned TLS 1.2/HTTP qualification now passes **16 disposable
Server 2022 cases**: positive, wrong nonce, untrusted certificate, deadline,
receive cancellation, actual migration, actual epoch change and local bypass,
each over H2 and H3. [Aggregate receipt](evidence/owned-https-requalification.json)
links every immutable source/run/report with its SHA256. The separate 16-case
loopback TLS matrix also passed. **59 local Python fixture checks PASS**.

All live HTTPS cases use the same pinned owned-probe SDK binary. Valid replies
after migration/local delivery remain unqualified; changed epochs discard old
proof. H3 uses the explicitly modified diagnostic reader-wakeup endpoint, not
an inferred production server fix. The original endpoint's failed H3 no-reply
close controls remain [recorded](evidence/owned-probe-wakeup-44123761038.json).
Ordinary packaging still selects the prior aggregate SDK/GUI and requires all
**seven** test flags OFF; its 14 installer groups passed with temporary CI signing.

No public HTTPS/DNS capability, production endpoint, periodic health freshness,
owned-adapter admission or release package is enabled. Independent DNS correlation,
[adapter ownership](ADAPTER_OWNERSHIP.md), certificate/revocation bootstrap policy,
trusted signing/distribution and separate Windows 10/11 desktop acceptance remain
open. LikeWeb, production and the owner's corporate tunnel/network/trust remain
unchanged. No owner installation or testing action is needed for this CI stage.

## Current adapter ownership work

Actual unsafe adoption is **reproduced** on disposable CI 44255030943, source
`9e95c07`, using the pinned aggregate SDK 44038398682 with NO_GLOBAL_ROUTES=ON.
The separate fixture retained its creation handle while SDK changed IPv4, MTU
and metric on that same adapter. Changes remained after SDK Stop. Only the
fixture's own adapter was then removed; exact network/WFP restoration passed
without watchdog intervention. No identifiers, addresses or raw logs were
exported. [Closed evidence](evidence/adapter-owner-reproduced-44255030943.json).
This proves the release blocker; it does not qualify ownership safety.

The first normal-routing attempt 44252986740 ended cancelled without artifacts;
its reproduction and cleanup remain unqualified. The successful bounded audit
needed no global routes or system DNS changes. Closed numeric checkpoints
retained native and parent stages. Normal runtime/package pins remain unchanged.

A first service refusal barrier is now implemented: query the OS interface table
before accepting Start and again immediately before SDK start, refusing a
pre-existing reserved alias or failed/oversized/ambiguous observation. No existing
adapter is opened or configured by this gate. The existing typed CoreFailure
response is used; public IPC and GUI capabilities are unchanged. **59 local
Python fixture checks PASS**; syntax/YAML/diff PASS. Actual Windows refusal,
healthy H2/H3 regression and updated package qualification are pending.

This alias preflight is **not complete ownership or race protection**. An adapter
whose Wintun internal name differs from its visible alias and a creation race
remain SDK/factory work, with separate guards/binary/network qualification
required. Production HTTPS/DNS capability and ownership/release admission remain
false. LikeWeb and the owner's device/network/trust were not modified.

First service-barrier attempts on `8fdddb6` (44256254164 / 44256260395 /
44256266011 / 44256271476) stopped at compilation: the new translation unit
lacked explicit Winsock IP/NetIO declarations. [Closed receipt](evidence/adapter-admission-compile-44256254164.json).
No driver fixture/tunnel started in those attempts. Explicit headers are added,
and a fast standalone clean-host OS-binding check is added before further full
network/package runs. The refusal barrier is also extended read-only to the
internal Wintun device-name property, since renaming the visible alias alone
must not hide a pre-existing SDK open-by-name target. SetupAPI queries are
bounded and errors refuse Start; no adapter is opened, renamed or configured by
the production guard. API compilation/clean-host qualification is pending.

Read-only name admission OS binding/clean-host preflight **PASS** on Windows
(44256771327), source `a2ae82f`, with existing socket/HTTP/Schannel contracts.
No adapter/TUN or network configuration was created/changed by that contract.
[Receipt](evidence/adapter-admission-contract-44256771327.json).
The service checks both visible aliases and the internal Wintun device-name
property via bounded read-only SetupAPI enumeration. No Wintun open operation is
used by the gate. Absent properties on other network devices are expected;
failed/malformed/oversized observation refuses Start.

The existing-adapter fixture gains a `renamed` variant: CI renames only its own
retained adapter, confirms unchanged IP/MTU/metric markers, then requires Start
refusal even though the visible reserved alias is now absent. Only a closed
rename confirmation is exported. **60 local Python fixture checks PASS**;
Windows visible/renamed refusal, healthy H2/H3 and updated package runs pending.
Full fresh-identity/creation-race protection still requires SDK work; no ownership
or release gate is marked complete by this preflight.

On `a018801`, visible-alias refusal 44257161489, healthy service-owned HTTPS
H2/H3 44257179946 / 44257185247 and package 44257190700 PASS. Renamed fixture
44257171911 FAIL: its name rebase/markers were valid, but Start was accepted.
The guard's copied Wintun property GUID had a transposed byte (E7 instead of
7E), so its private-name lookup did not find the target. The byte is corrected
against the original Wintun source. [Original closed report](evidence/adapter-guard-renamed-44257171911-failed.json).
That failed case restored the final network baseline and did not trigger the
watchdog, but did not reach final WFP qualification. Current-source renamed /
visible refusal and healthy/package regressions are pending. Complete adapter
ownership/race qualification remains false.

## Health development record

Next negative prerequisite: `owned_probe_mode=wrong-nonce` now returns an exact
24-byte reply with a zero nonce, which cannot match the worker's nonzero token.
Its strict oracle requires 24 endpoint TX / 24 RX, same instance/epoch and
disarm, but no verified echo/success, no cancellation/deadline, unknown service
observations and remote EOF before Stop. The fixture records only closed totals
including an invalid-reply count; no token/frame is logged. No native worker,
SDK ABI/binary, service command or GUI capability changed. **35 local Python
checks**, Python/YAML and diff checks PASS. Actual Windows wrong-nonce controls
**PASS**, source `dae28a7`: H2/original endpoint 44130232049 (**514 ms**) and
H3/reader-wakeup fixture 44130231978 (**952 ms**). Both independently received
one deliberate bad reply, with flags 15 / TX 24 / RX 24, same epoch and disarm,
but `echo_verified=false`, `qualified=false` and unknown service observations.
Receiver EOF preceded Stop; route/DNS/adapter/WFP baselines restored without
watchdog action. [Closed reports](evidence/owned-probe-wrong-nonce-44130231978.json).

Shared-observer H3 deadline regression **PASS** (44130232830 attempt 2,
**4327 ms** total), preserving timeout/disarm, receiver EOF before Stop,
unknown service observations and complete network/WFP restoration. Attempt 1
failed while fetching the endpoint artifact with HTTP 503 egress-limit text,
before native/service tests; [closed infrastructure receipt](evidence/owned-probe-infrastructure-44130232830-attempt1.json).
Successful attempt-2 evidence was retrieved by exact artifact ID 14350141597;
name-only download had selected attempt 1. No raw logs or signed artifact URLs
were archived. No native SDK/producer/IPC/UI or production admission change;
HTTPS/DNS health and live bypass/migration negatives remain open.

The next live negative is actual per-flow migration without a global epoch
change. A fifth default-OFF flag `LIWETUN_TEST_OWNED_MIGRATION` requires owned
probe mode and enables the SDK's existing early TCP acknowledgement only on the
fixed synthetic port 38556. Initial temporary-upstream acceptance then migrates
to the actual endpoint on first payload. No SDK hook, ABI, binary or diagnostic
flag is injected/modified. Native producer remains unchanged. Its new oracle
requires a correct nonce response, same instance/epoch, disarm and SDK Migrated
flag 33, with null path counters, unsuccessful request and unknown service
observations. Receiver EOF before Stop and network/WFP cleanup remain mandatory.
Normal package guards now require all five CI flags OFF. **36 local Python
checks**, syntax/YAML and diff checks PASS; Windows migration and package
exclusion qualification pending. This does not substitute for actual bypass,
global state-epoch, HTTPS/DNS or desktop acceptance.

Actual migration negative **PASS** on source `7e4a7cf`: H2 44136295359 and H3
44136296127 (explicit reader-wakeup fixture). Both had correct echo and unchanged
instance/epoch, but actual SDK flags 33 / Migrated, null proof counters,
`qualified=false`, disarm and unknown service observations. Receiver EOF before
Stop and final network/WFP restoration passed without watchdog. Ordinary H2 echo
with migration flag OFF also PASS (44136295987).
[All reports](evidence/owned-probe-migration-44136295359.json).
Five-flag-OFF installer **PASS** (44136296788), 14 groups using the prior aggregate
SDK and GUI, with preserved four pinned input receipt hashes; no tunnel start,
ephemeral CI signing only. [Package receipt](evidence/package-migration-44136296788.json).

The next explicit `epoch-change` fixture restarts only its owned diagnostic
endpoint after a request is in flight. Worker report v3 adds a closed
`state_epoch_changed` fact observed from the actual SDK counter under the existing
lifetime lock, with no epoch IDs exported and no state/flag injection. Following
failed I/O it observes for at most 250 ms without holding that lock while waiting.
Changed epochs discard any armed/counted proof; endpoint loss must yield no
success and unknown service observations, with receiver EOF before Stop and
baseline network/WFP restoration. **37 local Python tests** and syntax/YAML/diff
checks PASS. Actual H2/H3 epoch change and v3 echo/migration regressions pending.
Direct bypass and application HTTPS/DNS health remain separate work.

Epoch-control source `01e1333`: H2 actual epoch change, H2 v3 echo and H3 v3
migration PASS (44138099788 / 44138099764 / 44138099965), with baseline/WFP
restoration. H3 abrupt two-second restart 44138099219 FAIL: it timed out while
its actual SDK epoch still matched the old request. It was not counted as an
epoch-change success; final route/DNS/adapter restoration passed without watchdog,
but the failed case did not reach its final WFP measurement.
[All original reports](evidence/owned-probe-epoch-abrupt-44138099219.json).
Source inspection confirms that the endpoint handles SIGINT with a graceful
shutdown sending an actual QUIC CONNECTION_CLOSE, whereas abrupt SIGTERM can
leave H3 loss detection pending. The epoch fixture now separately requests
`restart-graceful`, requires sending SIGINT to only its retained Popen child,
zero exit without forced kill, and a fresh child after the same two-second gap.
The ordinary abrupt recovery fixture is unchanged. Native producer, deadlines
and acceptance oracle are unchanged; focused H2/H3 graceful epoch controls pending.

Actual graceful endpoint shutdown epoch controls **PASS** on source `646bb1b`:
H2 44139888726 and H3 44139888789. Both native reports observed changed SDK epoch,
flags 129 / no armed facts or counts, no verified reply/success, explicit disarm,
unknown service observations, receiver EOF before Stop, and final network/WFP
restoration without watchdog. [Reports](evidence/owned-probe-epoch-graceful-44139888789.json).
This does not change the failed abrupt-H3 loss observation or its timing limits.

Prepared an explicit local direct-bypass control with a sixth default-OFF flag
`LIWETUN_TEST_OWNED_BYPASS`, incompatible with migration and requiring owned mode.
Only disposable CI binds a fresh exclusive TCP socket to an address verified
against the actual SDK-held interface, then connects to fixed loopback port
38557 without forcing the outgoing interface. No route/DNS/firewall/trust change
is added. The internal bounded IPv4 table read retains only that attachment's
unambiguous preferred address and exports no address/interface identifiers.
A Windows loopback-only receiver provides the exact nonce echo; the diagnostic
endpoint receiver must record no request/reply. The strict oracle requires armed
SDK flags 3 / no endpoint TX or RX, current epoch, valid reply but no successful
request, unknown service observations and remote EOF before Stop. This tests
outside-SDK local delivery, not a claim that the SDK recovery bypass upstream
was selected. All six CI flags must be OFF for packaging. **38 local Python
checks**, syntax/YAML and diff checks PASS; actual H2/H3 bypass, ordinary-echo
regression and six-flag package exclusion pending.

Local-bypass source `b8b3c42`: H2 44141143587 / H3 44141144365 both FAIL before
initial TCP connection (worker stage 2, zero receiver requests), not a qualified
bypass control. Ordinary H2 echo 44141144058 PASS. Final route/DNS/adapter cleanup
passed without watchdog; failed cases did not reach post-Stop WFP measurement.
[Original setup reports](evidence/owned-probe-bypass-setup-44141143587.json).
Six-flag-OFF installer 44141143337 PASS, 14 groups and preserved four source-input
digests with the prior aggregate SDK; no tunnel started, ephemeral signing only.
[Package receipt](evidence/package-bypass-44141143337.json).
Native CI report v4 now adds a closed socket-setup code (0..12), including source
query/layout/membership/ambiguity, bind, interface selection, connect/wait/status.
No raw OS error, address or interface identifier is emitted. No acceptance oracle
or destination changed; the precise setup failure remains pending live diagnosis.

Added a separate bounded HTTP nonce-response parser and reserved-host request
builder, not yet a TLS client. It caps headers/fields/body, handles arbitrary
fragmentation and binary nonce bytes, rejects redirects/ambiguity/cookies/
compression/incorrect replies/truncation, and returns only a closed enum.
[Candidate HTTPS contract](HEALTH_HTTPS_V1.md) records target/privacy/TLS boundaries
and official Microsoft references. Portable C++ security cases are added to the
Windows probe-contract workflow; local C++ compilation remains unavailable.
**38 local Python tests** PASS; HTTP C++ compilation/contract and v4 socket-setup
Windows diagnosis are pending. No production endpoint, TLS bypass or GUI health
capability is introduced.

HTTP framing MSVC/security contracts **PASS** (44143544601), source `a309430`:
all existing slot/socket contracts and new binary nonce, arbitrary fragmentation,
truncation, wrong response, limits, duplicate/ambiguous headers, redirect, cookie
and compression refusal cases. [Receipt](evidence/health-http-contract-44143544601.json).
No TLS handshake or application health claim.

Closed bypass diagnostic 44143544310 FAIL at socket setup code 7 / connect wait;
lookup and source bind were reached, but no connection/request was accepted.
[Original diagnostic](evidence/owned-probe-bypass-diagnostic-44143544310.json).
The local fixture now binds only the task adapter's one preferred IPv4, accepts
only a peer with that same address, and is released before SDK adapter teardown.
Native bypass connects to that same verified local address with fresh descriptors
retried only before arm inside the existing deadline. It no longer assumes
cross-interface delivery to 127.0.0.1 from the TUN source. No network policy,
routes, DNS, trust, SDK or acceptance criterion changed. **39 local Python tests**
PASS; same-address local bypass qualification pending.

Internal borrowed-socket Schannel candidate is implemented separately from the
service: TLS 1.2 only, automatic name/chain validation, strong crypto, no implicit
client certificate, cache-only revocation/chain retrieval, explicit leaf time
check, bounded wire/record processing and closed outcomes. No validation bypass
or trust-store write. Incomplete/extra input and terminal error handling are
implemented. Initial MSVC compile/no-network cancellation/deadline/name guards
are pending; real TLS/HTTP/path and TLS 1.3/graceful shutdown qualification remain
open. [Contract and primary references](HEALTH_HTTPS_V1.md). No UI/production
health capability is enabled.

Same-address local direct-bypass negative **PASS** on source `63f1fe2`: H2
44165060299 and H3 44165060099 with the original diagnostic endpoint. Correct
local echo and same epoch did not qualify the request: actual SDK flags 3,
TX/RX zero, explicit disarm and unknown service observations. The endpoint
receiver saw no payload; local receiver EOF preceded Stop. Route/DNS/adapter/WFP
restoration passed without watchdog action. [Closed reports](evidence/owned-probe-local-bypass-44165060099.json).
This qualifies local delivery outside the SDK, not SDK recovery bypass selection.

Schannel MSVC compilation and no-network cancellation/deadline/name guards
**PASS** (44165060837), retaining HTTP and socket/slot contracts.
[Receipt](evidence/health-schannel-contract-44165060837.json). This is not a TLS
handshake result. Added a separate disposable-CI loopback TLS 1.2 fixture with
real automatic validation, nonce HTTP exchange/fragmentation, wrong nonce,
redirect/header limits, wrong name, untrusted/expired certificates, missing
revocation information, deadline and cancellation controls. Temporary fixture
roots are CI-only and must be removed by exact certificate identity; private
keys/certificates are never uploaded. Local synthetic certificate generation
PASS without trust changes. Actual Windows handshake matrix pending. No SDK,
service command, public IPC, GUI or release capability is enabled by this fixture.

Initial real TLS matrix 44167373258 on `628aea1` **FAIL**, with exact temporary
root removal. Real valid/fragmented HTTPS, bad nonce, redirect/header limits and
wrong-name/untrusted/expired certificate controls passed. The non-root leaf
without revocation information was unexpectedly accepted by automatic Schannel
validation despite its revocation flags; no application capability is enabled.
[Original report](evidence/health-tls-revocation-44167373258.json).
The candidate now additionally builds a local-machine chain with cache-only URL
and revocation lookup, root auto-update disabled, required server-auth usage and
zero tolerated chain errors. Unknown/offline/revoked status refuses HTTP before
any application request. Automatic Schannel name/chain validation remains ON.
Certificate controls now require their specific closed refusal codes rather than
any generic TLS rejection. Windows matrix rerun pending.

Explicit chain-only run 44167719737 on `a19d493` also **FAIL** at the same
missing-revocation control; temporary roots were removed. The fixture leaf is
self-issued (same issuer/subject name) but signed by a different trusted key.
A zero chain error mask was insufficient for the intended strict policy.
[Unchanged oracle report](evidence/health-tls-chain-44167719737.json).
The candidate now additionally requires explicit cache-only CertVerifyRevocation
success for each non-root certificate in the verified chain. CI adds a distinct
synthetic CA, fresh CRL, valid issued leaf and actually revoked issued leaf to
check both acceptance and refusal; only the fixture's exact CRL context is added
and deleted in disposable CI. Local CA/CRL generation and OpenSSL positive CRL
verification PASS. Windows attempt 44168154406 stopped at compilation: an unsupported symbolic
status constant was referenced; it is removed. No TLS fixture/root installation
ran in that attempt. Expanded Windows matrix rerun pending.

Expanded real TLS 1.2 loopback matrix **13/13 PASS** (44168412480), source
`0f9fc50`: valid/fragmented response, wrong nonce, redirect/header limits,
wrong name, untrusted/expired certificate, missing revocation information,
valid issued certificate with cached CRL, actually revoked certificate,
deadline (**4030 ms**) and receive cancellation (**219 ms**). Certificate negatives
returned their exact closed category and sent no HTTP request. All fixture
receivers ended and temporary roots were removed; the owned CRL deletion also
succeeded. [Report and source digests](evidence/health-tls-44168412480.json).
This is loopback Server 2022 evidence without SDK/TUN, not SDK-owned HTTPS,
Windows 10/11 acceptance, production certificate policy or release qualification.
The missing-revocation failures and compile-only failure remain documented.

DNS source analysis is recorded separately in [HEALTH_DNS_V1.md](HEALTH_DNS_V1.md):
the current socket ABI does not correlate Windows resolver traffic through the
SDK DNS proxy/rewrites. A direct DNS/DoH request cannot qualify the normal
Windows resolver. No DNS health UI/IPC capability is enabled.

Additional TLS-only controls now require refusal of a server demanding a client
certificate, refusal of a TLS-1.3-only server by the explicitly TLS-1.2 candidate,
and rejection of a truncated encrypted HTTP body. These extend the fixture only;
Windows execution pending. The 13-case successful receipt remains immutable.

Extended attempt 44168984358 on `fd2c8a7` stopped at the required-client-cert
control: the client correctly refused the handshake and sent no HTTP, but the
fixture expected only a local credential-request category. Windows returned the
closed generic TLS rejection, consistent with the peer terminating via a fatal
TLS alert. [Original report](evidence/health-tls-client-auth-44168984358.json).
The oracle now accepts either explicit client-credential refusal or generic TLS
refusal for this known server fixture, with independently failed server handshake
and zero HTTP/body still mandatory. The diagnostic is not relabeled as a known
client-auth cause. All certificate-category controls remain exact. No Schannel
code/policy changed. Contract regression 44168991601 PASS; extended rerun pending.

Extended TLS matrix **16/16 PASS** (44169309801), source `f64b6ec`:
all previous controls plus required-client-certificate refusal (generic TLS
rejection, not a fabricated client-auth diagnosis), TLS-1.3-only peer refusal
and truncated body refusal. Deadline **4016 ms**, receive cancellation **218 ms**.
All receivers ended; exact temporary root absence and owned CRL deletion passed.
[Full closed evidence/source digests](evidence/health-tls-44169309801.json).
Schannel/HTTP/socket/slot contract regression also **PASS** (44168991601),
[receipt](evidence/health-schannel-contract-44168991601.json). Local synthetic
receiver regression **14 tests PASS** outside the socket-restricting sandbox;
Python/YAML and diff checks PASS. No Flutter or shipped-service behavior changed.

Next implementation: execute the qualified TLS/HTTP exchange on the service's
fresh exclusive owned socket, arm before TLS I/O, require exact SDK path proof
plus current instance/epoch/deadline and disarm before socket close. Qualify
positive and negative controls on disposable CI before any public health DTO or
UI capability admission. DNS correlation remains a separate guarded SDK task.
Release certificate/revocation bootstrap policy, adapter ownership, trusted
signing/distribution and separate desktop Windows 10/11 acceptance remain open.

Implemented a seventh default-OFF CI mode `LIWETUN_TEST_OWNED_HTTPS` requiring
the owned socket/attachment profiles and excluding migration/local-bypass modes.
It performs the qualified reserved-host TLS/HTTP exchange after arm on the exact
fresh exclusive descriptor, then requires the same instance/epoch, deadline,
matching SDK endpoint TX/RX covering the actual TLS wire bytes, and disarm before
close. A separate bounded typed HTTPS receipt is produced; no public command,
GUI capability or production endpoint is enabled. Raw-path report v4 is retained
and continues to make no DNS/Internet/HTTPS claim by itself.

Disposable fixtures provide good HTTPS, wrong nonce, untrusted certificate,
missing-response deadline and Stop during receive. The good leaf is issued by
a synthetic CA with a cached fresh CRL; only CI adds/removes those exact owned
trust objects. All seven test flags must be OFF in the ordinary installer;
its SDK/GUI pins remain unchanged. **44 local Python checks PASS**, including
closed-report tampering, TLS failure/path/epoch/disarm mismatch and a real
loopback TLS receiver after the empty nonexclusive control. Python/YAML and diff
checks PASS. Actual Windows service compilation, SDK-owned HTTPS/path controls
and seven-flag-OFF packaging are pending. No owner-device network/trust changes.

Initial owned-HTTPS run 44172890209 on `9a3c420` failed before any network or
fixture trust installation: the service's own `security.h` include directory
shadowed the Windows SSPI wrapper used by the previously standalone TLS test.
The TLS header now directly includes the platform `sspi.h`; policy/validation
remain unchanged. [Closed compile receipt](evidence/owned-https-compile-44172890209.json).
Actual Windows compilation/HTTPS matrix reruns pending. The independent normal
package run continues with the seventh test mode OFF.

Service-owned HTTPS positive **PASS** on source `54533da5`: H2 44173333723 and
H3 44173344152 (explicit reader-wakeup diagnostic endpoint). Both verified TLS
1.2, CA/CRL, exact nonce HTTP reply, actual SDK flags 15, unchanged instance/epoch
and explicit disarm. SDK endpoint bytes exactly matched this socket's TLS wire:
**497 TX / 1703 RX**, including handshake/record framing, not HTTP payload totals.
Receivers observed owner EOF before Stop. Network/DNS/adapter/WFP baselines and
exact fixture-root cleanup passed without watchdog intervention.
[Positive evidence](evidence/owned-https-positive-44173333723.json).
This qualifies a synthetic CI request, not production HTTPS/DNS health, periodic
freshness or desktop readiness. H2/H3 wrong nonce, untrusted certificate,
deadline and receive cancellation controls plus the old raw-echo regression are
running against that same immutable source; no public capability is admitted.

Seven-flag-OFF ordinary installer **PASS** (44172896138), source `9a3c420`:
14 installer groups, common ephemeral signer for owned components, original
Wintun bytes, actual medium-integrity GUI, rollback/removal, unchanged network
and cleanup. Prior aggregate SDK 44038398682 and GUI 44073703263 remain selected;
all four pinned receipt digests were independently compared and preserved.
[Package receipt](evidence/package-https-44172896138.json). No tunnel started and
no owner-installable/trusted-release package was produced.

H2/H3 wrong-nonce and deadline controls passed on `54533da5`; evidence is being
collected. The first untrusted controls 44173662102 / 44173690152 correctly
returned ChainRejected with zero HTTP, current epoch, exact SDK wire proof and
disarm, but the observer checked the independent server failure before it had
arrived. It now waits boundedly for that fact, preserving the same oracle.
First receive-cancel controls 44173674795 / 44173704262 had native Cancelled /
explicit disarm, but the harness sent a traffic command after Stop had exited
its owned child. A buffered broken-pipe close then aborted finally and overwrote
the detailed receipt. Those cases have no qualified final WFP/root-cleanup
measurement and are not counted as passing. [Original reports](evidence/owned-https-harness-44173662102.json).

The cancellation observer now keeps its unknown-before-Stop observation and
never queries that child after Stop; the owner child is then closed once.
Broken-pipe stream close cannot skip remaining cleanup. A nested finally always
attempts exact HTTPS-root removal and writes the original closed result even
if another cleanup step fails. No native SDK/TLS/worker, deadline or security
policy changed. **47 local Python tests PASS**, including both reproduced harness
races and cleanup regression; syntax/diff checks PASS. Focused Windows reruns
pending. Positive HTTPS and seven-flag-OFF package evidence remains unchanged.

H2/H3 wrong-nonce and missing-response controls **PASS** on `54533da5`:
wrong nonce 44173655030 / 44173682426, deadline 44173669135 (**4655 ms**) /
44173697967 (**4562 ms**), plus original raw H2 echo 44173811153. TLS/path
success alone never admitted a wrong nonce or missing HTTP response. Negatives
kept service observations unknown; receiver EOF preceded Stop. Network/WFP and
exact fixture-root restoration passed without watchdog intervention.
[All closed reports](evidence/owned-https-negatives-44173655030.json).

Prepared HTTPS-specific actual migration and epoch-change controls without any
SDK/ABI/binary change. `https-migration` combines the seventh CI flag with the
existing default-OFF early-ack migration fixture; it requires verified TLS/HTTP
reply and unchanged global epoch but actual SDK Migrated flag 33, null path
counts and no qualified success. `https-epoch-change` withholds HTTP after the
handshake and gracefully restarts only the owned endpoint; it requires actual
changed SDK epoch, discarded proof, no reply/success and EOF before Stop.
No state/diagnostic flags are injected. **49 local Python checks PASS**, including
valid HTTPS after migration remaining unqualified and timeout not substituting
for changed epoch. Python/YAML/diff PASS; actual Windows controls pending.
All seven test flags remain excluded from ordinary packaging; no UI admission.

Corrected HTTPS certificate/cancellation controls **PASS** on `e65f009`:
H2 untrusted 44174701000 (**593 ms**) / H3 44174715707 (**718 ms**), with exact
ChainRejected and zero HTTP; H2 cancellation 44174707965 (**250 ms**) / H3
44174721432 (**108 ms**) for Stop through worker receipt/remote EOF. Native
Cancelled/disarm and unknown-before-Stop observations passed. Network/WFP,
exact fixture-root removal and no-watchdog checks passed in every case.
[All reports](evidence/owned-https-cert-cancel-44174701000.json).

HTTPS actual epoch invalidation **PASS** on `59b9d9d`: H2 44175156195 and H3
44175176414. Each had a verified TLS handshake and HTTP request in flight, then
only its owned endpoint was gracefully restarted. Native code observed changed
SDK epoch, flags 129/null proof counters, no verified response/success and
explicit disarm; EOF before Stop, unknown observations, network/WFP and fixture
trust restoration passed without watchdog action. The reported 15 ms is the
observer interval after the two-second restart command, not total restart time.
[Evidence](evidence/owned-https-epoch-44175156195.json).

First HTTPS migration controls 44175147739 / 44175166900 had the desired actual
SDK Migrated flag 33 / null counters, correct verified HTTPS, unchanged global
epoch, disarm and no qualified success. The harness incorrectly required an
empty TCP control at the endpoint, although early-ack kept that no-payload socket
entirely on the temporary upstream. The migration oracle now requires exactly
zero empty endpoint controls; other modes still require one. Native refusal
criteria are unchanged. These failed cases restored network/trust but did not
reach final WFP measurement. [Original reports](evidence/owned-https-migration-observer-44175147739.json).

Added `https-bypass` using the existing default-OFF local-bypass flag. Only CI
binds TLS on the actual task attachment's preferred address and accepts peers
with that same address; native arm/TLS/HTTP use that same source/local peer.
A valid HTTPS reply must still be rejected as path evidence: actual SDK flags 3,
zero endpoint bytes, unchanged epoch/disarm and unknown service observations.
The endpoint receiver must see zero payload. This tests local delivery outside
SDK, not SDK recovery bypass upstream selection. **51 local Python checks PASS**;
Windows migration reruns and TLS local-bypass controls pending. All seven flags
remain excluded from the ordinary package. No production/UI capability enabled.

HTTPS migration and local-bypass controls **PASS** on `1c19fe4`: H2 migration
44175923679 / H3 44175937890 had verified HTTPS and unchanged epoch, but actual
SDK Migrated flag 33/null counters and no qualification. H2 local bypass
44175931357 / H3 44175945743 had verified local HTTPS, unchanged epoch and actual
flags 3/zero endpoint TX/RX, with no qualified success and zero endpoint payload.
All disarmed before close; receiver EOF preceded Stop. Network/WFP and exact
fixture-root cleanup passed without watchdog action.
[Full reports](evidence/owned-https-dynamic-44175923679.json).

The [aggregate HTTPS receipt](evidence/owned-https-requalification.json) verifies
all 16 mode/transport pairs, their individual source commits, full receipt hashes,
identical SDK DLL digests, positive-only qualification and cleanup. The private
SDK manifest now records only this focused CI fact; its binary/source pins,
full-network/release/DNS/desktop booleans and normal service/package exclusion
are unchanged. This one-startup-request fixture does not establish production
health/freshness or SDK recovery bypass selection. No new public IPC/UI behavior.

A [source-grounded adapter ownership gate](ADAPTER_OWNERSHIP.md) records why the
current open-by-name/fixed-GUID SDK path cannot prove fresh ownership, and the
required separate guarded profile and disposable foreign-adapter/race checks.
It is not an implemented fix or an owner-device reproduction. This gate remains
open independently of successful endpoint TLS/path correlation.

## Development evidence and history

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
YAML/Python/diff checks PASS. Initial live H2/H3 producer and four-flag package
exclusion were then qualified as recorded below; cancellation has its separate
follow-up. This is raw synthetic TCP path qualification, not an application
HTTPS/DNS/Internet check or release.

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
actual Windows cancellation qualification is pending. A teardown audit then
found that withdrawing the borrowed core before joining the cancelled worker
could skip explicit token disarm. In the CI-only mode the worker now cancels,
disarms and joins before pointer withdrawal and SDK teardown, with no core mutex
held over join. The cancellation oracle now requires disarm too; 29 local Python
tests remain PASS. Earlier dispatched runs retain the weaker criterion and must
not be used to qualify this strengthened contract. Live bypass/migration negative
controls and product health integration remain open.

Historical cancellation source `8af8a99`: H2 44115411641 passed its earlier
criterion (16 ms Stop ACK / 172 ms receipt and remote EOF), but explicitly
reported `disarmed=false`; H3 44115410946 failed the fixture's two-second pending
request wait. Both final network cleanups passed without watchdog action.
[Both original reports](evidence/owned-probe-cancel-pre-fix-44115410946.json).
Neither qualifies the strengthened cancellation/disarm contract. After the
teardown fix, the CI-only socket worker now also reports a closed
`receive_cancelled` boolean from a typed I/O outcome, distinguishing cancellation
from deadline/failure. Bootstrap gets its own bounded 10 s wait; the controller
still requires no completed receipt before Stop, native receive cancellation,
explicit disarm, unknown counters, remote EOF, and Stop-to-completion below 1.5 s.
This avoids treating slow H3 connection preparation as a failed Stop or counting
a deadline expiry as cancellation. **29 Python tests PASS**; updated Windows
positive and cancellation qualification remains pending.

Updated positive H2/H3 and explicit receive-cancellation H2/H3 **PASS**, source
`1e7a579`: echo 44116428495 / 44116424941; cancellation 44117119550 / 44116425320.
Cancellation receipts require `receive_cancelled=true`, disarm, no reply, null
counters and remote EOF: **203 ms H2 / 250 ms H3** from Stop to receipt and close.
All four cases restored routes/DNS/adapter/WFP without watchdog action. H3
preparation took about 2.5 s, separately from its 250 ms Stop budget. The failed
H2 attempt 44116428194 stopped at endpoint UDP preflight (no response frame,
zero forwarded UDP), before tunnel/owned probe start; it remains archived.
[All five reports](evidence/owned-probe-outcomes-44116424941.json).
[Intermediate disarm reports](evidence/owned-probe-cancel-disarm-44115760730.json)
retain H2's 187 ms explicit disarm and the old H3 preparation-bound failure.
The separate probe runtime pin references the expanded focused CI receipt; full
network matrix, live bypass/migration negatives, normal service/package admission,
application HTTPS/DNS health, Windows 10/11 and release gates remain open.

Added a third CI-only `owned_probe_mode=deadline`: the receiver withholds all
response bytes until the worker's own 4 s I/O deadline, without an earlier Stop.
The closed worker report is now schema v2 with distinct receive-cancelled and
receive-timed-out booleans. Its strict negative oracle requires deadline (not
cancel/failure), same SDK epoch, exact 24 endpoint TX / 0 RX, no echo/success,
explicit disarm and remote EOF. Service observations must remain unknown; only
then does the harness Stop and check baseline network/WFP restoration. Existing
positive/cancel oracles refuse the new timeout fact. **30 local Python tests**,
Python/YAML/diff checks PASS; live deadline and schema-v2 regression are pending.
No SDK binary/profile/ABI or normal product probe capability changed.

Schema-v2 H2 echo **PASS** (44118196073), H3 cancellation **PASS**
(44118195424, 217 ms Stop-to-worker/EOF), and H2 receive deadline **PASS**
(44118196493, 4750 ms total including preparation). Deadline receipt has 24 TX /
0 RX, same epoch, explicit disarm, `receive_timed_out=true`, no cancellation or
echo, unknown service observations and receiver EOF before Stop; final
network/WFP restoration passed without watchdog action. H3 deadline **FAIL**
(44118196741): the native receipt had the expected timeout/disarm/24 TX / 0 RX
facts, but the full deadline observer did not qualify. Its first observer did
not retain last receiver facts, so the exact missing observation is unknown.
[All four original reports](evidence/owned-probe-deadline-44118196493.json).
The observer now retains only closed receiver totals, validated worker fields
and elapsed time, plus receiver totals after Stop and before fixture shutdown.
No oracle/timeout/routing/SDK behavior changed; focused H3 diagnostic pending.
H3 deadline remains unqualified until the full criterion passes. The receiver now
also records TCP `ConnectionResetError` in a separate closed `owner_reset` count;
it still does not qualify the EOF-only oracle. A real loopback SO_LINGER reset
check distinguishes reset from EOF without sending a response; **31 local Python
tests PASS**. Pinned H3 source uses stream reset on connection close, suggesting
an observer gap, but no live reset finding is established until CI observes it.
No SDK/routing behavior or acceptance criterion was changed.

Focused H3 deadline diagnostics 44119165669 / 44119407694 both **FAIL** the
unchanged criterion. At about 7983 ms the receiver was still waiting, with no
EOF and no reset; after Stop it recorded EOF. Native timeout/disarm/24 TX / 0 RX
facts were correct and never became success. [Both reports](evidence/owned-probe-deadline-open-44119407694.json).
The reset-only observer hypothesis is therefore not supported by these runs.
The CI-owned socket now uses abortive SO_LINGER(1,0) close for no-payload refusal
controls and failed/expired requests, after matching-token disarm; successful
exchanges retain ordinary close. This targets the half-open failed request,
without changing SDK/core routing or ordinary application traffic. Remote EOF
before Stop is still required; no acceptance budget was relaxed. Live H2/H3
deadline and echo/cancel regressions of this change are pending.

Abortive close experiment source `00125e2`: H2 deadline, H2 echo and H3 cancel
PASS, but H3 deadline 44120128489 **FAIL**, again with the receiver waiting and
no EOF/reset before Stop. [All four reports](evidence/owned-probe-abort-experiment-44120128489.json).
The ineffective native change was removed; the producer is byte-for-byte back
to its previously tested `8e23ec5` schema-v2 source.

Exact archived endpoint source (`fab5b835`) inspection found that its H3 Close
event shuts down the read side without waking a StreamSource parked on the
readable channel. Finished and Reset both map to Close; the write side retains
the stream/sender. This is a candidate explanation for the observed waiting
receiver, not yet a demonstrated live fix. A separately opt-in
`stream_close_fix=true` endpoint workflow now adds one readable notification
before the existing read shutdown. One exact input/output source digest and
all replacement anchors guard preparation; normal fixture defaults/pins are
unchanged. Production server/source repositories are untouched. Exact archived
source preparation, new no-mutation/reapply guards, **33 Python tests** and YAML
checks PASS. Candidate build/live differential qualification is pending; it
cannot silently replace the existing diagnostic endpoint pin.

Endpoint reader-wakeup candidate build **PASS** (44121575608), source `1303d20`:
full Linux release endpoint and two authenticated UDP flows, without SDK/TUN.
Downloaded binary SHA256, original archive/SOCKS5 patch provenance, wakeup input
manifest and output-source digests all verified. [Build receipt](evidence/endpoint-wakeup-build-44121575608.json).
Separate `endpoint-runtime-close.json` pins it as build/UDP-only. Windows selection
requires explicit `endpoint_stream_close=true`, the exact successful build/head,
binary/provenance hashes, wakeup manifest/output hashes and focused owned-probe
mode; the original endpoint pin/default remains unchanged. No production server
change. Live H2/H3 deadline and H3 echo/cancel differential qualification pending.
Binary retention expires 2026-12-01 16:11 UTC; safe UDP evidence 2026-11-24.

Explicit endpoint wakeup differential on source `520f9a5`: **all four Windows
cases PASS** — H2 deadline 44123761280 (**4217 ms** total), H3 deadline 44123765703
(**4359 ms**), H3 echo 44123761038 and H3 cancellation 44123761323 (**234 ms**
Stop-to-worker/EOF). Both missing-response cases satisfied the unchanged oracle:
24 endpoint TX / 0 RX, native receive timeout (not cancel), disarm, no success,
unknown service observations, remote EOF before Stop. All restored routes/DNS/
adapter/WFP without watchdog action. [Reports](evidence/owned-probe-wakeup-44123761038.json).
The producer matches the pre-experiment 8e23ec5 file byte-for-byte, and the SDK
binary is unchanged; only the explicit diagnostic endpoint candidate differs.
Its separate runtime pin now records this narrow qualification. The original
endpoint's H3 deadline remains unqualified; no production server readiness,
application HTTPS/DNS health, normal package/service admission or desktop claim.
Same-commit original-endpoint controls completed: H2 echo 44124581043 PASS;
H3 deadline 44124576722 repeats the expected failure, with receiver still waiting
and no EOF/reset at 7984 ms, then EOF after Stop. Both final route/DNS/adapter
restorations passed without watchdog action. The failed case did not reach its
post-Stop WFP observation; it is not claimed as a WFP-qualified case. The four
candidate-fixture cases did measure and restore WFP. All six reports are in the
same comparison receipt. This supports the missing-reader-wakeup explanation in
the diagnostic endpoint; no extrapolation to a production server version.

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
