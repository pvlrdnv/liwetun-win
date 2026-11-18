# Adapter ownership release gate

Status: unsafe adoption reproduced in bounded disposable CI (44255030943).
The service pre-existing-name refusal barrier is qualified on Windows CI for
visible and renamed aliases (44257822140 / 44257826925). Complete SDK ownership /
creation-race protection is not implemented.
The existing held-handle export proves attachment identity, not fresh creation
or authority to configure a pre-existing adapter. HTTPS endpoint correlation
does not close this independent release gate.

## Observed source behavior

Pinned SDK `a1ce3f9d2572e8c3fd6c31e6c31881d307131f40`,
`net/src/os_tunnel_win.cpp`, SHA256
`a6b529fc3159e816eb5e253bc3dc323eebec2ec0afa33d445b07c1f5252a8c04`:
`create_wintun_adapter` first opens an adapter by the configured name. Only when
that fails does it create one, deriving a deterministic requested GUID from the
name. Subsequent session setup assigns addresses using that returned handle.
Thus a successful open/held LUID/endpoint request is insufficient to establish
that LiWeTun created the configured adapter. This is source evidence; no foreign
adapter was reproduced or modified on the owner's device.

The pinned Wintun header separately describes close behavior for opened versus
created handles and permits a system-generated GUID when no GUID is requested.
Changing only the open call, checking only an alias before start or switching
only the GUID does not establish collision/race-safe ownership. The existing
duplicate-alias behavior source audit remains a constraint to test in CI.

## Required implementation boundary

Use a separate guarded SDK source profile and binary, with fresh per-attempt
adapter identity and explicit evidence from the actual create path before any
IP/DNS/route configuration. Do not adopt an adapter solely because its name,
GUID, type, address or current interface index looks expected. Alias absence
checks alone cannot authorize later mutation after a race.

Retain the exact created handle through configuration and teardown. A failed
start may release only that attempt's owned resources. Identity/ownership facts
must be fenced by the current SDK instance/epoch; a stale receipt cannot admit a
later adapter. Internal handles, identifiers and creation tokens remain private
and absent from GUI, diagnostics and owner reports. Unproved ownership refuses
configuration and health qualification.

Keep existing runtime pins and normal package admission unchanged until the
new profile's source/binary/ABI guards and required network regressions pass.
No owner-machine experiment, driver/service install, route/DNS/firewall or trust
change is authorized to investigate this gate.

## Disposable acceptance required

Preserve exact before/after configuration and retained identity of a separate
fixture-owned adapter while testing a pre-existing Wintun alias, a different
adapter type, a collision during creation and concurrent startup attempts.
Include create/configuration failure and Stop during startup. No foreign alias,
address, DNS, routes or adapter lifecycle may be changed; no foreign handle may
be adopted as an owned attachment. Export only closed success/refusal/cleanup
facts, never the interface identifiers used internally to validate preservation.

Then repeat ordinary routing/DNS restoration, service/lease failure, IPv6 and
owned HTTPS/path controls with the new SDK. Keep disposable Server 2022 evidence
separate from installed Windows 10 and Windows 11 acceptance. Trusted signing,
production health endpoint/revocation policy and independent DNS observation
remain additional gates.

## Reproduction fixture

The explicit `adapter_ownership_audit` network workflow mode uses the currently
pinned aggregate SDK with the existing NO_GLOBAL_ROUTES test mode ON and the
other service test flags OFF, on disposable CI. No global SDK routes or system
DNS changes are needed for this focused reproduction.
Its separate signed test client verifies the original Wintun hash, refuses any
existing task alias, creates one fixture adapter and retains its creation handle.
Before SDK start it verifies no non-link-local IPv4 and known fixture MTU/metric.

The observer requires actual IPv4/MTU/metric changes while the SDK is active,
then SDK teardown and continued access to that retained adapter before closing
the fixture's own handle. Only closed facts/counts are exported. The fixture
measures IPv4, MTU, metric and alias; it does not establish per-interface DNS or
route preservation. Its passing result means reproduction of unsafe adoption,
with ownership and release qualification explicitly false.

This helper is not linked into the installed GUI or service, exposes no new
service IPC operation, and refuses to run outside the explicit disposable CI
environment. Global network/WFP restoration after removal is independently
required. Real Windows compilation/reproduction is pending.

The first normal-routing attempt 44252986740 had no completed receipt and a
cancellation request; its outcome/cleanup are unqualified. Bounded-mode retries
include closed numeric parent/native checkpoints. They do not export OS errors,
addresses or adapter identity and cannot establish release readiness.

## Actual bounded result and first refusal barrier

[Run 44255030943](evidence/adapter-owner-reproduced-44255030943.json) reproduced
actual SDK changes to the fixture-owned adapter's IPv4, MTU and metric while its
original creation handle remained retained. Those changes persisted after SDK
Stop. The fixture then removed only its own adapter, with exact final network /
WFP restoration and no watchdog action. No global SDK routes or system DNS
changes were enabled in this experiment. Ownership qualification remains false.

The service now refuses an already occupied reserved visible alias, or an
unavailable/oversized interface-table read, before accepting Start and again
immediately before calling the SDK. Its checks are read-only; refusal uses the
existing typed CoreFailure reply. The fixture now requires this refusal with no
core-state observation, unchanged retained markers before/after Stop and zero
endpoint transport growth. Actual Windows refusal qualification is pending.

This is a partial mitigation. A visible alias is not the internal Wintun device
name used by the SDK, and the check/start interval is not atomic. These checks
do not authorize adoption, qualify a race or replace a fresh-identity SDK
factory. Existing SDK binaries/pins and normal ownership/release admission
remain unchanged until that independent work passes its required controls.

The refusal gate now also reads the internal Wintun name property used by its
open routine, using bounded read-only SetupAPI queries. The visible-name-only
weakness is being qualified with a fixture whose visible alias is renamed while
its creation handle and internal device name remain retained.
[Clean-host Windows API binding PASS](evidence/adapter-admission-contract-44256771327.json);
foreign-adapter and healthy-start qualification is pending.

Primary sources inspected for this gate:

- [Wintun original adapter create/open implementation](https://git.zx2c4.com/wintun/plain/api/adapter.c?h=0.14.1)
- [Read-only device property lookup](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdevicepropertyw)
- [Present device enumeration](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw)

The SDK factory check/start interval remains non-atomic. Pre-existing-name refusal
is a partial mitigation and is not fresh-creation or collision/race qualification.

## Qualified pre-existing-name refusal

On source `d3c75c1`, [visible and renamed-alias cases both PASS](evidence/adapter-name-refusal-44257822140.json).
Start returned CoreFailure before any observed core state or endpoint payload,
and the retained fixture's IPv4/MTU/metric/alias markers remained intact before
and after Stop. The fixture alone removed its own adapter. Exact network/WFP
restoration passed without watchdog action. The earlier transposed property-key
byte and its failed renamed case remain documented in STATUS.md.

[Healthy H2/H3 HTTPS regression PASS](evidence/adapter-guard-https-44257831987.json),
and [updated ordinary installer PASS](evidence/package-adapter-guard-44257841904.json)
with all seven test flags OFF. These confirm this service barrier's focused
behavior; they do not reclassify the original SDK factory as ownership-safe.

Next SDK work must provide fresh creation authority through configuration and
teardown, including internal recovery. The interval between these read-only
checks and SDK creation remains non-atomic. No complete ownership, creation-race,
desktop or release qualification is claimed.

## Isolated create-only candidate

The default-OFF `fresh_adapter` SDK profile now removes `WintunOpenAdapter` and
the name-derived GUID entirely. `CreateFresh` accepts no configured logical name;
the Windows binding supplies 32 bytes from the system-preferred
[BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
provider, split between a requested private GUID and a 128-bit opaque physical
alias. A bounded read-only interface-table scan refuses observed collisions or
unknown observations. The original signed Wintun DLL is unchanged.

Only the exact handle returned by Create is observed. Actual OS GUID, alias,
LUID and index must match before the SDK assigns addresses or starts a session.
On mismatch only that returned handle is closed. The retained per-instance
creation observation gates the existing private attached-interface getter;
teardown withdraws it before closing the handle. No new public IPC/GUI capability
or identifier diagnostics are added. A separate export identifies the build
policy only and cannot qualify an instance, epoch or network path.

This candidate is not admitted to the service or normal package. Full pinned
preparation and Python guards passed locally; Windows compilation, actual create
behavior and network controls are pending. Synthetic operation tests do not
establish real Wintun concurrency or cleanup. In particular the preflight is
non-atomic: original Wintun may rename a duplicate visible alias during Create.
An equal-privilege actor racing the exact random physical alias is not excluded
by a later handle-identity check. This limitation remains an open ownership gate;
do not reclassify random naming or a build marker as complete race protection.

Actual original-Wintun factory controls passed on disposable Server 2022
[44294660967](evidence/adapter-factory-44294660967.json), without SDK/session
startup: retained foreign logical-name adapter preserved, observed collision
refused, post-create refusal cleaned up and four concurrent created identities
distinct, with exact final adapter/route/DNS restoration.

The extended [44295089296](evidence/adapter-factory-race-44295089296.json) separately
passed alias-only and GUID-only observed-collision refusals, then reproduced the
remaining unsafe window. The helper inserts its own second adapter with the
exact physical alias but a different GUID **after** the real vacancy check and
before invoking original Wintun Create. Original Wintun renames that retained
foreign adapter; the newly returned handle still matches the candidate's expected
identity and is accepted. No session/IP/DNS/route configuration is needed to
reproduce this side effect. Both created handles are closed by their exact
owners; full adapter/route/DNS baseline restoration passed.

The fixture suite PASS records successful controls and reproduction, while
**creation-race safety FAILS**. The published
[0.14.1 adapter source](https://github.com/WireGuard/wintun/blob/0.14.1/api/adapter.c)
shows this duplicate-name handling inside `NciSetAdapterName`; the binary result
above is independent actual evidence for the pinned signed DLL. No source/binary
equivalence beyond those observed facts is assumed.

Adding another check immediately before Create just moves the unreserved window.
A process-local/global client mutex cannot serialize an unrelated adapter owner.
Detecting/repairing a rename afterward still permits the forbidden foreign
mutation and would require further unauthorized writes. Do not bypass signature
checks, patch the original DLL in memory/on disk or declare a random name an
atomic reservation. Keep this candidate outside normal runtime/service/package
admission while the create boundary is redesigned or an appropriate supported
API is qualified. No upstream issue/message has been sent on the owner's behalf.

## Policy 2: factory and SDK build qualified, network checks pending

Source inspection identified a refusal boundary in the pinned original API:
`NciSetAdapterName` formats the foreign suffix in a `MAX_ADAPTER_NAME` buffer
**before** calling the foreign rename. A valid maximum-length requested name
leaves no room for that suffix and should return an error first. This is a
specific original-binary behavior hypothesis, not a general Windows guarantee.

[Actual 44295841552 PASS](evidence/adapter-max-name-44295841552.json) confirmed
unique 127-character creation, alias-only collision refusal with retained
foreign configuration unchanged, and separately GUID-only collision refusal
with unchanged owner. Exact adapter/route/DNS restoration passed. This fixture
did not start an SDK/session; it also independently reproduced the old short
policy's unsafe race on the same original DLL.

The isolated SDK profile now uses policy 2: pad the opaque random alias to the
full 127 characters, statically assert the Windows header's limit, retain the
128-bit random alias component and independent requested GUID, and verify the
complete actual alias/GUID/LUID/index before configuration. Do not truncate the
physical alias for presentation or substitute another Wintun binary. Diagnostics
still export no identifiers. The build-policy export returns 2 and remains
insufficient for ownership/health admission.

The integrated factory test must refuse a separately inserted adapter **after**
preflight with its retained sample unchanged. An observed rename/accepted handle
now fails that test. Source preparation/Python guards pass. [Actual integrated
factory/native checks PASS](evidence/adapter-policy2-44296517432.json) on `ba80aa9`:
the exact post-preflight insertion is refused, retained alias unchanged, new
handle absent, and full adapter/route/DNS restoration verified. Full SDK
compilation/ABI **PASS 44296517605** on that same source;
[build/source/binary receipt](evidence/sdk-fresh2-44296517605.json). The default-OFF
network workflow selects a separate fresh runtime pin with all admission gates
closed and verifies its same-source factory receipt before use. Actual SDK
configuration/network checks are pending. Full ownership, SDK network/recovery/
Stop controls and desktop/release qualification remain open. Existing service
preflight and ordinary runtime pins/package are unchanged.

## Retained foreign fixture across actual SDK start/Stop

The separate default-OFF `preserved_adapter` network control holds a healthy
creator-owned adapter alongside fresh2 HTTPS traffic. Native samples compare its
IPv4/alias/MTU/metric; private parent snapshots compare DNS and non-link-local
routes without exporting identifiers. Link-local/multicast OS routes are excluded.
After Stop, fresh service queries plus SDK-adapter absence and WFP restoration
must settle before the fixture creator closes its own handle. Final global
baseline restoration remains required. Windows execution is pending.

This does not exercise active foreign traffic or disabled/problem devices.
Pinned Wintun global orphan cleanup behavior and general coexistence remain open;
the control cannot promote full ownership or package admission.
