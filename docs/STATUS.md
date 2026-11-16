# Development checkpoint — 2026-11-16

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
  updates, revocation, expiry, replay/version/type/size checks. No live fetch or
  LikeWeb API changes; this store is not wired to GUI persistence.
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
installer/updater, subscription fetch,
recovery/tray/startup, real metrics, route-bound
health probes, kill switch or Hysteria2/Xray connection adapter.

UNKNOWN until tested: clean Windows 10/11 installed GUI and ordinary-mode traffic,
ordinary default routing/DNS/IPv6 and restoration in normal installed mode,
non-elevated UI, cross-session/fake-server negative controls, release revocation
policy and full license closure. CI no-global-routes mode cannot prove these.

No production connections, messages, panel calls, migrations or deployment.
`main` remains the initial local baseline; no direct push to main.
