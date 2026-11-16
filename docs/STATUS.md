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

- Flutter 3.38.10 / Dart 3.10.9, Rust 1.95.0 isolated under `/tmp` for local work.
- `flutter analyze --no-pub`: PASS. `flutter test --no-pub --reporter expanded`:
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
GUI integration passed disposable Windows CI. No signed
installer/updater, subscription fetch,
recovery/tray/startup, real metrics, route-bound
health probes, kill switch or Hysteria2/Xray connection adapter.

UNKNOWN until tested: clean Windows 10/11 installed GUI and ordinary-mode traffic,
ordinary default routing/DNS/IPv6 and restoration in normal installed mode,
non-elevated UI, cross-session/fake-server negative controls, release revocation
policy and full license closure. CI no-global-routes mode cannot prove these.

No production connections, messages, panel calls, migrations or deployment.
`main` remains the initial local baseline; no direct push to main.
