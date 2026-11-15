# Development checkpoint — 2026-11-15

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

## Protected-storage continuation — starting

Next: current-user Windows DPAPI, private per-user ACLs, encrypted atomic storage,
strict bounded profile snapshots and honest load/save failure handling. Profiles
are still memory-only until that code and actual Windows checks pass.

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
- In-memory TT direct/QR import through official Rust parser and real Windows
  C++ channel; restricted TLS VLESS/HY2 import, HTTPS subscription-source parsing.
  TLS bypass and unsupported embedded TT subscriptions are rejected.
- Strict proposed subscription snapshot parser/store: atomic complete/partial
  updates, revocation, expiry, replay/version/type/size checks. No live fetch or
  LikeWeb API changes; this store is not wired to GUI persistence.
- Typed sanitized memory journal (1000 events), preview and ZIP export. No raw
  core strings or destination logs. Unknown metrics remain unknown.
- Full upstream SDK build with pinned SDK/Common/DNS revisions and guarded raw
  logging/destination instrumentation suppression. Source and binary hashes plus
  resolved Conan recipe lock archived; input lock enforcement and full notices
  inventory still open. Development DLL is not a release artifact.
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
no service is installed on the owner's computer. Imported secrets disappear on
exit. No protected storage, signed installer/updater, subscription fetch,
recovery/tray/startup, persistent rotated journal, real metrics, route-bound
health probes, kill switch or Hysteria2/Xray connection adapter.

UNKNOWN until tested: clean Windows 10/11 installed GUI and ordinary-mode traffic,
ordinary default routing/DNS/IPv6 and restoration in normal installed mode,
non-elevated UI, cross-session/fake-server negative controls, release revocation
policy and full license closure. CI no-global-routes mode cannot prove these.

No production connections, messages, panel calls, migrations or deployment.
`main` remains the initial local baseline; no direct push to main.
