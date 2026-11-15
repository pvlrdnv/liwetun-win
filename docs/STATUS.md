# Development checkpoint — 2026-11-15

## Current native stage — verified import, partial network qualification

Owner authorized the next native stage. Added official-parser Rust staticlib,
bounded C ABI, Windows C++/Dart method channel and native rejection handling in
UI. SDK/parser source revisions and Cargo.lock pinned; Apache license retained.
Added Rust tests, desktop integration test and manual disposable-Windows CI.
Windows build and real C++ channel integration PASS on source `4916f51`:
6 Rust tests, 65 Dart tests, 1 desktop integration test, analyze and compilation.
CI: https://github.com/pvlrdnv/liwetun-win/actions/runs/43717022021
Evidence: [Windows build](evidence/windows-import-4916f51.json).

Separate actual Windows CLI/local-endpoint test: HTTP/2 data path and negative
auth/custom-CA controls verified. Requested HTTP/3 delivered through HTTP/2
fallback; native HTTP/3 network qualification remains OPEN. Harness exit 2
means partial qualification, not a successful HTTP/3 test. This is not a mock.
Evidence: [network POC](NATIVE_NETWORK_POC.md) and
[raw safe result](evidence/local-network-261115.json).

This bridge cannot connect a tunnel from the UI. The CLI experiment is a separate
developer test and is not shipped or called by the application.
See [native integration boundaries](NATIVE_IMPORT.md).

Scope: LOCAL client development only. Product LiWeTun; GitHub description
`LiWeTun — Windows connection client`. Independent private repository:
https://github.com/pvlrdnv/liwetun-win

## Implemented and locally verified

- Flutter Windows runner, three-screen desktop shell with responsive navigation,
  OS light/dark themes, native title, original SVG/code-native mark and multi-size
  Windows ICO. No dependency on another GUI client.
- In-memory import of TT direct/QR carriers, a restricted TLS VLESS/HY2 URI
  subset, HTTPS subscription sources; duplicate QR/direct collapse. Input is
  obscured. Error messages do not echo input. Windows uses the official binary
  parser through Rust/C++ for TT import; TLS-bypass, malformed or unsupported
  embedded-subscription links are rejected. Without a native plugin, links stay
  explicitly unvalidated. Parsed data is not a verified working connection.
- Proposed strict JSON subscription parser and atomic per-subscription store:
  complete/partial, explicit denial/revocation, expiry, unknown versions, replay,
  duplicate/conflicting IDs, type/date validation and 1MiB input limit.
  Omitted profiles in partial snapshots keep their old expiry.
  This model is tested in isolation; no server feed or HTTP client is wired.
- Closed typed diagnostic events, maximum 1000 in-memory events, clear action,
  ZIP generation and explicit export preview/file selection. No free-form
  exception/core-output string is accepted by the journal API. No upload.
- Counter observation classifier distinguishes unknown, idle, outgoing without
  reply, and RX growth. It is not attached to real metrics or used to claim a
  working tunnel. The app runs no direct-network probes; the separate developer
  harness described above probes only its own synthetic local origin.

## Actual checks

Environment: Linux/WSL, Flutter 3.38.10 at
`c6f67dede3d4aa1aa7a69dd56a3494a5cde6cc80`, Dart 3.10.9.
Development SDK is isolated under `/tmp/liwetun-flutter-sdk`; it is not vendored.
Rust 1.95.0 and its Cargo cache are isolated under `/tmp`; Windows CI uses a
disposable Server 2022 runner. The local CLI test ran on Windows 10 x64 + WSL;
this does not qualify a Windows 11 installer, TUN or service.

- `flutter analyze --no-pub`: PASS, no issues in the application/test code.
- `flutter test --no-pub --reporter expanded`: PASS, **65 tests**, locally and
  on Windows CI. Rust C ABI: **6 tests PASS**. Actual Windows channel: **1 PASS**.
- Synthetic-secret canary: absent from controller error strings, all diagnostic
  event JSON and decompressed ZIP entries. This does not yet cover native core
  crash/stdout paths because no native core is integrated.
- Widget checks: 1280x800 and 480x800 navigation, empty state, import and truthful
  unavailability. Initial compact header overflow fixed and rerun passed.
- `python3 tools/generate_icon.py`: completed with no external packages.
- Explicit Flutter screen rendering: PASS, three actual screen PNGs saved under
  `build/previews/` and visually inspected. These are framework renders on Linux,
  not screenshots of a running native Windows application.
- New files reviewed for credentials: only a deliberately synthetic test canary
  matched the targeted token/password scan.

## Not implemented / acceptance still open

No signed installer, privileged service/full-core SDK bridge, TUN, DNS/routes,
protected storage, persistent rotated journal, subscription fetch,
scheduler/backoff, actual health probes, recovery, tray/startup, app updater,
kill switch, Hysteria2/Xray adapter or real network metrics.

The app cannot connect yet. Imported links disappear on exit. The domain store
is memory-only and is not wired to the GUI. Disk-full/ACL/rotation/IPC and clean
Windows native acceptance have not run. The save dialog and actual Windows file
write have not been exercised on Windows. Export format is unit-tested.

No fabricated profile list or fake connected state. All runtime diagnostic data
in tests is synthetic; no application/server runtime mock was installed.
LikeWeb repositories unchanged. Production contacted: **NO**.
Database migrations/deployment/real messages/panel calls: **0**.

Git: published working branch `feat/windows-mvp`; initial source `89e0894`, native
bridge `4916f51`. Local `main` is the initial baseline; no direct push to main.
GitHub currently uses the first published feature branch as default. Establishing
the remote main/review workflow remains a separate repository housekeeping step.

## Next concrete stage

Integrate the full official tunnel SDK/service behind the existing narrow
Windows bridge. Pin the actual library build/Conan dependency closure and
licenses; remove raw logs and per-destination collection before enabling it.
Validate signer, server/caller identity and per-user/session boundary on a
disposable Windows 11 x64 host. Prove actual QUIC traffic (no HTTP/2 fallback),
then TUN-bound probes, DNS/IPv6, stop/crash recovery and secret paths.
Keep server export changes deferred while LikeWeb's concurrent work continues.
