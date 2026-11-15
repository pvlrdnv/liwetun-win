# Development checkpoint — 2026-11-15

Scope: LOCAL client development only. Product LiWeTun; GitHub description
`LiWeTun — Windows connection client`. Independent private repository:
https://github.com/pvlrdnv/liwetun-win

## Implemented and locally verified

- Flutter Windows runner, three-screen desktop shell with responsive navigation,
  OS light/dark themes, native title, original SVG/code-native mark and multi-size
  Windows ICO. No dependency on another GUI client.
- In-memory import of TT direct/QR carriers, a restricted TLS VLESS/HY2 URI
  subset, HTTPS subscription sources; duplicate QR/direct collapse. Input is
  obscured. Error messages do not echo input. TT payload stays opaque pending
  actual SDK validation; imported data is not a verified working connection.
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
  working tunnel. No direct-network probes run.

## Actual checks

Environment: Linux/WSL, Flutter 3.38.10 at
`c6f67dede3d4aa1aa7a69dd56a3494a5cde6cc80`, Dart 3.10.9.
Development SDK is isolated under `/tmp/liwetun-flutter-sdk`; it is not vendored.

- `flutter analyze --no-pub`: PASS, no issues in the application/test code.
- `flutter test --no-pub --reporter expanded`: PASS, **57 tests**.
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

No Windows compilation, signed installer, service, TrustTunnel SDK bridge, TUN,
DNS/routes, protected storage, persistent rotated journal, subscription fetch,
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

Git: working branch `feat/windows-mvp`; publish this initial slice there. Keep
a local `main` baseline; no direct push to main. An empty GitHub repository will
initially use the first published feature branch as its default. Establishing
the remote main/review workflow remains a separate repository housekeeping step.

## Next concrete stage

Pin an actual official Windows SDK/library artifact and its SHA256/licenses
(the public CLI release is not assumed to be the DLL SDK). Add a narrow Flutter
Windows bridge and validate the SDK's signed service/caller boundary on a
disposable Windows 11 x64 host. Start with synthetic TT import and HTTP/2/HTTP/3,
then verify tunnel-bound traffic, DNS/IPv6, stop/crash recovery and secret paths.
Keep server export changes deferred while LikeWeb's concurrent work continues.
