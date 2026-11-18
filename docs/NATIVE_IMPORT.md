# Native TrustTunnel import — implementation and boundaries

The real TrustTunnel binary deep-link parser is integrated through a small Rust
static library, a C ABI, the Flutter Windows C++ runner and a typed Dart channel.
The parser is the official crate used by TrustTunnelClient's Windows SDK:

- SDK interface research: TrustTunnelClient
  `a1ce3f9d2572e8c3fd6c31e6c31881d307131f40`.
- Actual parser dependency: TrustTunnel/TrustTunnel
  `48f424c0874eb6f6374ee84492c5cd55aa04dca9` (upstream tag v1.3.0-beta.2).
- Rust 1.95.0; Cargo.lock includes all transitive registry checksums.

This channel remains an import-only bridge. A separate authenticated service
channel and full SDK adapter now exist; see [WINDOWS_SERVICE.md](WINDOWS_SERVICE.md).
No random DLL is loaded, logger initialized, network request made or Windows
service installed. The method channel has two operations: `capabilities` and
`inspectTrustTunnel`. No generic privileged command, TOML runner or shell call.

`canConnect` is hardcoded false. Successful parsing is displayed separately
from unknown entitlement/reachability and never changes the connected state.
Without the native platform, a link may be retained as explicitly unvalidated.
On Windows, SDK-invalid, TLS-bypass or unsupported TT links are rejected.
Embedded TT version-2 subscription URLs require a separate transport contract
and are rejected even when accompanied by fallback server parameters.

## Why not link the full C++ adapter for import

SDK `trusttunnel_decode_deeplink` logs the parser's free-form error. The service
has connection-info callbacks and optional persistent per-connection ring
storage; these are outside the client's privacy requirements. Using the same
official parser directly allows dropping its error without invoking that logger.

The separate LiWeTun SDK profile now disables raw logs and per-destination
instrumentation in guarded pinned-source patches, verified in service CI. Leaving
the Dart callback unset alone does not prove collection is disabled upstream.
The service signer check also accepts certain intact self-signed/expired chains
for signer matching; release trust, caller identity/session ACL, service identity
verification and installer directory ACL require separate qualification.

## Verification

Completed run:
https://github.com/pvlrdnv/liwetun-win/actions/runs/43717022021

Source `4916f5139972e174ea2c97659833cce643070401`: 6 Rust tests, 65 Dart tests,
Flutter analyze, Windows release compilation and 1 actual desktop integration
test all PASS. The tested shell executable SHA256 is
`8e96e7f40a369aab8e81b7c8e0f9d8f15240360d21e71be9d63d915814b1cc13`.
The CI evidence JSON is retained in docs/evidence/windows-import-4916f51.json.

The manual GitHub workflow `Windows native import check` runs on a disposable
Windows Server 2022 runner with Visual Studio tooling. It pins Flutter and Rust,
runs Rust C-ABI tests, Dart tests, compiles the real Windows shell and runs a
desktop integration test through the actual C++ channel. Synthetic HTTP/2 and
HTTP/3 fixtures come from the official encoder; no real credentials are used.
It never installs/starts a tunnel/service and uploads only build-evidence JSON,
not an unsigned application package. This is distinct from Windows 11 clean-host
network/DNS/IPv6/recovery acceptance, which remains open.

Run locally on a Windows development machine with Visual Studio C++ tools,
Rust 1.95.0 and the pinned Flutter:

```powershell
cargo test --manifest-path native/trusttunnel_bridge/Cargo.toml --locked
New-Item -ItemType Directory -Force build | Out-Null
cargo run --manifest-path native/trusttunnel_bridge/Cargo.toml --locked --release --example synthetic_fixture -- build/native-fixture.json
flutter pub get --enforce-lockfile
flutter test integration_test/native_bridge_test.dart -d windows --no-pub --dart-define-from-file=build/native-fixture.json
```

The owner's accessible host is Windows 10 x64 with no detected Flutter or Visual
Studio toolchain. A subsequent isolated CLI/network POC is recorded in
[NATIVE_NETWORK_POC.md](NATIVE_NETWORK_POC.md). No host development tools were
installed; no certificate store, network settings, drivers or services changed.
The persistent PowerShell policy was verified as RemoteSigned before/after.
The final harness directly executes the verified exe; it runs no .ps1 and uses
no policy override. Synthetic credentials and certificates stay in a temporary
task directory, not the repository or diagnostic journal.

### Private presentation metadata (0.1.1 candidate)

The separate `liwetun_tt_presentation` ABI returns bounded, NUL-terminated UTF-8
name/hostname/address-list buffers for the profile UI only. Existing inspection
ABI1 remains 16 bytes. No username, password, certificate body or arbitrary parser
error is returned. Display controls/bidi overrides are replaced with spaces;
UTF-8 truncation retains complete code points. Embedded names replace numbered
fallbacks for direct profiles; subscription labels retain precedence. These fields
must never enter typed journal events or support reports. Synthetic native and
widget/export tests cover this boundary. Windows run 44382051192 passed 8 Rust,
234 Dart and 6 actual desktop channel tests, including the embedded synthetic
Unicode name and endpoint fields. Desktop owner acceptance remains pending.
