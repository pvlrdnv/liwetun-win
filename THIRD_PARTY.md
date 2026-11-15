# Third-party components

Development SDK baseline: Flutter 3.38.10 (BSD-3-Clause), Dart 3.10.9.
Direct packages: archive 4.0.7, crypto 3.0.6, file_selector 1.0.4;
development packages: flutter_test (SDK), flutter_lints 6.0.0.
Resolved direct/transitive versions and hosted checksums: pubspec.lock.
Upstream package metadata and license files remain authoritative.

The Windows runner is generated from the official Flutter template. LiWeTun
brand assets are original code-native geometry, generated without external
images or fonts by tools/generate_icon.py.

The import bridge statically builds the official Apache-2.0 TrustTunnel deep-link
parser at `48f424c0874eb6f6374ee84492c5cd55aa04dca9`; upstream license is retained
at `third_party/licenses/TrustTunnel-Apache-2.0.txt`. Rust transitive versions,
source revisions and registry checksums are pinned in
`native/trusttunnel_bridge/Cargo.lock`. A full Rust notice inventory remains a
distribution gate; CI does not publish an application package.

No tunnel-core, Hysteria2, Xray or Wintun binary is vendored or redistributed
at this stage. Do not interpret sample versions in upstream READMEs
as selected SDK versions. Before distributing a package, inventory every
included binary and package, preserve notices/licenses, pin SHA256, verify
redistribution terms and complete the signing/native acceptance gates.
