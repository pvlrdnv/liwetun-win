# SDK dependency closure and distribution notices

SDK/Common/DNS commits and bootstrap/Wintun digests are pinned in
`native/sdk/inputs.json`. `native/sdk/conan.lock` promotes the actual successful
SDK qualification's recorded recipe revisions into a required build input.
The patched provider passes this input with `--lockfile`, writes the resolved
output lock and rejects drift before the top-level DLL build. Graph entries
must also refer to an allowed exact recipe revision.

Conan's [2.12 install documentation](https://docs.conan.io/2.12/reference/commands/install.html)
defines the input/output lock flags. Recipe locks constrain recipe revisions;
they do not prove bit-for-bit reproducible packages, compiler/toolchain identity
or license completeness. CI image/toolchain and rebuilt binary package revisions
are recorded separately and can still differ. Local recipe export timestamps
can change without changing the recipe revision, so comparison ignores only
those ordering timestamps, never revision hashes or dependency membership.

`tools/sdk/closure.py` reads actual packaged notices from the resolved Conan
graph, copying bounded license directories/root notice files while leaving the
cache read-only. It rejects packages outside the supplied Conan cache, symlinks,
junctions, excess depth/count/size and output-directory reuse. Reports omit
absolute cache paths. Missing package notices remain explicitly `missing`;
present files are `collected_for_review`, not a release approval. Build-context
packages remain labeled separately from host dependencies.

`tools/sdk/rust_notices.py` also collects the native parser's exact Cargo.lock
closure from offline Cargo metadata, verifies cached registry archive checksums
and copies package/workspace license texts into a separate inventory. Local
collection found notice files for all ten external crates, including the pinned
TrustTunnel workspace license and Unicode data license. Build/procedural-macro
dependencies are included conservatively; declaration metadata is not used to
invent a missing license. Windows collection passed on `463c690`,
[run 43753020825](https://github.com/pvlrdnv/liwetun-win/actions/runs/43753020825),
alongside the actual app/channel checks. All 22 original notice files and the
hash inventory are archived in [third_party/rust](../third_party/rust/README.md).

The release inventory must also include Flutter/engine/Dart packages, Wintun and distribution tools/runtime
components as applicable. Upstream SDK/Wintun notices already accompany the
development SDK artifact. A full redistribution review remains open.

Local validation: five closure/drift/collection/path-escape tests passed; actual
prepare script passed on a fresh pinned SDK tree and bootstrap. Windows SDK
rebuild with enforced input lock and notice collection passed on `37519a8`,
run `43752644532`. The downloaded runtime digest is pinned and passed both full
bounded endpoint network matrices with service `dd566d9`; see TUN_NETWORK_ACCEPTANCE.md.

Actual packaging omitted 13 notice sets. Supplements from exact recipe source
commits, checked source archives and explicitly labeled post-build tag resolution
now cover those sets. [third_party/sdk](../third_party/sdk/README.md) archives
38 original files and provenance. `verify_notices.py` checks all SDK/Rust notice
bytes against receipts and exact dependency locks, with tamper/path/membership
guards. Local tests passed; the Windows integrity workflow remains pending.
Coverage is not approval of nested attributions or complete release composition.

## Offline application notices

The actual prior GUI artifact from run 43850065637 was downloaded and all 13
file digests checked. Its bundled Flutter notices include engine/framework/Dart
texts, but not the native SDK/Rust inventories. The client now declares a
generated additional-license source containing all 38 SDK/Wintun and 22 Rust
notice bodies unchanged, and Support opens Flutter's offline license page.
[Generation and boundaries](../third_party/client/README.md).

The pinned Flutter 3.38.10 collector supports `flutter.licenses`; source inspection
at the pinned framework revision confirms additional source inclusion. The build
guard checks the generated native bundle verbatim inside bounded decoded
`NOTICES.Z` and every body from the exact pinned engine license file. Framework,
engine and engine-license digests are recorded with the GUI artifact. Package
admission checks that provenance and the actual native notice bytes again.

Local checks PASS: analyze, 118 Dart tests, complete generated native bundle,
1594 engine license sections present in the test asset bundle; an earlier GUI
without native notices is correctly rejected. This is local evidence only;
updated actual Windows build/package qualification is pending. These are byte
coverage checks, not a declaration of complete redistribution rights or closure
of the remaining source/nested-attribution/CRT/modified-SDK review gates.

Actual updated Windows qualification **PASS** on `eefbcf7`,
[run 43887262100](https://github.com/pvlrdnv/liwetun-win/actions/runs/43887262100):
analyze, 118 Dart + 6 Rust + 3 real desktop-channel tests, release build/staging,
and complete native/engine notice byte checks.
[Windows notice receipt](evidence/notice-bytes-eefbcf7.json).
Package/installer validation using that GUI also **PASS** on `17d66b6`,
[43888747188](https://github.com/pvlrdnv/liwetun-win/actions/runs/43888747188),
including the installed native notice-byte guard and all 14 installer groups.
[Evidence](evidence/installer-notices-17d66b6.json). Final distribution rights,
source/nested attribution, CRT and modified-source notices remain separate gates.

The SDK notice directory now also carries a prominent
[LiWeTun modification notice](../third_party/sdk/MODIFICATIONS.md) identifying
the exact upstream SDK, changed Windows logging/connection-info instrumentation
and Conan provider behavior. Original 38 notice texts are unchanged. The package
copies that notice directory; final assembled distribution/source attribution
review remains open.


The isolated source-pinned successor is described in [SDK_SOURCE_PINS.md](SDK_SOURCE_PINS.md).
A separate candidate notice check is prepared: it retains the original archived
inventory/provenance, verifies only the reviewed recipe substitutions, requires
exact candidate build run/commit and source/lock digests, and compares each new
packaged notice hash with that package's archived texts. Unknown bodies or new
dependencies fail; packages still needing source supplements remain explicit.
The GUI notice bundle stays unchanged unless a real text change requires review.
Twelve local integrity/source-pin/closure tests passed. Actual candidate notice
comparison awaits successful DLL compilation; this is not distribution approval.
