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

This is only the SDK Conan closure. The release inventory must also include
Flutter/engine/Dart packages, Rust crates, Wintun and distribution tools/runtime
components as applicable. Upstream SDK/Wintun notices already accompany the
development SDK artifact. A full redistribution review remains open.

Local validation: five closure/drift/collection/path-escape tests passed; actual
prepare script passed on a fresh pinned SDK tree and bootstrap. A Windows SDK
rebuild with enforced input lock and notice collection is pending. Existing
network results use the earlier qualified SDK artifact, not this pending build.
