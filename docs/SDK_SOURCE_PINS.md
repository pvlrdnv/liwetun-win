# Candidate immutable dependency sources

The active SDK remains the qualified development build pinned in
`native/sdk/runtime.json`, with the original `native/sdk/conan.lock`.
This stage prepares an isolated successor build input; no runtime is promoted.

Four Common recipes need stronger source inputs:

| Recipe | Candidate source input |
| --- | --- |
| libevent 2.1.11 | Exact upstream commit archive and SHA256 |
| libsodium 1.0.18 | Exact Git commit |
| nghttp2 1.56.0 | Exact Git commit |
| nghttp3 1.0.0 | Exact Git commit |

The selected commits already appear in archived notice provenance. This does
not retroactively prove the earlier build's tag checkout. The new profile uses
the exact Common revision and records original/patched recipe digests in
`native/sdk/source-pins.json`. Changed recipes carry a LiWeTun notice; patches
do not change upstream library versions, algorithms or recipe build options.

`tools/sdk/pin_sources.py` validates every source before mutation. The disposable
Windows export job first verifies each original Conan 2.12.2 recipe revision
against the active lock, then prepares/exports the candidate and writes a
separate candidate lock. Only the four reviewed references may change; active
runtime/lock files are never overwritten by this tool. Failures use closed
reason codes and bounded reference metadata, without cache paths or raw output.

Local checks: three atomic-tamper/path/active-lock-isolation tests PASS; exact
patching of all four pinned upstream recipe files PASS; Python and workflow YAML
syntax PASS. Actual Windows recipe exports are pending. Export success alone
will not qualify an SDK: the successor needs a complete DLL build, source/notice
receipts, service/network requalification and package validation. Desktop,
trusted signing and distribution rights remain separate release gates.
