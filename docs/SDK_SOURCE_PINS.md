# Candidate immutable dependency sources

The active SDK remains the qualified development build pinned in
`native/sdk/runtime.json`, with the original `native/sdk/conan.lock`.
This stage prepares an isolated successor build input; no runtime is promoted.

Seven recipes need stronger source inputs:

| Recipe | Candidate source input |
| --- | --- |
| libevent 2.1.11 | Exact upstream commit archive and SHA256 |
| libsodium 1.0.18 | Exact Git commit |
| nghttp2 1.56.0 | Exact Git commit |
| nghttp3 1.0.0 | Exact Git commit |
| NativeLibsCommon 8.2.0 | Full Git commit instead of release tag |
| DnsLibs snapshot | Full Git commit instead of abbreviated revision |
| BoringSSL 2026-05-08 | Exact official mirror commit archive and SHA256 |

The selected commits already appear in archived notice provenance. This does
not retroactively prove the earlier build's tag checkout. The new profile uses
the exact Common revision and records original/patched recipe digests in
`native/sdk/source-pins.json`. Changed recipes carry a LiWeTun notice; patches
do not change upstream library versions, algorithms or recipe build options.

`tools/sdk/pin_sources.py` validates every source before mutation. The disposable
Windows export job first verifies each original Conan 2.12.2 recipe revision
against the active lock, then prepares/exports the candidate and writes a
separate candidate lock. Only the seven reviewed references and their matching override references may change; active
runtime/lock files are never overwritten by this tool. Failures use closed
reason codes and bounded reference metadata, without cache paths or raw output.

The initial four recipe exports passed on Windows:
[run 43913812035](https://github.com/pvlrdnv/liwetun-win/actions/runs/43913812035).
The expanded seven-recipe export also passed:
[run 43915706506](https://github.com/pvlrdnv/liwetun-win/actions/runs/43915706506),
[receipt](evidence/sdk-source-pins-538fe45.json). Both root recipes are exported with
explicit original versions. All Common and DNS inputs validate before either
vendor tree is changed. Overrides preserve their structure and only follow
reviewed recipe substitutions.

BoringSSL Gitiles produced different tarball hashes on two downloads, while all
8582 regular file bodies matched. The official google/boringssl GitHub archive
of the identical commit has exactly the same file set and contents. The
candidate uses that archive with SHA256 and removes its single root directory;
upstream patch files remain unchanged. This is a download/recipe change, not a
library code upgrade. tldregistry exports its sources from the pinned Common
checkout; libuv and pcre2 downloads already carry recipe checksums.

Local checks: four atomic-tamper/path/active-lock-isolation tests PASS, including
cross-repository atomic validation and BoringSSL override substitution; exact
validation of all seven pinned upstream recipes PASS; Python/workflow syntax
and diff checks PASS. Export success alone
will not qualify an SDK: the successor needs a complete DLL build, source/notice
receipts, service/network requalification and package validation. Desktop,
trusted signing and distribution rights remain separate release gates.

The reviewed candidate lock is `native/sdk/conan-sources.lock`. The SDK workflow
accepts `source_pins=true`, revalidates/reexports original and modified recipes
on its fresh runner, and compares the result to that recorded lock before
compilation. Privacy preparation and closure/notice collection use the selected
lock; the source profile records its SHA256 and candidate manifest SHA256.
The default still uses the original lock. Both local preparation paths and nine
source-pin/closure tests passed. Candidate DLL compilation is pending; the active
runtime receipt still refers exclusively to the earlier qualified DLL.

The first full candidate build
[43916079717](https://github.com/pvlrdnv/liwetun-win/actions/runs/43916079717)
failed before DLL production: Conan inferred an extensionless archive filename
from the codeload URL and selected ZIP extraction after successful SHA256 checking.
Both archive recipes now specify a `.tar.gz` filename. The recipe discovery job
also executes real `conan source` download/checksum/extraction/upstream-patch
checks for both recipes. Updated exports and lock refresh are pending; the
previous seven-recipe export receipt describes the earlier candidate exactly.
