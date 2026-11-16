# SDK dependency notice candidates

Original files only, with SHA256/size/source receipts in `inventory.json`.
The starting point is actual SDK build `37519a8`,
[run 43752644532](https://github.com/pvlrdnv/liwetun-win/actions/runs/43752644532):
28 dependency graph nodes, 20 packaged notice files. Thirteen package notice
sets were missing. Source supplements now provide candidate files for all 13,
including the Chromium notice for tldregistry, both PCRE2 notices and a
conservative lwIP notice from the pinned DNS tree. SDK and original Wintun binary
license texts accompany the set. Total: **38 files**.

The upstream Common/DNS trees and Git sources use exact commit references.
GitHub blob bytes were checked against their Git object hashes. ngtcp2 and
PCRE2 source archives match the SHA256 values in the pinned build recipes.
For libevent, libsodium, nghttp2 and nghttp3, the recipe uses a tag; its current
commit was resolved after the build and is recorded explicitly. This does not
retroactively prove the build's checkout HEAD. Future release source provenance
must capture/enforce those source revisions on the builder.

These are candidates for review, **not a complete distribution approval**.
The original missing-package report remains archived as evidence. Nested
third-party attributions, modified SDK source notices, source/tag provenance,
Flutter/engine/Dart/runtime notices and final package composition remain audit
gates. Build-context and duplicated test dependency nodes are retained
conservatively; they are not claims that every listed component is linked.

`python tools/sdk/verify_notices.py` verifies exact lock membership, runtime
provenance and file bytes for this SDK set and the Rust set. A changed dependency,
missing file, path escape, extra text file or altered notice fails verification.
Original line endings/spacing are preserved to keep receipt hashes valid.

[LiWeTun modification notice](MODIFICATIONS.md) records the SDK privacy-profile
and build-provider changes and accompanies the copied SDK notice directory in
the installer payload. It is separate from the 38 original upstream texts and
does not constitute final legal/release approval.
