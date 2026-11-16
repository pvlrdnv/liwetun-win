# Offline client notice bundle

`NOTICES.txt` is generated from the 38 verified SDK/Wintun candidate notice files
and 22 Rust parser notice files, with component labels for Flutter's license page.
All original notice body bytes are retained. The original files and provenance
remain under `third_party/sdk` and `third_party/rust`.

Regenerate with `python tools/sdk/client_notices.py --write`; the default command
requires exact agreement with the verified source inventories and rejects drift.
The Flutter pubspec declares this file as an additional license source. It is
combined with Flutter/Dart/package/engine notices in `NOTICES.Z`, viewable offline
from Support → «Лицензии компонентов» without service or network access.

The Windows builder also checks every license body from the pinned engine's
`sky_engine/LICENSE`, records notice hashes and engine/framework revisions, and
the package builder rejects a missing/altered native bundle or mismatched GUI
notice provenance. Original upstream text files are preserved separately.

These checks establish byte coverage/integrity, not legal interpretation or
release approval. Build/procedural-macro dependency notices are conservatively
included. Nested SDK attributions, actual build source-tag provenance, modified
SDK notices, Microsoft CRT redistribution terms and final distribution review
remain gates. The diagnostic Linux endpoint is not part of this client payload.
