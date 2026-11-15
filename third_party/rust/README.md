# Native parser dependency notice texts

These original notice/license texts were collected from the locked Rust build
on disposable Windows CI, source `463c690`, run
[43753020825](https://github.com/pvlrdnv/liwetun-win/actions/runs/43753020825).
The inventory records package/version/source and each file's SHA256/size; its
Cargo.lock digest matches `native/trusttunnel_bridge/Cargo.lock` with that
Windows checkout's CRLF endings. The receipt additionally records the canonical
LF digest; future collection normalizes LF directly. The registry
crate archives were also checked against Cargo.lock before collection.

Ten external crates, 22 notice files, none missing. Numbered files preserve the
source text exactly; see each package entry in `inventory.json`. Alternate
license texts are retained together. Unicode's additional data license is
included. The pinned TrustTunnel workspace Apache-2.0 license is retained even
though that crate's manifest does not declare a license field.

The list conservatively includes procedural macros/build dependencies. It is
the Rust parser closure only, not the SDK, Flutter engine or full distribution
inventory. Bundle these notices with the native parser in the future package;
they do not themselves approve a complete LiWeTun release. Collection is
reproducible through `tools/sdk/rust_notices.py` after locked offline metadata.
