# TrustTunnel import bridge

Uses the official `trusttunnel-deeplink` crate directly, the same parser used by
TrustTunnelClient's SDK. Pinned revision and transitive dependencies are in
Cargo.toml/Cargo.lock. This is the real binary-format parser, not a reimplemented
decoder or a synthetic runtime adapter. It does **not** contain the tunnel core.

The C ABI returns only status, HTTP/2 vs HTTP/3, custom-certificate presence and
IPv6 configuration. Credentials, names, addresses and raw upstream errors stay
inside native memory and are not returned to Dart, printed or saved. No network
or SDK logger is initialized. TLS-bypass and embedded subscription URLs are
rejected; the latter require an explicit future transport contract.

Rust 1.95.0 is pinned at repository root. Build/test:

```sh
cargo test --manifest-path native/trusttunnel_bridge/Cargo.toml --locked
cargo build --manifest-path native/trusttunnel_bridge/Cargo.toml --release --locked
```

The Windows CMake build statically links this crate and requires Cargo on PATH.
No dynamic DLL search path or untrusted library loading is introduced. The
upstream C++ adapter logger is deliberately not linked. Tunnel/service integration
requires separate signer, ACL, privacy and routing qualification.

FFI pointers are trusted in-process pointers; this API is not an IPC trust
boundary. Panic output is suppressed before parsing; panics return a closed
internal-error code. Allocator abort/OOM is not recoverable. Memory zeroization
of all upstream parser copies is not guaranteed; memory dumps are prohibited.
