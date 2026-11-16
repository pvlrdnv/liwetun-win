# CI diagnostic endpoint source notice

Upstream: https://github.com/TrustTunnel/TrustTunnel
Source commit: `fab5b8353a19332f935fa30869307d37d4a898d1` (v1.1.0).
The original Apache-2.0 `LICENSE` is copied unchanged from the pinned source
archive. Its SHA256 is
`cd994f29faba128fa963ccab364cdee0b51cdb399f98432c4bb6c7a6d017d3df`.

LiWeTun modifies only `lib/src/socks5_client.rs` and
`lib/src/socks5_forwarder.rs` in its disposable diagnostic build to use
nonblocking UDP receive and return to polling on WouldBlock. The exact patch,
source archive and before/after digests are in `tools/service/endpoint-source.json`
and `tools/service/endpoint_socks5.patch`.

This server is a CI fixture, not part of the Windows client/installer payload.
Its modified binary is explicitly not an official upstream release. This notice
does not establish a full redistribution audit of its transitive dependencies.
