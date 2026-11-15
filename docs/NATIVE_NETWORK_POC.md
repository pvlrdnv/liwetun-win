# Native network POC — 2026-11-15, PARTIAL

Real binaries: official Windows CLI TrustTunnelClient 1.1.12 and Linux endpoint
1.1.0. These are a **separate synthetic test**, not the app's service adapter.
No LikeWeb server, profile, key, broker, panel or application was used/changed.

| Case | Actual observed data transport | Result |
| --- | --- | --- |
| HTTP/2 + correct credentials/custom CA | HTTP/2, 142 bytes inbound /88 outbound | VERIFIED |
| HTTP/3 requested | HTTP/2 fallback, zero HTTP/3 bytes | HTTP/3 NOT QUALIFIED |
| Wrong password, with working HTTP/2 baseline | No origin request or data bytes | Expected denial VERIFIED |
| Different trusted CA, same hostname/SNI | No origin request or data bytes | Expected denial VERIFIED |

Every case stopped its own random-name Windows process. A second request through
the closed SOCKS failed, excluding direct curl fallback. Aggregate counters from
the endpoint prove actual HTTP/2 data flow; per-user metrics were disabled.
No visited-site/SSID/MAC/process-list collection. No raw core output written or
printed; only closed test result fields and safe counters are retained.

The harness returns **2** when qualification is partial (as here), **0** only if
all four strict cases pass, and **1** for a harness exception. This known partial
result is separate from the fully passing Windows compilation/import CI.
Evidence: [safe JSON](evidence/local-network-261115.json), including harness SHA256
and pinned archive digests. No app package or core binaries are published.

## Important findings

1. The official core forces loopback destinations through its direct upstream.
   The initial loopback-origin smoke test returned data while endpoint counters
   remained empty. It was insufficient proof and is **not** accepted as a
   tunnel/HTTP/3 test. The final origin binds only an already-existing private
   WSL IPv4, while SOCKS/endpoint/metrics listen on loopback; no IP/routes added.
2. A request configured for HTTP/3 may fall back to HTTP/2. A successful response
   and configured protocol alone are insufficient. The final harness checks
   per-transport data-plane counters and retains the HTTP/3 qualification gap.
   The cause of QUIC failure in this Windows/WSL path is UNKNOWN; no conclusion
   about LikeWeb servers or general HTTP/3 support follows.
3. CLI exit code 0 also occurs for the negative auth/CA fixtures. Never map exit
   code or process lifetime directly to connected/healthy.
4. Endpoint 1.1.0's metrics path uses Http1Codec settings. The fixture must include
   `[listen_protocols.http1]` in addition to HTTP/2/QUIC; otherwise metrics
   connections reset. This was fixed only in the synthetic fixture.

Source evidence for findings 1 and 4:

- https://github.com/TrustTunnel/TrustTunnelClient/blob/a1ce3f9d2572e8c3fd6c31e6c31881d307131f40/core/src/tunnel.cpp
- https://github.com/TrustTunnel/TrustTunnel/blob/v1.1.0/lib/src/metrics.rs
- https://github.com/TrustTunnel/TrustTunnel/blob/v1.1.0/lib/src/http1_codec.rs

## Reproduce

The harness deliberately performs no downloads or installs. Place these exact
upstream archives in `/tmp`, verify the listed SHA256, then unpack into the
task-only layout expected by `tools/local_loopback_probe.py`:

- `liwetun-endpoint-v1.1.0.tar.gz`: official release asset
  `trusttunnel-v1.1.0-linux-x86_64.tar.gz`, SHA256
  `91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7`.
- `liwetun-client-v1.1.12-windows.zip`: official release asset
  `trusttunnel_client-v1.1.12-windows-x86_64.zip`, SHA256
  `56fb620f4cd30abbc1b4586c6645b56d90c8c0e977ba53d95fb0f542acb7cb1f`.

```sh
mkdir -p /tmp/liwetun-loopback-bin/endpoint /tmp/liwetun-loopback-bin/client
tar -xzf /tmp/liwetun-endpoint-v1.1.0.tar.gz -C /tmp/liwetun-loopback-bin/endpoint --strip-components=1
unzip -q /tmp/liwetun-client-v1.1.12-windows.zip -d /tmp/liwetun-loopback-bin/client
python3 tools/local_loopback_probe.py
```

The harness rechecks both archives and extracted executables against the archive
contents before execution. It requires WSL interop, Windows curl, Python and
openssl. Certificates/credentials are synthetic and automatically removed. The
only PowerShell command stops a task-generated random process name; ordinary
user TrustTunnel processes are never selected. There is no .ps1 execution,
permanent policy change, service/driver installation, TUN, system DNS/route or
certificate-store mutation. No cleanup resets other adapters or connections.

Next acceptance needs a disposable Windows 11 x64 environment with a verified
UDP path, then full service/IPC/signature and TUN DNS/IPv6/recovery tests. The
application's connection button remains unavailable until that integration.
