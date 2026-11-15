# Windows native acceptance — OPEN

No Windows result can be inferred from Dart unit tests or a Linux build.
Run on a disposable clean Windows 11 x64 host with synthetic credentials and
a local test endpoint. A real LikeWeb node requires separate authorization.

Completed prerequisite, distinct from the tunnel gates below: Windows Server
2022 CI compiled the C++/Rust/Flutter shell and exercised the actual native import
channel, with synthetic HTTP/2 and HTTP/3 links and TLS-bypass rejection. Details:
[native import verification](NATIVE_IMPORT.md#verification).

- [ ] Pin TrustTunnel SDK version, SHA256 and all distributed licenses.
- [ ] Verify app/service/adapter embedded signatures, common signer, Program
  Files ACL and refusal of an unauthorized process, user/session or executable.
- [ ] Import actual SDK TT fixture, HTTP/2 and HTTP/3 separately; system CA and
  profile-scoped custom PEM; reject certificate mismatch without TLS bypass.
- [ ] TUN DNS, IPv4/IPv6, UDP, large transfer; prove probes use chosen tunnel.
- [ ] Distinguish idle, TX-no-RX, DNS failure, endpoint failure, missing metrics.
- [ ] Service/core crash, sleep/wake, Wi-Fi/Ethernet switch, bounded recovery.
- [ ] Stop/cancel/failed start/uninstall restore routes and DNS; no orphan TUN.
- [ ] Secret persistence through DPAPI with per-user ACL, no plaintext fallback.
- [ ] Cache expiry, explicit account/profile revoke, partial/upsert and replay.
- [ ] Log rotation 7 days /20MiB (stricter wins), disk full, permissions, clear.
- [ ] Unique synthetic secret through malformed URI/core crash; inspect app
  output, local logs, temporary files and exported ZIP for zero occurrences.
- [ ] Installer, icon/tray/DPI, startup, update signature/rollback, uninstall.

Kill switch and automatic reconnection stay unavailable until these paths are
qualified. Hysteria2 and VLESS TCP/REALITY/XHTTP need separate acceptance.
