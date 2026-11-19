# Driver-free SDK path: local SOCKS feasibility

Scope: an isolated feasibility experiment, not a delivered application feature.
The owner has no spare PC. A limited application-scoped first test could avoid
adapter creation while full-system ownership safety remains unresolved.

## Verified

Standard public Windows Server 2022 run
[44531398018](https://github.com/pvlrdnv/liwetun-win/actions/runs/44531398018)
on `94e00a29b0d54b57e7e6eb82804adc0aa15426a9` reused the exact already qualified
aggregate SDK DLL, SHA256
`fcafa344cd1ce143a928c3f1cfc63f25686e7f6b739aa7ed58d4736d082d1ca5`.
No SDK rebuild, signing-root installation, service installation or TUN start.

The SDK was staged with no `wintun.dll` beside it. A separate fixture process
held its own deliberately disabled node. SDK start, authenticated local SOCKS5
handshake, refusal of no-auth and wrong-password clients, Stop and DLL unload
all succeeded without loading Wintun into the SDK process. The held node stayed
present and unchanged throughout; only its creator restored/closed it. Adapter,
route and DNS baselines were restored. [Original report](evidence/sdk-socks-isolation-44531398018.json).

The fixture used a refused synthetic loopback upstream and fixed synthetic
credentials. It made no production connection and verified no upstream payload.
SDK startup or local SOCKS authentication is not a working tunnel claim.

## What this does not establish

- Upstream TrustTunnel authentication, server TLS, HTTPS/DNS or data transfer.
- Browser proxy integration or compatibility with its authentication behavior.
- Operation as a non-elevated desktop user; the disposable runner was elevated.
- Windows 10/11 acceptance or an owner-ready portable/installed package.
- Safety of the original TUN/Wintun path or later foreign-state transitions.

## If the owner chooses this intermediate scope

First qualify real HTTPS through the local proxy against an isolated synthetic
endpoint, with wrong upstream credentials/CA, proxy auth and cancellation/Stop
controls. Keep Wintun absent and verify unchanged network/device baselines and
non-elevated operation. Then implement a visibly application-scoped mode with
protected profile handling and an authentication-capable client/probe. Preserve
unknown metrics and distinguish startup from verified data flow. Do not change
system proxy settings, routes/DNS/firewall, trust stores, install drivers or
silently fall back from the user's selected full-system mode.

The first installer must not be repurposed as a corporate-PC deployment. Any
owner handoff for this path needs its own reviewed package/run instructions and
the approved scope; no such handoff is provided by this experiment.
