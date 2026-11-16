# Windows TUN network acceptance — bounded CI PASS

LOCAL/CI scope only. LikeWeb and the owner's corporate device remain unchanged.
Targets for later installed-client acceptance: Windows 10 x64 and Windows 11 x64.

## Confirmed results

Current locked SDK runtime (source run `43752644532`, DLL SHA256 in
`native/sdk/runtime.json`) passed with service source
`dd566d9e8b8a025aa89ada095ec6611a1805038a`:

| Official endpoint | Run | Result |
| --- | --- | --- |
| 1.1.0 | [43814467138](https://github.com/pvlrdnv/liwetun-win/actions/runs/43814467138) | 18 service/security/transport checks and all 6 network cases PASS |
| 1.3.0-beta.2 | [43814471604](https://github.com/pvlrdnv/liwetun-win/actions/runs/43814471604) | 18 service/security/transport checks and all 6 network cases PASS |

[1.1 network](evidence/network-43814467138.json),
[1.1 service](evidence/qualification-43814467138.json),
[1.3 network](evidence/network-43814471604.json),
[1.3 service](evidence/qualification-43814471604.json).
Both also passed an old-disconnect data-loss reproducer and an actual signed
client delaying its reply read. The service now preserves replies until bounded
peer completion. Earlier new-runtime runs failed before this fix and remain
archived as failures; the successful runs above supersede those diagnostics.

### Earlier runtime baseline

Actual signed service, pinned SDK DLL and original Wintun on Windows Server 2022:

| Official endpoint | Run | Result |
| --- | --- | --- |
| 1.1.0 | [43748675582](https://github.com/pvlrdnv/liwetun-win/actions/runs/43748675582) | 16 service/security checks and all 6 network cases PASS |
| 1.3.0-beta.2 | [43748678908](https://github.com/pvlrdnv/liwetun-win/actions/runs/43748678908) | 16 service/security checks and all 6 network cases PASS |

Both use source `52c20478280b6d8f3a0f41ddc4a70b510b884589`.
[1.1 network evidence](evidence/tun-network-43748675582.json),
[1.1 service evidence](evidence/tun-qualification-43748675582.json),
[1.3 network evidence](evidence/tun-network-43748678908.json),
[1.3 service evidence](evidence/tun-qualification-43748678908.json).

Cases: HTTP/2, HTTP/3, wrong password, wrong CA, client lease-process death and
service crash. Positive cases delivered normal-certificate-verified HTTPS and
an exact synthetic DNS answer through the selected TUN. H3 endpoint has no H2
listener; no other transport carried data. Each positive DNS probe produced
82 endpoint data bytes; HTTPS plus DNS totaled about 6–6.5 KiB. Negative cases
delivered no data and counted zero endpoint data bytes.

Pre/post route and DNS snapshots matched after every case, and no task TUN
remained. Reusing the removed interface index failed delivery. Idle endpoint
traffic was zero; positive-case endpoint idle socket counts were TCP 0, UDP
1–3, below the fixed limits. No sustained service CPU loop was observed.
`release_ready` remains false; diagnostics-only runs cannot qualify all cases.

## Test method and scope

The real official endpoint runs in a task-created WSL1 distribution. Ubuntu
22.04.5 base archive and both endpoint archives are pinned by SHA256. WSL1 avoids
the prior WSL2 UDP forwarding ambiguity. The workflow removes its exact task
Linux distribution. Synthetic credentials and certificates remain in build
folders; raw endpoint/core logs, private addresses and DNS names are not exported.

The service is compiled with `LIWETUN_TEST_TUN_NETWORK`, mutually exclusive with
`LIWETUN_TEST_NO_GLOBAL_ROUTES`. SDK config creates `198.18.0.0/15` and configures
DNS on its own adapter. The fixture adds high-metric origin/DNS host routes on
TUN and lower-metric physical routes where none already exist. This separates
same-host endpoint egress from client ingress. Only task-created physical routes
are removed; earlier routes are preserved. Probe sockets explicitly set Windows
`IP_UNICAST_IF` to the TUN index, independently of ordinary route preference.

The HTTPS origin is `https://example.com/`, with ordinary hostname/certificate
verification. DNS targets the SDK-configured adapter DNS address. Its configured
upstream is a synthetic DNS responder on the runner's existing private IPv4,
reachable by the endpoint. A loopback DNS destination is unsuitable evidence:
the SDK can bypass loopback. A correct DNS answer alone never passes; endpoint
transport counters must grow separately during that DNS probe.

The DNS fixture answers only its fixed synthetic question and returns NXDOMAIN
for unrelated questions. It retains aggregate counts, not question names.
Counters, active TCP/UDP socket totals, the owned service's CPU time and route
prefix-length counts are used to reject contamination or a hidden busy loop.
No process list, visited-site history, interface identifiers or packet logs are
collected for the support journal.

## Corrections established by the experiments

- Windows adds multicast routes on virtual interfaces independently of SDK
  `included_routes`. With an empty engine exclusion list, the fixture produced
  thousands of endpoint UDP sockets and large idle data counts. The service now
  excludes `224.0.0.0/4`, `ff00::/8` and `255.255.255.255` from tunnel exit routing.
  Local discovery uses the SDK direct path. After this change, both endpoint
  versions passed byte/resource bounds. This is common service policy, not a
  replacement networking implementation or a temporary firewall change.
- Early loopback DNS and contaminated aggregate counters did not prove tunneled
  DNS. Those preliminary criteria are superseded. Old functional evidence is
  retained as [superseded measurement](evidence/tun-network-a7b1ca8.json), not
  payload-size or DNS-transport acceptance. Aggregate-only diagnostics are in
  [0da23de](evidence/tun-network-0da23de-diagnostic.json) and
  [c6d188d](evidence/tun-network-c6d188d-diagnostic.json). Same-host DNS re-entry
  was investigated but did not explain the large idle flow; multicast was the
  effective correction. No automatic IPv4 default route was observed.
- SDK default routes split into narrower prefixes, so searching for one `/0`
  was an invalid test design. [Earlier failed run](evidence/tun-network-c61f856-failed.json)
  is retained; the current test uses explicit bounded routes.
- Busy named-pipe transport now waits for availability without resending a
  command. Authorization-negative helpers fail on an unavailable server rather
  than treating transport failure as authorization evidence.

## Remaining gates

This is not acceptance of a normal installed GUI on either desktop OS, ordinary
system-wide default routing, DNS leak prevention, IPv6 data, arbitrary large UDP
or TCP transfers, Wi-Fi changes, suspend/resume or a signed installer/updater.
Fixture route priorities deliberately differ from production defaults. There is
no fabricated connected state in the UI. The signed client probe and unsigned
Flutter desktop channel tests remain separate acceptance layers.
