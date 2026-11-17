# DNS health design boundary

Status: source analysis only; no application DNS health capability or new public
service command. The UI must continue to show DNS health as unavailable.

## Separate claims

An exact HTTP response proves neither a Windows resolver result nor the path of
the resolver's packets. A direct DNS message sent by the service would qualify
that message, not the user's normal resolver. A successful DoH request similarly
does not establish Windows DNS behavior. Existing CI A/AAAA marker/relay evidence
qualifies its synthetic network scenario; it is not a runtime application sensor.

The candidate needs separate facts for a fresh system-resolution result and
endpoint traversal correlated to that exact request. A result without path proof
must remain path-unknown. No combined green state may hide a DNS failure,
unsupported path observation, expired evidence or changed connection epoch.

## Pinned SDK observations

Analysis uses client commit `a1ce3f9d2572e8c3fd6c31e6c31881d307131f40`:

| Source | SHA256 |
| --- | --- |
| `core/src/dns_handler.h` | `d7c03d612a6f53f596ae27e6efea5f6d764c893002ca7c14e44948f358d41eb9` |
| `core/src/dns_handler.cpp` | `ddec63e062968b838e255f200a0762e3e1b173c6f3dad0c4aba26f3146daa969` |

The handler intercepts TCP/UDP port 53 and may forward through an endpoint
listener, a configured DNS proxy or a system/direct path. When the endpoint is
disconnected and the kill switch is off it can choose system/direct DNS.
`send_request` maps proxy client IDs to upstream connection IDs;
`send_request_as_listener` creates a listener connection. These are internal
transformations. The current exclusive connected TCP socket ABI does not
correlate them to Windows resolver requests. A TUN source, a preferred route,
aggregate byte delta or nearby timestamp cannot substitute for that correlation.

## Implementation prerequisites

Choose a fixed synthetic resolver question/answer contract before runtime work;
do not expose caller-selected names, resolvers, URLs or privileged packet sends.
Production names/authority/bootstrap policy remain unselected. No personal
queries are observed or retained.

First qualify the resolver call's cancellation, cache handling, duplicate/fanout
behavior and exact answer validation on disposable Windows. Then design a
private one-attempt correlation across original resolver request, SDK DNS
handler and actual endpoint exchange, including configured proxy rewrites.
This needs its own guarded SDK source profile, ABI review and binary rebuild;
the already pinned TCP probe DLL must not be silently relabeled DNS-capable.

Require negatives for cached/unrelated answers, wrong question/answer,
system/direct fallback, missing reply, Stop, changed epoch and flow migration.
Internal query tokens/IDs/addresses remain transient, never exported. Only closed
typed outcomes may cross authenticated IPC. An unsupported configuration or
unprovable mapping stays unavailable. No DNS, routes, firewall or trust changes
are permitted on the owner's development device.

Desktop Windows 10 and Windows 11 acceptance and trusted distribution remain
independent from disposable Server 2022 qualification.
