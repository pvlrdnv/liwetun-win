# Draft: retained disabled software device removed by global cleanup

Draft only. This has not been sent to an upstream maintainer, mailing list or
issue tracker. It contains synthetic-fixture observations, no real credentials,
connection configurations or device identifiers.

## Environment and scope

- Disposable GitHub standard Windows Server 2022 x64 runner.
- Original signed Wintun 0.14.1 AMD64 DLL, SHA256
  `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.
- No SDK, Wintun data session, production endpoint or foreign application.
- One fixture process holds two independent creation handles. The first handle
  remains held throughout the second adapter's creation and close.
- Windows 10/11 desktop behavior has not been tested for this case.

## Reproduction

1. Use the original API to create a unique adapter with an independent random
   requested GUID and a full-length random physical alias.
2. Verify the returned handle's actual GUID, complete alias, LUID and index.
   Retain its creation handle. Locate only that exact GUID's PnP node.
3. Allow initial creation cleanup to settle, disable only this fixture-owned
   node with SetupAPI and observe its disabled problem state.
4. Create a second unique adapter through the original API. Keep the first
   creator handle open. Observe whether the first node remains present.
5. Close the second adapter and observe the first node again, still before its
   creator closes the first creation handle.
6. Release only the fixture's creation handles and verify the original adapter,
   route and DNS baselines are restored. No generic host repair is performed.

Observed in [44353969169](https://github.com/pvlrdnv/liwetun-win/actions/runs/44353969169)
and the raw arm of [44355747535](https://github.com/pvlrdnv/liwetun-win/actions/runs/44355747535):
the first disabled node disappeared after the second Create, before first creator
Close. The creation handle had not been released. Both experiments completed
with final adapter/route/DNS restoration. Harness success is distinct from the
failed preservation expectation.

The fixture reports only typed booleans/counts. Original reports and hashes:
[initial reproduction](evidence/adapter-problem-44353969169.json),
[paired raw/refusal control](evidence/adapter-problem-guard-44355747535.json).

## Source observation and requested behavior

The pinned [adapter implementation](https://git.zx2c4.com/wintun/tree/api/adapter.c?h=0.14.1)
queues global cleanup from Create/Close. Its software-device enumeration skips
nodes with a successful healthy-status observation; problem or unknown status
can reach removal without proving that a live creator no longer owns the node.
The fixture is consistent with that path. It does not independently instrument
the library's worker or qualify every possible device-state transition.

Requested behavior: creation/close of one adapter should not remove an unrelated
retained device solely because it is disabled/problematic. Cleanup should require
authoritative orphan/ownership evidence, or leave that node untouched. The report
does not prescribe a kernel/API implementation or claim an upstream fix exists.

## Client mitigation and remaining boundary

LiWeTun now has a read-only startup-refusal mitigation: problematic/unknown
Wintun software nodes, including non-present nodes, and legacy root Wintun refuse
Start before SDK adapter creation. The paired control proves healthy acceptance,
disabled refusal with zero Create calls, unchanged retained disabled node, and
healthy acceptance after its creator restores it.

This does not prevent a node from becoming problematic later while Create/Close
cleanup is queued. Full lifecycle ownership and release admission remain closed.
Holding a system-wide Wintun mutex throughout a connection, patching a loaded
signed DLL or changing unrelated devices are not implemented workarounds.

The client retains original signed Wintun bytes. The official
[distribution page](https://www.wintun.net/) distinguishes GPL 2.0 source from the
separately licensed supported prebuilt DLLs. This draft does not authorize a
modified driver/API distribution or change the application's license.
