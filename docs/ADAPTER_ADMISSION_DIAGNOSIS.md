# Adapter admission diagnosis — focused iteration

This iteration captures the refusal predicate at observation time. It does not
weaken admission, fix global Wintun cleanup or qualify desktop connectivity.
The owner has no second PC; current main-device work remains read-only.

## Closed reply codes

Existing request/reply framing and the 32-byte Reply ABI stay unchanged.
Code10 remains accepted for earlier service versions. New codes are appended:

| Code | Typed result | Refusal observation |
| --- | --- | --- |
| 11 | adapterInterfaceUnavailable | Interface table unavailable, invalid or beyond bound |
| 12 | adapterAliasConflict | Reserved visible interface alias already present |
| 13 | adapterSwdUnavailable | SWD inventory/enumeration/state unavailable or beyond bound |
| 14 | adapterSwdProblem | SWD Wintun node has a problem flag |
| 15 | adapterRootUnavailable | Legacy ROOT inventory unavailable or beyond bound |
| 16 | adapterRootPresent | Legacy ROOT Wintun node present |
| 17 | adapterInventoryUnavailable | Network-device inventory unavailable or beyond bound |
| 18 | adapterPropertyUnavailable | Internal Wintun-name property read failed, other than not-found |
| 19 | adapterPropertyInvalid | Property type, size, termination or comparison invalid |
| 20 | adapterNameConflict | Reserved internal Wintun name already present |
| 21 | adapterStateUnavailable | Named Wintun node status unavailable |
| 22 | adapterProblem | Named Wintun node has a problem flag |

The initial Start returns its observed reason while remaining disconnected.
If the repeated gate before SDK initialization refuses, the worker retains its
reason in the error snapshot; GUI polling records the typed rejection and keeps
Stop available. A subsequent Stop or query does not erase the recorded event.
No adapter name/ID, native error string, configuration or credential is returned.
Older components reject unknown codes rather than interpreting them as success;
new UI/service deployment still requires a coherent qualified package.

## Disposable Windows evidence

Service run [44527659328](https://github.com/pvlrdnv/liwetun-win/actions/runs/44527659328),
source `e17bd0d8b0fa0a093f2f3dadef852f3379fb7a43`, passed synthetic WinAPI
contracts for success plus all 12 specific refusals, and 21 signed-service groups.
The original signed Wintun fixture exercised these states on its own exact node:

| Fixture state | Actual admission |
| --- | --- |
| Held creation handle, active Wintun session | Accepted |
| Session ended, healthy creation handle/node retained | Accepted |
| Fixture explicitly disables its PnP node | Refused, code14 |
| Fixture creator re-enables its node | Accepted |
| Creator closes its handle and its node disappears | Accepted |

The signed service also returned code14/state0/core unknown while a separate
fixture retained its disabled node. The fixture remained unchanged until its
creator restored/closed it. Adapter/route/DNS baselines were restored. SDK
lifecycle checks used no-global-routes mode. The session matrix itself did not
start the SDK or transfer payload.

Ending a session is therefore distinct from disabling the PnP device in this
fixture. These results do not identify which predicate refused the owner's
historical attempt, reproduce a particular corporate client, qualify later
foreign-state races or establish Windows 10/11 traffic acceptance.

## Observe without another Start

[Read-only observation tool](../tools/diagnostics/README.md) supports a bounded
watch that prints only transitions, the first sample and the final sample. It
requires neither a connection key nor LiWeTun Start. Do not change corporate
client/device state for this test; collect during ordinary use only. The initial
alias query uses Get-NetAdapter instead of GetIfTable2, so this is a diagnostic
aid, not an authorization replacement. Private results belong under ignored temp.

The two-sample watch compiled and executed on the local Windows host with only
closed fields; both observations passed at that later time. Existing Windows
logs did not provide an available historical observation for the refusal window.
No host service/driver/trust/network changes or connection experiments occurred.

## GUI verification

[44528862824](https://github.com/pvlrdnv/liwetun-win/actions/runs/44528862824)
passed on `3c2aadba942c2142141b5a6d568f8ac3304f9f9d`: analysis, Windows release
compilation, 248 Dart tests, 8 Rust tests and 6 actual desktop-channel tests.
Every closed initial refusal survives ZIP export with an idle state; a later
pre-SDK refusal survives polling while Stop remains available. First GUI attempt
44527665182 failed a new test's pending-timer cleanup; the test now disposes its
controller in finally before the widget framework's invariant check.

No installer is delivered for this diagnosis-only iteration. Historical owner
failure remains unresolved, and global Wintun cleanup safety remains open.
