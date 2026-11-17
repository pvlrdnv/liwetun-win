# Protected bounded diagnostic history

The application journal persists only closed typed events. No raw text logger,
core stdout/stderr, arbitrary URL/path/name fields or plaintext intermediate is
introduced. The source remains `DiagnosticEvent.toJson`; loaded history must
pass the same exact schema and enum constraints before any event is applied.

## Native isolation and crash behavior

`journal.v1.bin` uses the current-user DPAPI/ACL/atomic-write machinery in a
separate fixed storage area, with independent revision and DPAPI purpose.
Profile ciphertext cannot be decoded in the journal slot. Clearing journal
history does not touch profiles. IPC accepts three fixed journal operations;
there is no caller-selected path.

Journal writes use one fixed private encrypted pending file, under the shared
per-user mutex. A valid abandoned pending file can be removed before a fresh
write while retaining the last committed canonical file. A corrupt or unsafe
pending file blocks automatic writes. Explicit journal clear removes only the
canonical journal/pending file after revision and private-object checks. Partial
deletion/failure is reported; it never becomes a fabricated successful clear.

Both journal files are bounded to 1 MiB plaintext plus a 64 KiB container cap
each, so this journal stays below the proposed 20 MiB disk ceiling, including a
crash orphan. Profile temporary files are outside this journal guarantee.

## Retention and application behavior

Seven days and 1000 events, whichever removes history sooner; smaller injected
test limits remain stricter. Retention follows the system clock and runs at
startup, on changes and at the oldest event's expiry timer. Export/preview also
exclude expired events. Sleep/process exit can defer physical cleanup until the
app runs again; there is no background cleanup service solely for the journal.
Dates must be canonical UTC; cached times more than five minutes in the future
are rejected rather than trusted after an unexpected clock change.

New startup events wait in memory while history loads, then merge atomically.
Writes coalesce in one sequence with revision compare-and-swap. Clear during
loading or a pending save cannot resurrect the preceding history. Corrupt or
unknown snapshots stay unchanged unless the user explicitly clears the journal.
Native failure, disk exhaustion/permissions errors, uncertain writes or another
window's conflicting revision stop further automatic writes. Current events
remain available in memory and network operations continue independently.
No write retry can overwrite a newer/uncertain revision blindly.

Support shows whether the journal is loading, saving, saved or memory-only /
blocked. Summary v2 records the closed persistence state and limits. Clear can
empty the current view while disk deletion is still pending/failed; only the
saved state confirms the operation. The user still exports and sends the report
manually. Hard crashes can lose in-flight events; there are no memory dumps or
guarantees of recovering an unacknowledged write.

## Verification

Native isolation, cross-purpose ciphertext denial, pending recovery/corruption,
explicit clear and unchanged profiles passed on `53bd51d`:
[run 43754557047](https://github.com/pvlrdnv/liwetun-win/actions/runs/43754557047),
[safe evidence](evidence/journal-storage-53bd51d.json), alongside the previous
DPAPI/ACL/concurrency/reparse/current-user tests and LocalSystem denial.

Local analyze and **118 Dart tests PASS**, including 16 journal persistence,
retention, timer, clear/load/write race, corruption, raw-error canary and disposal
cases. Actual Flutter/Windows journal-channel roundtrip **PASS** on `c7b6f3d`:
[run 43812996533](https://github.com/pvlrdnv/liwetun-win/actions/runs/43812996533),
[safe build evidence](evidence/windows-journal-c7b6f3d.json). Release build,
analyze, 118 Dart + 6 Rust tests and 3 actual desktop tests passed. The journal
test proves restart/clear and an unchanged real encrypted profile slot.
Non-elevated installed desktop acceptance and power-loss/disk-full fault
injection remain separate gates.


Summary v3 retains the persistence state/limits and adds scoped aggregate traffic
observations. Event schema v1 adds the closed `trafficWindowReset` event with
reasons for stale observations, sampling gaps, instance/state-epoch changes and
monotonic clock/counter regression. It records a reset once, not every poll;
classifying a new window requires fresh history. No counter values, interface
identifiers, destinations or free-form error text are added to those events.
