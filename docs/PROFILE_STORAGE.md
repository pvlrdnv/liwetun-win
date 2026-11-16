# Protected user profiles

The UI process stores direct links, pending subscription-source links and the
selected profile in `%LOCALAPPDATA%\LiWeTun\profiles.v1.bin`. This path is fixed
in native code. Credentials never go to a plaintext intermediate file. The
LocalSystem tunnel service does not own this cache.

## Protection and consistency

- Current-user Windows DPAPI, `CRYPTPROTECT_UI_FORBIDDEN`, no machine-wide flag.
  This is protection at rest tied to the Windows user's DPAPI keys, not a defence
  against malware already executing as that user or an administrator. DPAPI key
  roaming/recovery policies can affect portability; do not claim absolute device
  binding.
- New directory/files have a protected DACL allowing only that user and SYSTEM.
  Existing objects with a foreign owner, broader ACL or reparse point are denied;
  the app does not repair them silently. The directory is held against replacement
  while operating. Unknown/unreadable files are preserved.
- Bounded 1 MiB plaintext, versioned container and encrypted inner integrity
  check. Random temporary files contain only ciphertext, use private ACLs and
  are flushed before atomic replacement. Failed replacements remove the exact
  temporary file created by the operation. A hard process crash may leave an
  encrypted orphan; there is no automatic orphan collection yet.
- Per-user cross-session mutex, bounded wait and ciphertext-revision compare
  and swap prevent two app windows from silently overwriting each other. This
  addresses cooperating windows; code running as the owner remains trusted.
- Corrupt/unsupported caches are never automatically overwritten or reset.
  Native explicit clear requires the matching revision. Reset UI is deferred.
- Owned native plaintext buffers are wiped where practical. Dart strings and
  allocator/codec copies cannot be guaranteed erased.

## Application behavior

The legacy v1 JSON schema retains direct/source links and selected profile ID.
Schema v2 adds source-bound subscription stores within the same encrypted native
container and 1 MiB bound; direct/source links plus derived profiles total at most
100. Selection for derived profiles is scoped to the source and remote profile
ID, so equal IDs from different feeds do not alias. The accepted revision floor,
access denial and original per-profile expiry times survive restoration. Links are reparsed, duplicates and invalid selection rejected; no
native acceptance metadata or live connection state is persisted. Restored TT
profiles are inspected again through the official parser before the complete
snapshot is applied. Loading never starts a connection or contacts a server.

Imports wait for initial loading. Writes are serialized and coalesced; each write
uses the preceding committed revision. A save failure, timeout or stale revision
stops automatic writes, retains current memory and displays the limitation. A
timed-out operation may have committed, so no blind retry/reset is issued. Reopen
the app to load fresh state. Platforms without the Windows channel remain
explicitly memory-only. The UI distinguishes loading, saving, saved and failure.

## Actual evidence and remaining limits

Isolated native Windows qualification **PASS** on source `a08114b`:
[run 43751590632](https://github.com/pvlrdnv/liwetun-win/actions/runs/43751590632),
[safe report](evidence/storage-a08114b.json). Actual tests include user roundtrip,
no plaintext canary in the container, stale/concurrent writes, locked/readonly
files, failed replacement cleanup, broad ACL denial, tamper/version preservation,
real symlink denial and explicit reset. A separate LocalSystem process could not
decrypt a verified copy of the valid user's ciphertext; the original user could
still decrypt and remove it. Disposable test directories/service were removed.
Fixture preparation/assertion checks are also listed in the report, not counted
as independent security properties.

The actual Windows GUI worker channel and profile restoration also **PASS** on
source `aa40380`: [run 43752160848](https://github.com/pvlrdnv/liwetun-win/actions/runs/43752160848),
[build evidence](evidence/windows-storage-aa40380.json). The run passed 99 Dart
tests, six Rust tests, analyze, release build and both real desktop channel tests.
The storage case proves save/load, stale-write rejection, malformed-channel
rejection, restored selection, repeated official inspection and no auto-connect;
it then removes the synthetic cache. The unsigned app still rejects service
commands before privileged side effects. No owner-device installation or network
mutation occurred. Desktop Windows 10/11, non-elevated installed GUI, abrupt
power loss and profile reset/recovery UI remain separate acceptance gates.


Subscription cache/controller integration has local synthetic coverage for
source binding, atomic parse/native/capacity failure, restart without auto-start,
replay/revoke persistence, partial deadline retention, expiry and active-session
Stop. A revoke or changed active URI queues Stop even if Start was still pending.
An uncertain Stop is not automatically resent. The UI displays derived names /
stale eligibility; a stale selection cannot start. These client checks do not
replace server-side entitlement/revocation. HTTPS refresh and its UI action are
not enabled yet. A fourth actual Windows desktop-channel case is prepared for
v2 DPAPI save/restore/revoke/replay/cleanup; Windows execution remains pending.

The updated actual Windows app qualification subsequently **PASS** on `b3ffc07`:
[43929885246](https://github.com/pvlrdnv/liwetun-win/actions/runs/43929885246),
[receipt](evidence/windows-subscription-cache-b3ffc07.json). Analyze, 150 Dart /
6 Rust tests, release build and 4 real desktop-channel cases passed. The fourth
case uses real user DPAPI and the official TT parser to restore a source-bound
subscription selection without connecting, persist revoke/revision, reopen,
reject replay and remove the synthetic cache. No HTTP fetch or tunnel start.
This remains Server 2022 CI, not Windows 10/11 installed acceptance.
