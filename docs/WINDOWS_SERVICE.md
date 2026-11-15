# Windows service development boundary

LOCAL development only. No owner-machine installation or production changes.

## Implemented

The Flutter service channel queues bounded start/query/stop requests on a worker
thread. Results return on the platform thread. The UI preserves unknown outcomes
after timeouts and ignores observations from before a newer command. SDK ready
means **tunnel started**, not verified Internet traffic.

`LiWeTun` runs as LocalSystem. The installer command accepts one owner SID;
clients cannot supply arbitrary TOML, paths, commands or logging options. Named
pipe frames are bounded to 8192 bytes with a version and request nonce. Remote
pipe access is rejected. Before reading a profile the service checks the caller's
process image, signature, owner SID and session/logon lease. UI process death or
owner logoff initiates stop. The client verifies the pipe server against SCM's
running service PID and LocalSystem identity before transmitting the profile.

Service, client and SDK must have trusted Authenticode signatures from the same
leaf signer in an ACL-protected Program Files directory. Writable ancestors,
unexpected owners and unknown access-granting ACL forms fail closed. The original
Wintun signature and pinned DLL hash are preserved. Signature verification is
offline/cache-only; release revocation freshness policy remains open.

The service validates TT links with the Rust parser, decodes in memory using the
SDK and constructs its own fixed TUN configuration. It clears owned secret
buffers and never accepts arbitrary configuration over IPC. There is no promise
that every allocator/SDK internal copy is erased. Profiles remain memory-only.

The SDK build applies guarded source patches to the pinned upstream revision:
drop raw logger output, disable raw file logging/export, and suppress generation
of per-destination diagnostic events. Admission requires policy marker version 1.
The networking and certificate-validation algorithms are upstream code.

## Actual evidence and limits

Full SDK build [43721746165](https://github.com/pvlrdnv/liwetun-win/actions/runs/43721746165)
passed on Windows Server 2022. Safe source hashes, binary digests and the resolved
Conan lock are archived in `docs/evidence/sdk-43721746165-*`. The lock records
that build's recipe closure; subsequent builds do not yet consume this lock.
Recipe/package revisions and declared license metadata are archived separately
in `sdk-43721746165-packages.json`; null license fields remain unknown.
Actual dependency notices and reproducible rebuild acceptance remain open.
Development runtime artifacts are not a signed release distribution.

Signed service test [43724352857](https://github.com/pvlrdnv/liwetun-win/actions/runs/43724352857)
passed 11 checks without the SDK: real installation, owner query, unsigned
service/client rejection, different signer rejection, different owner SID
rejection even for an administrator, invalid profiles, frame bounds, idempotent
stop and uninstall. See [safe result](evidence/service-b81ce09.json).

`tools/service/qualify.ps1` is restricted to disposable GitHub runners. Temporary
test certificates and trust entries exist only there and are cleaned up. The
optional SDK test creates/closes an actual Wintun adapter, checks suppressed raw
logging and runs the SDK against a synthetic refused loopback endpoint. Its
service is compiled with `LIWETUN_TEST_NO_GLOBAL_ROUTES`: no default routes or
system DNS changes. These tests cannot prove full routing/DNS restoration or a
working external data path. Joint qualification on source `1d727e9` passed **15 checks**:
[run 43726594305](https://github.com/pvlrdnv/liwetun-win/actions/runs/43726594305),
[safe evidence](evidence/service-sdk-1d727e9.json). Both standalone Wintun and
SDK-created adapters were observed and cleaned up; actual SDK state callbacks
were observed. DNS/default routes remained unchanged in bounded mode. Windows release shell compilation and the real Flutter worker channel also
passed on source `5adc6b6`:
[run 43726801060](https://github.com/pvlrdnv/liwetun-win/actions/runs/43726801060),
[safe build evidence](evidence/windows-service-channel-5adc6b6.json). Desktop
query/start/stop correctly return untrusted-installation from an unsigned
workspace without SCM side effects. This does not test an installed signed GUI
with real traffic; the signed client probe and unsigned desktop tests are separate.

## Remaining acceptance

Clean Windows 11 installation, release certificate/installer, real TUN-bound
HTTPS and HTTP/3 traffic, DNS/IPv6 routing and restoration after stop/crash,
non-elevated UI acceptance, fake-server and cross-session adversarial tests,
protected persistence, recovery/tray/startup and dependency notices remain open.
The UI has no verified-Internet state and no fabricated traffic counters.
