# Fresh Windows installer prototype — CI qualification pending

This is installer source for disposable CI, not a package for the owner's PC.
It uses the already qualified GUI artifact plus a production-mode service/SDK
payload. Windows 10/11 x64 remain separately unqualified desktop targets.
No release artifact, private signing key or temporary-root instructions are
published. `windows-package.yml` opts in with `qualify_installer: true`.

The [NSIS compiler](https://nsis.sourceforge.io/Docs/Chapter3.html) is pinned to
3.13 and the downloaded archive SHA256 in `tools/packaging/nsis.json`. The local
archive digest was verified. The original COPYING is included in payload notices;
the script uses zlib compression and Unicode x86 installer machinery for an x64
payload, rejecting non-native-AMD64 hosts. Dependency/license release review is
still open. The compiler is fetched only on a disposable GitHub runner.

The prototype fixes the destination to Program Files/LiWeTun, requires elevation
for installation/removal, serializes setup with a global mutex, and refuses
existing destination directories, service registrations, Start Menu shortcuts
or uninstall keys. There is no upgrade/adoption path. Files inherit a private
administrator/System write policy with Users read/execute; ownership is set to
Administrators before invoking the native service installer. Service admission
retains its own signature/path/ACL checks. The service is demand-start and setup
does not start a service, tunnel or elevated GUI. The finish page directs the
user to launch from Start Menu.

By default native setup resolves only this session's Windows Explorer shell
process and its user SID, checking the Windows image path, session, liveness and
shell identity again. It fails closed without a supported shell. The UAC admin
account is never used as an owner fallback. `/OWNER_SID=` is an explicit advanced
input used by headless CI; native validation requires an actual user SID.
Explorer ownership selection, alternate-admin elevation and desktop interaction
are still pending real Windows 10/11 qualification.

Installer and uninstaller use the same temporary nonexportable CI signer as the
owned payload. NSIS [!uninstfinalize](https://nsis.sourceforge.io/Docs/Chapter5.html#uninstfinalize)
signs the uninstaller before embedding it. Original Wintun/CRT signatures and
payload bytes remain unchanged. This temporary trust exists only during the
disposable job, then the fixture removes its own trust/certificate entries.

A failed native registration attempts to remove only its owned service and
fresh files. Rollback is tested with a synthetically invalid owner. Uninstall
stops/removes only a service whose native command belongs to this protected
installation. The service's absent-registration case is idempotent while still
requiring a trusted native executable. The generated removal list names exact
payload files; directory removal is nonrecursive. Unknown files cause a partial
removal failure while preserving those files, the marker, signed retry
uninstaller and uninstall registration. An absent service can be retried after
the unknown files are moved. This is not a fully transactional uninstall or
upgrade/rollback implementation. In-use GUI behavior remains a separate gate.
Current-user DPAPI files outside the installation remain untouched. No shared
driver-store cleanup or unrelated service/adapter/certificate changes occur.

The CI fixture checks existing-directory preservation, invalid-owner rollback,
fresh install/digests/demand-start registration, duplicate rejection, actual
installed GUI query at restricted medium integrity with fifteen privileged
rights denied, unknown-file preservation, uninstall retry and normal uninstaller
bootstrap. One body test runs an exact signature-verified uninstaller copy with
NSIS `_?=` to wait for its exit; a separate test exercises ordinary self-copy
bootstrap. DNS/routes/adapter snapshots are checked by the enclosing payload
fixture. Only closed result evidence and hashes are uploaded, not this installer.

Current implementation has not yet passed that Windows fixture. Remaining gates:
desktop-owner selection, in-use/reboot/failure recovery, upgrades, release
signing/revocation, final notices and ordinary routing/DNS/IPv6 acceptance. Do not
give this package to the owner or equate CI certificate trust with a public signer.
