# Windows package payload preparation — not an installer

`windows-native.yml` now stages only release GUI runtime files (executable,
DLLs and data), verifies required assets and rejects unexpected/reparse inputs.
The source commit and every staged file hash accompany a private CI artifact.
No test profile/config, raw logger output, debug symbols or private keys are
part of the payload. The unsigned runtime remains unavailable for service use.

The GUI has a fixed read-only `--service-status` command. It returns only closed
numeric service code/state, runtime availability and core-state observation,
with unknown fields represented as null. It neither starts the service/tunnel
nor initializes Flutter/cache/history. Missing output returns failure, not an
empty success. Signature/path/server checks are the normal service client path;
an unsigned workspace must return untrusted-installation before IPC effects.

`windows-package.yml` takes a successful GUI run, validates provenance/digests,
builds the service with both network test modes OFF, and adds the pinned SDK,
unchanged Wintun, original Microsoft app-local CRT and SDK/Rust notice candidates.
All native payload images must be x64. Third-party Wintun/CRT bytes/signatures
are preserved. The app, service and modified SDK get one temporary common CI
signer, only on a disposable runner. No private key is exported or uploaded.

The fixture creates a fresh protected Program Files directory and task service,
then asks the actual signed GUI executable to query the idle production-mode
service. A separate optional CI helper launches only the adjacent trusted GUI's
fixed query under a medium-integrity restricted token with Administrators
disabled. It uses explicit inherited handles and a fresh non-inheriting user
environment. It cannot choose a program/command or accept profiles/credentials.
Only the exact owned child can be terminated on timeout. This verifies a limited
privilege boundary; it does not substitute for a separate ordinary desktop-user
account, Windows 10/11 acceptance or a signed install/uninstall transaction.

No tunnel is started. Route/DNS/adapter snapshots must remain unchanged. The
service, task directory and temporary trust entries are removed; safe evidence
and a post-signing file manifest remain. There is no owner-device installation,
temporary-root instruction, release publication or license-approval claim.

Current status: local analyze passed; updated GUI CLI/runtime staging and the
production-mode payload fixture still need actual Windows qualification.
Installer authoring, upgrade/rollback, desktop ownership selection, release
signing/revocation and full distribution audit remain open. Public signing
process availability has been asked while independent preparation continues.
