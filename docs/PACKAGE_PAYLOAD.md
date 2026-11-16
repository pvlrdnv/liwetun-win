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
Its fixed `--hold-gui` CI mode additionally opens a real visible Flutter window
with that token, discards GUI raw output and coordinates a bounded WM_CLOSE via
PID-scoped ready/stop events. An owned kill-on-close job contains failure cleanup.
Only the exact owned child/job can be terminated on timeout. This verifies a limited
privilege boundary; it does not substitute for a separate ordinary desktop-user
account, Windows 10/11 acceptance or a signed install/uninstall transaction.

No tunnel is started. Route/DNS/adapter snapshots must remain unchanged. The
service, task directory and temporary trust entries are removed; safe evidence
and a post-signing file manifest remain. There is no owner-device installation,
temporary-root instruction, release publication or license-approval claim.

Current status: release GUI runtime staging **PASS** on `9d891c8`,
[run 43837997739](https://github.com/pvlrdnv/liwetun-win/actions/runs/43837997739),
with analyze, 118 Dart, 6 Rust and 3 actual desktop tests. Production-mode signed
payload **PASS** on service `2c79109`,
[run 43841410482](https://github.com/pvlrdnv/liwetun-win/actions/runs/43841410482),
using that exact GUI artifact and SDK run 43752644532.

Payload failures use closed assembly/signing/ACL/query stage identifiers so that
the evidence can distinguish packaging failures without recording raw core data.
Run 43837040458 identified Flutter's generated root `native_assets.json` as the
unexpected input. Staging now admits only the pinned writer's empty format-1.0.0
mapping, with a 1024-byte limit, and includes it in the hashed runtime payload.
Nonempty native mappings require a separate dependency/path review.
Initial payload runs stopped before installation at the CRT publisher-name
check. All ten original signatures were Valid; the captured certificate name
was `Microsoft Windows Software Compatibility Publisher`. Admission accepts
that exact name or `Microsoft Corporation`, still requiring Valid Authenticode.
The CRT files retain their original signatures and bytes.

An initial medium-integrity GUI query returned Denied. The service now grants
only its configured owner metadata-read rights on its own live process/token;
the client retains its complete LocalSystem/signature/path/PID proof. The actual
GUI query now passes with Administrators disabled. Seven process-control and
eight token-control permissions are checked separately and remain denied.
See [service boundary](WINDOWS_SERVICE.md) and
[safe payload evidence](evidence/package-payload-2c79109.json).

The opt-in fresh installer prototype passed its bounded Windows fixture on
`d31a0bb`, [run 43847087250](https://github.com/pvlrdnv/liwetun-win/actions/runs/43847087250).
See [installer scope and remaining gates](INSTALLER.md). Upgrade/rollback,
desktop ownership selection, loader-sharing/recovery, release signing/revocation and
full distribution audit remain open. Public signing process availability has
been asked while independent preparation continues.

Updated GUI `eefbcf7` build 43887262100 includes all 60 SDK/Rust notice bodies in
Flutter's offline license page and verifies every section of the pinned engine
license text. GUI provenance records framework/engine revisions and byte-check
receipts; package admission verifies them and the actual embedded native bytes.
That payload plus all 14 installer groups **PASS** on `17d66b6`,
[43888747188](https://github.com/pvlrdnv/liwetun-win/actions/runs/43888747188),
[safe evidence](evidence/installer-notices-17d66b6.json). Visible medium GUI,
uninstall gating, unchanged network and cleanup passed. These checks do not
approve redistribution rights or qualify release signing/desktop acceptance.
