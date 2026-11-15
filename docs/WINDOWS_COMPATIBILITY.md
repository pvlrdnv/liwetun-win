# Windows compatibility and owner acceptance

Owner clarified on 2026-11-15: support **Windows 10 x64 and Windows 11 x64**.
Windows 10 is available on a second PC for manual acceptance. Windows 11 is not
currently available to the owner; lack of that machine does not block Windows 10
development, but Windows 11 acceptance must remain separately open.

## Evidence boundary

The pinned Flutter 3.38.10 tools distinguish Windows 10/11 and reject older host
versions (`packages/flutter_tools/lib/src/windows/windows_version_validator.dart`
at `c6f67dede3d4aa1aa7a69dd56a3494a5cde6cc80`). This host check alone does not
qualify the application. Current official [deployment documentation](https://docs.flutter.dev/reference/supported-platforms)
lists Windows 10 and 11; it describes the current Flutter release, not necessarily
every older pinned release. Native service/control targets `_WIN32_WINNT=0x0A00`.

| Target | Actual acceptance |
| --- | --- |
| Windows Server 2022 x64 disposable CI | Native build, signed service/IPC and network fixture evidence recorded separately |
| Windows 10 x64 | Earlier isolated CLI experiment only; installed LiWeTun application acceptance OPEN |
| Windows 11 x64 | Installed application acceptance OPEN |
| ARM64 / 32-bit Windows | Outside the current acceptance target |

Use Windows 10 22H2 as the first manual baseline when available; record the exact
build in the safe acceptance report. Other Windows 10 builds are not qualified
by that result. Server CI cannot substitute for either desktop OS acceptance.

## Owner's corporate device

The owner already uses a corporate tunnel on the development device. Keep that
connection operating. No LiWeTun service, driver, DNS/route changes, certificate
trust changes or corporate client modifications are authorized on that device.
Network experiments remain on disposable GitHub runners.

Manual tests should use the owner's separate Windows 10 PC without a competing
tunnel. The developer need not be installed or connected there: prepare a signed
test package, a short scenario and a sanitized report workflow; the owner runs it
and returns the report, and source changes continue in this repository.

That package is not available yet. It must not ask the owner to disable corporate
protection, install a development toolchain, weaken signature checks or import a
temporary CI certificate. Release signing, installer validation and safe report
collection are prerequisites to owner-machine network testing.
