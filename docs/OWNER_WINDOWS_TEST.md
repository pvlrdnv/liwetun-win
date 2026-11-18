# Windows owner-test scenario — dedicated test signing approved

This document prepares future acceptance on the owner's separate Windows 10 PC.
It is not an instruction to install the current workspace build. The corporate
development PC remains excluded. Windows 11 repeats this acceptance separately
when a suitable environment is available.

On 2026-11-18 the owner explicitly approved trusting a dedicated test certificate
on that separate PC to start manual testing. The opt-in owner_test package mode
uses a distinct 30-day code-signing-only publisher and exports only its public
certificate after installer qualification and CI cleanup pass. The private key
stays nonexportable on the disposable builder. The generic one-day CI publisher
is not delivered. See [handoff instruction source](../tools/packaging/OWNER_TEST_README_RU.txt).
Fingerprint/hash verification must use values delivered separately from the
archive. Uninstall the app before removing its exact test certificate and before
certificate expiry. No development/corporate PC trust-store changes are allowed.
The package is currently being prepared; it is not a stable public release.

## Delivery gates

Provide a signed installer with a verified release manifest, documented signer,
version/digests and uninstall path. The actual GUI/service/runtime must satisfy
the existing signature admission checks. The owner-test exception above permits
only its dedicated public test certificate; signature bypass, developer toolchain
or developer remote access is not required.
Distribution notices, normal routing/DNS/IPv6 cleanup and installer rollback
must be qualified before giving the owner a package that changes the network.
Test credentials/endpoint are separate synthetic fixtures. A live LikeWeb node
or account requires its own authorization; no key is published in these docs.

## Owner steps after a qualified package is delivered

1. Use the separate PC with no competing tunnel. Keep company-required protection
   on the development PC running. Record only the Windows version/build from
   `winver`; no full desktop screenshot or personal machine details are needed.
2. Verify the provided installer version/publisher, install and open LiWeTun as
   an ordinary user. Elevation belongs to installation; the GUI must run without
   a continuous administrator session.
3. Import the supplied private test link. Check its obscured input, selected
   profile and explicit saved state. Close/reopen: the profile returns and the
   app remains disconnected. Never include the private link in the report.
4. Connect and follow the package's bounded test-endpoint scenario. A running
   tunnel label alone does not establish working Internet. Check HTTPS/DNS and
   idle behavior according to that scenario; do not change system DNS/routes
   manually. Stop and confirm ordinary connectivity returns.
5. In Support, review report composition/time period, then save the ZIP. Return
   the ZIP and the step/result description through the agreed conversation.
   LiWeTun does not upload it or message support automatically.
6. Perform only the sleep/network-switch/restart/uninstall cases explicitly
   included in that package's qualified acceptance instructions. If restoration
   fails, stop testing and use the prepared package recovery procedure rather
   than improvising firewall, adapter or DNS changes.

## Safe report implementation

The report's version-3 `summary.json` contains app version, bounded Windows API
major/minor/build numbers, application architecture and last service response
with UTC observation time. An unsuccessful/unavailable service response has
unknown state/runtime fields, not fabricated disconnected/zero values. Optional
traffic observations contain only registered endpoint-client payload totals,
monotonic sample/last-TX/last-RX times and an instance/state epoch. Missing,
invalid or more-than-five-second-old observations have null counters.
Unobserved core versions remain unknown. Event schema stays version1.

Environment observation is a read-only local Win32 call, without SCM access,
network requests, process enumeration, user/computer names or interface/address
collection. The manifested [GetVersionExW API](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw)
can be influenced by compatibility mode; it is diagnostic metadata, not a feature
gate or proof of desktop qualification. Compare it to the owner's `winver` build
when accepting the package. Missing/malformed native results remain unknown.

Protected journal persistence and seven-day/1000-event retention passed actual
Windows GUI roundtrip. In-flight events can be lost on a hard
crash, and a failed write leaves new events in memory. See JOURNAL_STORAGE.md.
The report does not yet replace all manual
observations. No arbitrary shell scripts or corporate software modifications
are part of this owner workflow.


The 20-second window distinguishes measured idle, incoming data, and outgoing
data without a reply. It covers all registered flows, including background tasks;
leaving the application's test socket idle does not make the whole system idle.
TX growth is not proof of remote delivery. These facts cannot establish DNS,
Internet health or server blocking. Missing capability remains visibly unavailable.
SDK, service/GUI and counter traffic CI evidence is separate from live signed GUI
traffic display, desktop owner acceptance and trusted release signing. Internal
interface identifiers from a future attachment bridge are excluded from reports.
