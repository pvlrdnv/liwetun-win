# LiWeTun changes to the TrustTunnel SDK

This client contains a modified development build of TrustTunnelClient from
upstream commit `a1ce3f9d2572e8c3fd6c31e6c31881d307131f40`.
Upstream: https://github.com/TrustTunnel/TrustTunnelClient.
The original Apache-2.0 license is retained in
`components/trusttunnel_sdk/LICENSE.txt`; dependency and Wintun notices are
provided alongside it.

LiWeTun privacy profile version 1 changes:

- `platform/windows/src/trusttunnel.cpp`: installs a no-op logging callback
  before configuration parsing, exports `liwetun_core_policy_version`, and makes
  the raw file logger initialization/export/clear functions no-ops.
- `core/src/tunnel.cpp`: disables per-destination connection-information event
  generation, including destination/domain diagnostic instrumentation.
- The copied CMake Conan provider uses the reviewed input recipe lock and records
  the resolved lock/dependency graph for build verification.

These changes are reproduced by `tools/sdk/prepare.py` in the LiWeTun source
repository. Exact upstream input hashes are in `native/sdk/inputs.json`;
the qualified builder's source-profile receipt records preparation-script and
patched-file hashes. The runtime input manifest records the corresponding
source run/commit and original development DLL digest before application signing.

The SDK transport, TLS verification and routing algorithms are retained. The
client supplies its own listener/routing configuration. Original Wintun DLL
bytes/signature are retained and licensed separately.

This is a LiWeTun-modified build, not an unmodified upstream distribution or an
upstream endorsement. This change notice does not approve redistribution rights,
resolve the remaining dependency-source/nested-notice audit, or qualify a release.

For the separately selected immutable-source candidate, dependency recipes also
pin exact Git commits or archive checksums for libevent, libsodium, nghttp2,
nghttp3, NativeLibsCommon, DnsLibs and BoringSSL. BoringSSL uses the official
GitHub mirror archive of the same commit with identical file contents; both
archive recipes specify `.tar.gz` filenames for Conan extraction. Original
library versions, source patch files and build options are retained. Exact
recipe input/output digests and replacements are in `native/sdk/source-pins.json`
in the source repository, reproduced by `tools/sdk/pin_sources.py`. Candidate
packages include `SOURCE_PINS.json` and `CANDIDATE_SOURCE_RECEIPT.json` alongside
these notices. The original archived notice inventory retains its earlier
build provenance; the separate candidate receipt checks the new build's package
notice bodies and identifies packages still relying on source supplements.

Optional aggregate-traffic profile (`tools/sdk/traffic_profile.py`), for the
separately recorded `runtime-traffic.json` candidate only:

- Adds an aggregate-only positive-byte observer before the existing per-connection
  statistics notification threshold. Forwarded deltas contain no flow identifier,
  address, domain or application name. Existing registered endpoint-client flows
  define the scope; this is not a complete DNS or adapter traffic total.
- Adds closed internal/public aggregate event forwarding and an optional callback
  in the pinned TrustTunnel wrapper. Existing raw logger suppression and disabled
  per-destination event generation stay in place.
- Adds a fixed-size read-only snapshot export with state epochs, monotonic times,
  bounded totals and invalidity flags. Counter failures are contained and do not
  escape into routing callbacks. No routing/TLS/DNS/recovery policy change.
- Modified source files have an explicit LiWeTun modification header. Exact
  canonical input, added-header and output digests are recorded separately in
  `traffic-inputs.json` / `traffic-profile.json`. This profile is opt-in and does
  not replace either previous qualified runtime receipt.

Optional SDK-held TUN interface profile (`tools/sdk/attached_tun_profile.py`),
after the aggregate profile, separate from all currently pinned runtime inputs:

- Adds Windows-only read methods to the OS tunnel and TrustTunnel wrapper plus
  the fixed 40-byte `liwetun_attached_tun_v1` export. It reads the held Wintun
  adapter/session, checks index consistency and fences ready-state epoch/time.
- Interface identifiers are internal selection inputs, never diagnostic journal
  output. The caller must serialize with SDK start/stop/destruction. This export
  does not establish adapter ownership, probe traversal or Internet/DNS health.
- No logger, routing, TLS, DNS, adapter creation or recovery policy change.
  All changed files carry an explicit modification header; six baseline digests,
  added-header hashes and output hashes are recorded in `attached-tun-inputs.json`
  and `attached-tun-profile.json`. Default SDK/profile selections are unchanged.

Optional owned-socket correlation (`tools/sdk/owned_probe_profile.py`), after the
attachment profile, separate from every currently admitted runtime:

- Adds one in-memory correlation slot per core instance. A 32-byte request and
  56-byte snapshot contain only closed flags/token/epoch/time/byte facts. TCP
  local/peer tuples stay private, expire logically by a bounded monotonic TTL,
  and must be disarmed by the caller on completion/cancellation.
- Derives an exclusive connected socket's tuple inside the Windows wrapper and
  checks its exact local address entry against the SDK-held TUN. No interface
  enumeration, generic public tuple-registration export or network I/O is added.
- Observes positive bytes at three existing tunnel transfer points, checks the
  actual endpoint/listener, and invalidates on other-path selection/migration.
  Core connection IDs, addresses, domains and application names are not exported.
  Existing raw logger/per-destination event suppression stays intact.
- Adds private C++ core/wrapper methods and three versioned Windows exports;
  no routing/TLS/DNS/recovery decision is changed. Changed vendor files carry an
  explicit modification header. Exact seven source and six added-file digests
  are pinned in `owned-probe-inputs.json` / `owned-probe-profile.json`.
  These facts do not themselves prove an application HTTPS/DNS request or qualify
  a release. A dedicated health endpoint remains unselected.

Optional fresh-adapter profile (`tools/sdk/fresh_adapter_profile.py`), after the
owned-socket profile, outside normal service/package admission:

- Removes the Windows SDK's open-existing-by-name path and deterministic
  name-derived GUID. Creates a private per-attempt GUID and physical alias from
  independent system CSPRNG material, with no configured logical-name adoption.
- Policy 2 pads the physical alias to exactly 127 characters. This depends on
  the pinned original Wintun 0.14.1 DLL's maximum-name duplicate-suffix refusal;
  it is not a general guarantee for other binaries. Policy 1's shorter alias
  failed the controlled foreign-name race and is superseded, not admitted.
- Verifies actual GUID, complete alias, LUID and index on the returned creation
  handle before IP/session setup. Retains private creation observations for the
  existing attached-interface getter and clears them before handle teardown.
  Adds a build-policy export; it is not a per-instance health/ownership receipt.
- Changes only guarded Windows tunnel factory/attachment handling and the build
  marker, plus two private headers. Original signed Wintun bytes and existing
  transport/TLS/privacy behavior remain unchanged. Baseline/header/output digests
  are recorded in `fresh-adapter-inputs.json` / `fresh-adapter-profile.json`.
- Focused native/factory Server 2022 controls passed; full SDK/network, recovery,
  desktop and release qualification remain separate gates. No private identity
  is added to diagnostic output. This notice does not promote this candidate.
