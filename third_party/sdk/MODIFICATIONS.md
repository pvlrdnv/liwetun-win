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
