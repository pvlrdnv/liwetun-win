# Production routing configuration — route lifecycle, not Internet acceptance

Production means both `LIWETUN_TEST_NO_GLOBAL_ROUTES` and
`LIWETUN_TEST_TUN_NETWORK` are OFF. It does not mean release qualification.
The opt-in `windows-service.yml` production lifecycle uses only a synthetic,
closed loopback endpoint and an independent armed deadline on a disposable VM.
No owner-device or production-server experiment is involved.

An actual defect was found when the first production-branch observation showed
only DNS/local/multicast routes. The pinned SDK documentation describes default
route arrays, but its [TOML parser](https://github.com/TrustTunnel/TrustTunnelClient/blob/a1ce3f9d2572e8c3fd6c31e6c31881d307131f40/trusttunnel/src/config.cpp#L389)
leaves omitted arrays empty. Its [listener](https://github.com/TrustTunnel/TrustTunnelClient/blob/a1ce3f9d2572e8c3fd6c31e6c31881d307131f40/trusttunnel/src/client.cpp#L357)
passes those arrays directly rather than copying the OS recommended defaults.
The service now supplies `0.0.0.0/0` and `2000::/3` explicitly, plus the pinned
SDK's recommended private/link-local/multicast IPv4 exclusions. Endpoint address
exclusions are additionally managed by the SDK. Local/private network exceptions
are an explicit policy, not a complete firewall/kill-switch implementation.
Existing bounded CI branches and core TLS/authentication remain unchanged.

The corrected route lifecycle **PASS** on `0c211b1`,
[run 43856182784](https://github.com/pvlrdnv/liwetun-win/actions/runs/43856182784):
18 service checks; own-adapter IPv4/IPv6 CIDRs covered fixed address samples,
adapter DNS was observed and all route/DNS/adapter snapshots returned to baseline.
The independent watchdog was armed but did not need intervention. The initial
three-second native observation was extended to six seconds. Only prefix-length
categories and booleans are retained, without interface identifiers/addresses,
usernames, endpoint credentials or core logs. [Evidence](evidence/general-routes-0c211b1.json).

The pinned Windows SDK's DNS setup also creates a WFP dynamic session. Source
inspection shows DNS rules use that session and its destructor closes the WFP
engine. A read-only CI-only probe now counts only the SDK-labelled sessions
belonging to the authenticated own service PID; other session names, SIDs,
usernames and IDs are not exported. The stricter lifecycle fixture requires
dynamic sessions to appear and return to baseline after SDK stop while the
service itself remains running. This additional check is pending Windows proof.
[Windows dynamic-session semantics](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0).

Remaining gates: successful ordinary unbound traffic to a real synthetic
endpoint, effective DNS leak prevention, IPv6 payload delivery, crash/network-
change/suspend recovery and installed Windows 10/11 desktop acceptance. These
route/sample observations cannot establish any of those. Existing H2/H3/DNS
payload acceptance uses bounded, explicitly interface-bound sockets and is
documented separately in TUN_NETWORK_ACCEPTANCE.md. No fabricated connectivity
or release-ready state is derived from this negative lifecycle test.
