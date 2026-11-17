# Adapter ownership release gate

Status: source audit and required acceptance, not an implemented ownership fix.
The existing held-handle export proves attachment identity, not fresh creation
or authority to configure a pre-existing adapter. HTTPS endpoint correlation
does not close this independent release gate.

## Observed source behavior

Pinned SDK `a1ce3f9d2572e8c3fd6c31e6c31881d307131f40`,
`net/src/os_tunnel_win.cpp`, SHA256
`a6b529fc3159e816eb5e253bc3dc323eebec2ec0afa33d445b07c1f5252a8c04`:
`create_wintun_adapter` first opens an adapter by the configured name. Only when
that fails does it create one, deriving a deterministic requested GUID from the
name. Subsequent session setup assigns addresses using that returned handle.
Thus a successful open/held LUID/endpoint request is insufficient to establish
that LiWeTun created the configured adapter. This is source evidence; no foreign
adapter was reproduced or modified on the owner's device.

The pinned Wintun header separately describes close behavior for opened versus
created handles and permits a system-generated GUID when no GUID is requested.
Changing only the open call, checking only an alias before start or switching
only the GUID does not establish collision/race-safe ownership. The existing
duplicate-alias behavior source audit remains a constraint to test in CI.

## Required implementation boundary

Use a separate guarded SDK source profile and binary, with fresh per-attempt
adapter identity and explicit evidence from the actual create path before any
IP/DNS/route configuration. Do not adopt an adapter solely because its name,
GUID, type, address or current interface index looks expected. Alias absence
checks alone cannot authorize later mutation after a race.

Retain the exact created handle through configuration and teardown. A failed
start may release only that attempt's owned resources. Identity/ownership facts
must be fenced by the current SDK instance/epoch; a stale receipt cannot admit a
later adapter. Internal handles, identifiers and creation tokens remain private
and absent from GUI, diagnostics and owner reports. Unproved ownership refuses
configuration and health qualification.

Keep existing runtime pins and normal package admission unchanged until the
new profile's source/binary/ABI guards and required network regressions pass.
No owner-machine experiment, driver/service install, route/DNS/firewall or trust
change is authorized to investigate this gate.

## Disposable acceptance required

Preserve exact before/after configuration and retained identity of a separate
fixture-owned adapter while testing a pre-existing Wintun alias, a different
adapter type, a collision during creation and concurrent startup attempts.
Include create/configuration failure and Stop during startup. No foreign alias,
address, DNS, routes or adapter lifecycle may be changed; no foreign handle may
be adopted as an owned attachment. Export only closed success/refusal/cleanup
facts, never the interface identifiers used internally to validate preservation.

Then repeat ordinary routing/DNS restoration, service/lease failure, IPv6 and
owned HTTPS/path controls with the new SDK. Keep disposable Server 2022 evidence
separate from installed Windows 10 and Windows 11 acceptance. Trusted signing,
production health endpoint/revocation policy and independent DNS observation
remain additional gates.
