# LiWeTun subscription v1 — proposed client contract

Status: local proposal; no LikeWeb route or server implementation exists.
No URL endpoint is assumed. The current UI accepts a personal HTTPS URL but
does not fetch it. The domain parser is tested with synthetic JSON only.

## Transport boundary, to be implemented

User explicitly imports one HTTPS personal URL; treat the full URL as a secret.
Use system TLS, no redirects to any origin, no cookies, no credential forwarding,
no plaintext HTTP. Body <= 1 MiB, timeout and bounded backoff. Consider SSRF and
loopback/private targets before enabling desktop fetch. Never fetch the
TrustTunnel QR wrapper: its fragment is a local credential carrier.
An HTML page or a legacy line-based feed is not this contract.

## Envelope

```json
{
  "schema_version": 1,
  "revision": 1,
  "generated_at": "2026-11-15T12:00:00Z",
  "valid_until": "2026-11-15T13:00:00Z",
  "access_expires_at": "2026-12-15T12:00:00Z",
  "access": "active",
  "complete": true,
  "profiles": [],
  "revoked_profile_ids": []
}
```

All fields mandatory, additional fields rejected. `revision` is a monotonically
increasing integer per personal subscription, not a timestamp. A store is scoped
to exactly one subscription; never merge different accounts. Timestamp format:
UTC RFC3339 with Z. generated_at <= now (5min clock-skew allowance), valid_until
> generated_at, snapshot lifetime <=24h (initial client
policy, subject to review). For active access, valid_until <= access_expires_at.
For expired access, access_expires_at <= now; the envelope itself must be fresh.
valid_until must still be in the future when applied.
These client checks do not replace server entitlement/revocation enforcement.

access: active/revoked/expired. Non-active responses must be complete with no
profiles. A fresh, validated higher revision with revoked/expired access clears
the store. HTTP failures including 401/403 are not yet mapped to revocation;
the future transport must define authoritative origin/response semantics first.

Profile fields (all required): `id`, `server_id` (opaque ASCII IDs, not secrets),
`name` (display-only), `country` (ISO-like 2 uppercase letters), `protocol`
(trusttunnel/hysteria2/vless), `uri` (personal import URI), `allowed` (boolean).
Names, addresses, remote IDs and URI data never enter logs. Remote IDs are not
assumed safe just because the schema allows them. Availability is initially
unknown; no port check or endpoint metadata is interpreted as working traffic.
Monitoring metadata will need a separately versioned extension.

## Atomic reconciliation

Validate the entire response before any change. Reject duplicate IDs, wrong
types, unsafe URI schemes, protocol mismatch, invalid times, replay revision,
unknown schema/fields and contradictory revoke/profile entries.

- Full response replaces this subscription's set. Empty full active response
  is valid and removes its profiles.
- Partial response upserts included profiles; absent profiles stay. Explicit
  revoked IDs and `allowed:false` remove matching profiles in either response.
- A partial response never extends the lifetime of omitted profiles. Each
  cached profile retains its previous snapshot deadline and access deadline.
- A parse/network error leaves both revision and profiles unchanged.
- Expired cached profiles remain visible as stale but cannot connect.
- Revocations remove local eligibility; saved keys still require server-side
  physical revocation. Cached credentials never grant rights on their own.
- Endpoint/URI updates come only from validated snapshots; no DNS/IP rewriting.

For a directly imported key, entitlement is unknown. Server enforcement is
authoritative; do not present an invented subscription deadline or active right.


## Prepared cache codec (not yet connected to Windows storage or GUI)

`SubscriptionStore.encodeCache` / `restoreCache` preserve the accepted revision
floor, access denial, and each retained profile's original generated/valid/access
expiry times. Restoring an old cache never renews a deadline; stale profiles can
remain visible but `canUse` rejects them. A persisted revoke/expiry stays empty
and still refuses replay of older revisions. Restoring is atomic and rejects
unknown fields/versions, duplicate IDs, noncanonical URIs, invalid time bounds
and unsafe profile types with closed exceptions.

The client policy now bounds a snapshot to 100 profiles / 100 explicit revokes
and a store to 100 retained profiles, including partial accumulation. A partial
update exceeding capacity rejects without changing revision or existing data.
The encoded private cache is limited to 1 MiB. Its plaintext is an in-memory
serialization for future inclusion in the existing user-DPAPI envelope, never a
file/log/export format. This codec alone does not implement protected persistence,
HTTPS refresh, GUI reconciliation, active-session revocation or a LikeWeb route.
