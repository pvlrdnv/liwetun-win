import 'dart:convert';

// Synthetic, deliberately not an actual usable TrustTunnel SDK profile.
const ttPayload = 'U1lOVEhFVElDX09OTFlfTk9UX0FfUkVBTF9LRVk';
const tt = 'tt://?$ttPayload';
const hy2 =
    'hy2://synthetic-password@node.example.invalid:443?sni=node.example.invalid';
const vless =
    'vless://00000000-0000-4000-8000-000000000001@node.example.invalid:443?security=reality&type=tcp';

final now = DateTime.utc(2026, 11, 15, 12);

Map<String, Object> profile(String id, {bool allowed = true}) => {
  'id': id,
  'server_id': 'server_$id',
  'name': 'Synthetic $id',
  'country': 'NL',
  'protocol': 'trusttunnel',
  'uri': tt,
  'allowed': allowed,
};

String feed({
  int revision = 1,
  bool complete = true,
  String access = 'active',
  List<Map<String, Object>>? profiles,
  List<String> revoked = const [],
  String validUntil = '2026-11-15T13:00:00Z',
  String accessExpires = '2026-12-15T12:00:00Z',
}) => jsonEncode({
  'schema_version': 1,
  'revision': revision,
  'generated_at': '2026-11-15T12:00:00Z',
  'valid_until': validUntil,
  'access_expires_at': accessExpires,
  'access': access,
  'complete': complete,
  'profiles': profiles ?? [profile('one')],
  'revoked_profile_ids': revoked,
});
