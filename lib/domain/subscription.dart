import 'dart:convert';

import 'import_link.dart';

enum Access { active, revoked, expired }

enum SnapshotFailure { malformed, unsupported, stale, replay }

final class SnapshotException implements Exception {
  const SnapshotException(this.reason);
  final SnapshotFailure reason;
  @override
  String toString() => 'SnapshotException(${reason.name})';
}

final class ServerProfile {
  const ServerProfile({
    required this.id,
    required this.serverId,
    required this.name,
    required this.country,
    required this.link,
    required this.allowed,
  });
  final String id;
  final String serverId;
  final String name;
  final String country;
  final ImportedLink link;
  final bool allowed;
}

final class Snapshot {
  const Snapshot({
    required this.revision,
    required this.validUntil,
    required this.accessExpiresAt,
    required this.access,
    required this.complete,
    required this.profiles,
    required this.revokedIds,
  });

  final int revision;
  final DateTime validUntil;
  final DateTime accessExpiresAt;
  final Access access;
  final bool complete;
  final List<ServerProfile> profiles;
  final Set<String> revokedIds;

  static Snapshot parse(String text, DateTime now) {
    try {
      return _parse(text, now.toUtc());
    } on SnapshotException {
      rethrow;
    } catch (_) {
      throw const SnapshotException(SnapshotFailure.malformed);
    }
  }

  static Snapshot _parse(String text, DateTime now) {
    if (text.length > 1024 * 1024 || utf8.encode(text).length > 1024 * 1024) {
      _bad();
    }
    final data = jsonDecode(text);
    if (data is! Map<String, dynamic>) _bad();
    _keys(data, {
      'schema_version',
      'revision',
      'generated_at',
      'valid_until',
      'access_expires_at',
      'access',
      'complete',
      'profiles',
      'revoked_profile_ids',
    });
    if (data['schema_version'] is! int || data['schema_version'] != 1) {
      throw const SnapshotException(SnapshotFailure.unsupported);
    }
    final revision = data['revision'];
    if (revision is! int || revision < 0 || revision > 9007199254740991) _bad();
    final generatedAt = _date(data['generated_at']);
    final validUntil = _date(data['valid_until']);
    final accessExpiresAt = _date(data['access_expires_at']);
    if (generatedAt.isAfter(now.add(const Duration(minutes: 5))) ||
        !validUntil.isAfter(generatedAt) ||
        validUntil.difference(generatedAt) > const Duration(hours: 24)) {
      _bad();
    }
    if (!validUntil.isAfter(now)) {
      throw const SnapshotException(SnapshotFailure.stale);
    }
    final access = switch (data['access']) {
      'active' => Access.active,
      'revoked' => Access.revoked,
      'expired' => Access.expired,
      _ => _bad(),
    };
    if (access == Access.active && validUntil.isAfter(accessExpiresAt)) _bad();
    if (access == Access.expired && accessExpiresAt.isAfter(now)) _bad();
    if (data['complete'] is! bool ||
        data['profiles'] is! List ||
        data['revoked_profile_ids'] is! List) {
      _bad();
    }
    final profiles = <ServerProfile>[];
    final seen = <String>{};
    for (final item in data['profiles'] as List) {
      if (item is! Map<String, dynamic>) _bad();
      _keys(item, {
        'id',
        'server_id',
        'name',
        'country',
        'protocol',
        'uri',
        'allowed',
      });
      final id = _id(item['id']);
      final serverId = _id(item['server_id']);
      if (!seen.add(id)) _bad();
      final name = item['name'];
      final country = item['country'];
      if (name is! String ||
          name.trim().isEmpty ||
          name.length > 128 ||
          RegExp(r'[\x00-\x1f\x7f]').hasMatch(name) ||
          country is! String ||
          !RegExp(r'^[A-Z]{2}$').hasMatch(country) ||
          item['uri'] is! String ||
          item['allowed'] is! bool) {
        _bad();
      }
      final link = parseLink(item['uri'] as String);
      if (link.kind != ImportKind.profile ||
          link.protocol?.name != item['protocol']) {
        _bad();
      }
      profiles.add(
        ServerProfile(
          id: id,
          serverId: serverId,
          name: name,
          country: country,
          link: link,
          allowed: item['allowed'] as bool,
        ),
      );
    }
    final revoked = <String>{};
    for (final value in data['revoked_profile_ids'] as List) {
      final id = _id(value);
      if (!revoked.add(id) || seen.contains(id)) _bad();
    }
    if (access != Access.active &&
        (!(data['complete'] as bool) || profiles.isNotEmpty)) {
      _bad();
    }
    return Snapshot(
      revision: revision,
      validUntil: validUntil,
      accessExpiresAt: accessExpiresAt,
      access: access,
      complete: data['complete'] as bool,
      profiles: List.unmodifiable(profiles),
      revokedIds: Set.unmodifiable(revoked),
    );
  }
}

Never _bad() => throw const SnapshotException(SnapshotFailure.malformed);

void _keys(Map<String, dynamic> data, Set<String> keys) {
  if (data.length != keys.length || !keys.every(data.containsKey)) _bad();
}

String _id(dynamic value) {
  if (value is! String || !RegExp(r'^[A-Za-z0-9_-]{1,64}$').hasMatch(value)) {
    _bad();
  }
  return value;
}

DateTime _date(dynamic value) {
  if (value is! String ||
      !RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$').hasMatch(value)) {
    _bad();
  }
  final parsed = DateTime.parse(value);
  // DateTime.parse normalizes out-of-range calendar dates; reject them.
  if (parsed.toIso8601String().replaceFirst('.000Z', 'Z') != value) _bad();
  return parsed;
}

final class CachedProfile {
  const CachedProfile(this.profile, this.validUntil, this.accessExpiresAt);
  final ServerProfile profile;
  final DateTime validUntil;
  final DateTime accessExpiresAt;
  bool canUse(DateTime now) =>
      profile.allowed &&
      now.isBefore(validUntil) &&
      now.isBefore(accessExpiresAt);
}

/// One instance per subscription. All transitions build a new map before commit.
final class SubscriptionStore {
  int _revision = -1;
  Access _access = Access.active;
  Map<String, CachedProfile> _profiles = {};
  int get revision => _revision;
  Access get access => _access;
  Map<String, CachedProfile> get profiles => Map.unmodifiable(_profiles);

  void apply(String json, DateTime now) {
    final snapshot = Snapshot.parse(json, now);
    if (snapshot.revision <= _revision) {
      throw const SnapshotException(SnapshotFailure.replay);
    }
    final next = snapshot.complete
        ? <String, CachedProfile>{}
        : Map<String, CachedProfile>.of(_profiles);
    if (snapshot.access != Access.active) {
      next.clear();
    } else {
      for (final profile in snapshot.profiles) {
        if (profile.allowed) {
          next[profile.id] = CachedProfile(
            profile,
            snapshot.validUntil,
            snapshot.accessExpiresAt,
          );
        } else {
          next.remove(profile.id);
        }
      }
      for (final id in snapshot.revokedIds) {
        next.remove(id);
      }
    }
    _profiles = next;
    _revision = snapshot.revision;
    _access = snapshot.access;
  }
}
