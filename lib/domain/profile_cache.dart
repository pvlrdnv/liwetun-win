import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'import_link.dart';
import 'subscription.dart';

enum CacheFailure { malformed, unsupported, tooLarge }

final class CacheException implements Exception {
  const CacheException(this.reason);
  final CacheFailure reason;
  @override
  String toString() => 'CacheException(${reason.name})';
}

/// Private plaintext exists only in memory, immediately around user DPAPI calls.
/// Native inspection and connection state are deliberately never cached.
final class ProfileCache {
  ProfileCache({
    required Iterable<ImportedLink> links,
    this.selectedId,
    this.closeToTray = false,
    Map<String, SubscriptionStore> subscriptions = const {},
  }) : links = List.unmodifiable(links),
       subscriptions = Map.unmodifiable(subscriptions);

  static const maxBytes = 1024 * 1024;
  static const maxProfiles = 100;
  final List<ImportedLink> links;
  final String? selectedId;
  final bool closeToTray;
  final Map<String, SubscriptionStore> subscriptions;

  /// Source-scoped selection never conflates profiles from different feeds.
  static String subscriptionSelectionId(String sourceId, String remoteId) =>
      sha256
          .convert(utf8.encode('subscription\u0000$sourceId\u0000$remoteId'))
          .toString();

  String encode() {
    _validate(links, selectedId, subscriptions);
    final text = jsonEncode({
      'schema_version': closeToTray ? 3 : (subscriptions.isEmpty ? 1 : 2),
      if (closeToTray) 'close_to_tray': true,
      'links': links.map((link) => link.secret.value).toList(),
      'selected_id': selectedId,
      if (subscriptions.isNotEmpty || closeToTray)
        'subscriptions': subscriptions.map(
          (source, store) => MapEntry(source, jsonDecode(store.encodeCache())),
        ),
    });
    _bound(text);
    return text;
  }

  static ProfileCache decode(String text, {DateTime? now}) {
    try {
      _bound(text);
      final data = jsonDecode(text);
      if (data is! Map<String, dynamic>) _bad();
      final version = data['schema_version'];
      if (version is! int || ![1, 2, 3].contains(version)) {
        throw const CacheException(CacheFailure.unsupported);
      }
      final keys = {
        'schema_version',
        'links',
        'selected_id',
        if (version >= 2) 'subscriptions',
        if (version == 3) 'close_to_tray',
      };
      if (data.length != keys.length || !keys.every(data.containsKey)) _bad();
      if (version == 3 && data['close_to_tray'] is! bool) _bad();
      final raw = data['links'];
      if (raw is! List || raw.length > maxProfiles) _bad();
      final links = <ImportedLink>[];
      for (final value in raw) {
        if (value is! String) _bad();
        final link = parseLink(value);
        // Reject non-canonical cache entries instead of silently rewriting them.
        if (link.secret.value != value) _bad();
        links.add(link);
      }
      final selected = data['selected_id'];
      if (selected != null && selected is! String) _bad();
      final subscriptions = <String, SubscriptionStore>{};
      final observedNow = now ?? DateTime.now();
      if (version >= 2) {
        final rawSubscriptions = data['subscriptions'];
        if (rawSubscriptions is! Map<String, dynamic> ||
            rawSubscriptions.length > maxProfiles) {
          _bad();
        }
        for (final entry in rawSubscriptions.entries) {
          subscriptions[entry.key] = SubscriptionStore.restoreCache(
            jsonEncode(entry.value),
            observedNow,
          );
        }
      }
      _validate(links, selected as String?, subscriptions);
      return ProfileCache(
        links: links,
        selectedId: selected,
        closeToTray: version == 3 && data['close_to_tray'] == true,
        subscriptions: subscriptions,
      );
    } on CacheException {
      rethrow;
    } catch (_) {
      // JSON/URI exceptions can contain the original credentials.
      _bad();
    }
  }

  static void _validate(
    List<ImportedLink> links,
    String? selected,
    Map<String, SubscriptionStore> subscriptions,
  ) {
    if (links.length +
            subscriptions.values.fold<int>(
              0,
              (count, store) => count + store.profiles.length,
            ) >
        maxProfiles) {
      throw const CacheException(CacheFailure.tooLarge);
    }
    final ids = <String>{};
    final sources = <String>{};
    final selectable = <String>{};
    for (final link in links) {
      final checked = parseLink(link.secret.value);
      if (checked.secret.value != link.secret.value ||
          checked.localId != link.localId ||
          checked.kind != link.kind ||
          checked.protocol != link.protocol ||
          !ids.add(checked.localId)) {
        _bad();
      }
      if (link.kind == ImportKind.subscription) sources.add(link.localId);
      if (link.kind == ImportKind.profile) selectable.add(link.localId);
    }
    for (final entry in subscriptions.entries) {
      if (!sources.contains(entry.key)) _bad();
      for (final remoteId in entry.value.profiles.keys) {
        if (!selectable.add(subscriptionSelectionId(entry.key, remoteId))) {
          _bad();
        }
      }
    }
    if (selected != null && !selectable.contains(selected)) _bad();
  }

  static void _bound(String text) {
    if (text.length > maxBytes || utf8.encode(text).length > maxBytes) {
      throw const CacheException(CacheFailure.tooLarge);
    }
  }

  static Never _bad() => throw const CacheException(CacheFailure.malformed);

  @override
  String toString() => '[private profile cache]';
}
