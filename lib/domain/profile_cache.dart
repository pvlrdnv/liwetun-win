import 'dart:convert';

import 'import_link.dart';

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
  ProfileCache({required Iterable<ImportedLink> links, this.selectedId})
    : links = List.unmodifiable(links);

  static const maxBytes = 1024 * 1024;
  static const maxProfiles = 100;
  final List<ImportedLink> links;
  final String? selectedId;

  String encode() {
    _validate(links, selectedId);
    final text = jsonEncode({
      'schema_version': 1,
      'links': links.map((link) => link.secret.value).toList(),
      'selected_id': selectedId,
    });
    _bound(text);
    return text;
  }

  static ProfileCache decode(String text) {
    try {
      _bound(text);
      final data = jsonDecode(text);
      if (data is! Map<String, dynamic> ||
          data.length != 3 ||
          !{'schema_version', 'links', 'selected_id'}.every(data.containsKey)) {
        _bad();
      }
      if (data['schema_version'] is! int || data['schema_version'] != 1) {
        throw const CacheException(CacheFailure.unsupported);
      }
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
      _validate(links, selected as String?);
      return ProfileCache(links: links, selectedId: selected);
    } on CacheException {
      rethrow;
    } catch (_) {
      // JSON/URI exceptions can contain the original credentials.
      _bad();
    }
  }

  static void _validate(List<ImportedLink> links, String? selected) {
    if (links.length > maxProfiles) {
      throw const CacheException(CacheFailure.tooLarge);
    }
    final ids = <String>{};
    for (final link in links) {
      final checked = parseLink(link.secret.value);
      if (checked.secret.value != link.secret.value ||
          checked.localId != link.localId ||
          checked.kind != link.kind ||
          checked.protocol != link.protocol ||
          !ids.add(checked.localId)) {
        _bad();
      }
    }
    if (selected != null &&
        !links.any(
          (link) => link.kind == ImportKind.profile && link.localId == selected,
        )) {
      _bad();
    }
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
