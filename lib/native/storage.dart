import 'dart:convert';

import 'package:flutter/services.dart';

import '../domain/profile_cache.dart';

enum StorageCode {
  ok,
  missing,
  corrupt,
  denied,
  busy,
  conflict,
  tooLarge,
  failed,
  unsupported,
  unavailable,
}

final class StorageReply {
  const StorageReply(this.code, {this.payload, this.revision = ''});
  final StorageCode code;
  final String? payload;
  // Private compare-and-swap token. Never a diagnostic identifier.
  final String revision;
  @override
  String toString() => 'StorageReply(${code.name})';
}

abstract interface class StorageGateway {
  Future<StorageReply> load();
  Future<StorageReply> save(String payload, String expectedRevision);
  Future<StorageReply> clear(String expectedRevision);
}

final class WindowsStorage implements StorageGateway {
  const WindowsStorage() : _journal = false;
  const WindowsStorage.journal() : _journal = true;
  final bool _journal;
  static const channel = MethodChannel('top.likeweb.liwetun/storage');
  static bool _revision(String value) =>
      value.isEmpty || RegExp(r'^[0-9a-f]{64}$').hasMatch(value);
  @override
  Future<StorageReply> load() => _call('load');
  @override
  Future<StorageReply> save(String payload, String expectedRevision) {
    if (payload.length > ProfileCache.maxBytes ||
        utf8.encode(payload).length > ProfileCache.maxBytes) {
      return Future.value(const StorageReply(StorageCode.tooLarge));
    }
    if (!_revision(expectedRevision)) {
      return Future.value(const StorageReply(StorageCode.conflict));
    }
    return _call('save', {'payload': payload, 'revision': expectedRevision});
  }

  @override
  Future<StorageReply> clear(String expectedRevision) {
    if (!_revision(expectedRevision)) {
      return Future.value(const StorageReply(StorageCode.conflict));
    }
    return _call('clear', {'revision': expectedRevision});
  }

  Future<StorageReply> _call(String method, [Map<String, Object>? args]) async {
    try {
      final value = await channel
          .invokeMapMethod<String, dynamic>(
            _journal ? '${method}Journal' : method,
            args,
          )
          .timeout(const Duration(seconds: 15));
      if (value == null ||
          value.length != 3 ||
          !{'code', 'payload', 'revision'}.every(value.containsKey)) {
        return const StorageReply(StorageCode.failed);
      }
      final code = {
        for (final item in StorageCode.values) item.name: item,
      }[value['code']];
      final payload = value['payload'];
      final revision = value['revision'];
      if (code == null ||
          code == StorageCode.unavailable ||
          revision is! String ||
          !_revision(revision) ||
          (payload != null &&
              (payload is! String ||
                  payload.length > ProfileCache.maxBytes ||
                  utf8.encode(payload).length > ProfileCache.maxBytes)) ||
          (method == 'load' &&
              code == StorageCode.ok &&
              (payload == null || revision.isEmpty)) ||
          ((method != 'load' || code != StorageCode.ok) && payload != null) ||
          (method == 'save' && code == StorageCode.ok && revision.isEmpty)) {
        return const StorageReply(StorageCode.failed);
      }
      return StorageReply(
        code,
        payload: payload as String?,
        revision: revision,
      );
    } on MissingPluginException {
      return const StorageReply(StorageCode.unavailable);
    } catch (_) {
      // A timed-out write may have committed. Caller must stop automatic writes,
      // retain memory and require a fresh load; never retry the old revision.
      return const StorageReply(StorageCode.failed);
    }
  }
}
