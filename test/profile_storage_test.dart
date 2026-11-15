import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/domain/profile_cache.dart';
import 'package:liwetun/native/storage.dart';
import 'package:liwetun/native/trusttunnel.dart';

import 'fixtures.dart';

const revision =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const nextRevision =
    'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

final class _Store implements StorageGateway {
  Future<StorageReply> answer = Future.value(
    const StorageReply(StorageCode.missing),
  );
  final saves = <(String, String)>[];
  Future<StorageReply> Function()? onSave;
  @override
  Future<StorageReply> load() => answer;
  @override
  Future<StorageReply> save(String payload, String expectedRevision) async {
    saves.add((payload, expectedRevision));
    return onSave == null
        ? const StorageReply(StorageCode.ok, revision: revision)
        : await onSave!();
  }

  @override
  Future<StorageReply> clear(String expectedRevision) =>
      throw StateError('No automatic reset');
}

final class _Inspector implements TrustTunnelInspector {
  _Inspector(this.status);
  final NativeImportStatus status;
  int calls = 0;
  @override
  Future<NativeInspection> inspect(SecretLink link) async {
    calls++;
    return NativeInspection(status);
  }
}

Future<void> settle() => Future<void>.delayed(Duration.zero);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(
    () => messenger.setMockMethodCallHandler(WindowsStorage.channel, null),
  );

  test(
    'cache roundtrip includes private links and selection, no runtime state',
    () {
      final link = parseLink(tt);
      final text = ProfileCache(
        links: [link, parseLink('https://feed.example.invalid/private')],
        selectedId: link.localId,
      ).encode();
      final cache = ProfileCache.decode(text);
      expect(cache.links.first.secret.value, tt);
      expect(cache.selectedId, link.localId);
      expect(
        jsonDecode(text).keys,
        unorderedEquals(['schema_version', 'links', 'selected_id']),
      );
      expect(cache.toString(), isNot(contains(ttPayload)));
    },
  );

  for (final data in <Object>[
    [],
    {
      'schema_version': 1,
      'links': [tt],
      'selected_id': null,
      'inspection': 'accepted',
    },
    {
      'schema_version': 2,
      'links': [tt],
      'selected_id': null,
    },
    {
      'schema_version': 1.0,
      'links': [tt],
      'selected_id': null,
    },
    {
      'schema_version': 1,
      'links': [tt, tt],
      'selected_id': null,
    },
    {
      'schema_version': 1,
      'links': [' $tt'],
      'selected_id': null,
    },
    {
      'schema_version': 1,
      'links': ['http://insecure.invalid/SECRET'],
      'selected_id': null,
    },
    {
      'schema_version': 1,
      'links': [tt],
      'selected_id': 'absent',
    },
    {
      'schema_version': 1,
      'links': ['https://feed.example.invalid/private'],
      'selected_id': parseLink('https://feed.example.invalid/private').localId,
    },
    {'schema_version': 1, 'links': List.filled(101, tt), 'selected_id': null},
  ]) {
    test(
      'cache rejects malformed, unsafe or unbounded snapshot ${data.hashCode}',
      () {
        expect(
          () => ProfileCache.decode(jsonEncode(data)),
          throwsA(isA<CacheException>()),
        );
      },
    );
  }

  test('cache parser errors and byte limits do not expose input', () {
    try {
      ProfileCache.decode('{PRIVATE_CANARY');
    } catch (error) {
      expect(error.toString(), isNot(contains('PRIVATE_CANARY')));
    }
    expect(
      () => ProfileCache.decode(List.filled(300000, '😀').join()),
      throwsA(
        isA<CacheException>().having(
          (error) => error.reason,
          'reason',
          CacheFailure.tooLarge,
        ),
      ),
    );
  });

  test(
    'channel has exact private request and validates closed reply',
    () async {
      messenger.setMockMethodCallHandler(WindowsStorage.channel, (call) async {
        expect(call.method, 'save');
        expect(call.arguments, {'payload': 'PRIVATE_CANARY', 'revision': ''});
        return {'code': 'ok', 'payload': null, 'revision': revision};
      });
      final reply = await const WindowsStorage().save('PRIVATE_CANARY', '');
      expect(reply.code, StorageCode.ok);
      expect(reply.toString(), isNot(contains('PRIVATE_CANARY')));
    },
  );

  test(
    'channel rejects malformed responses and sanitizes raw errors',
    () async {
      for (final value in [
        null,
        {'code': 'PRIVATE_CANARY', 'payload': null, 'revision': ''},
        {'code': 'ok', 'payload': tt, 'revision': ''},
        {'code': 'missing', 'payload': tt, 'revision': ''},
        {'code': 'missing', 'payload': null, 'revision': 3},
        {'code': 'ok', 'payload': tt, 'revision': revision, 'extra': true},
      ]) {
        messenger.setMockMethodCallHandler(
          WindowsStorage.channel,
          (_) async => value,
        );
        expect((await const WindowsStorage().load()).code, StorageCode.failed);
      }
      messenger.setMockMethodCallHandler(WindowsStorage.channel, (_) async {
        throw PlatformException(code: 'PRIVATE_CANARY', message: tt);
      });
      final reply = await const WindowsStorage().load();
      expect(reply.code, StorageCode.failed);
      expect(reply.toString(), isNot(contains(ttPayload)));
    },
  );

  test(
    'load blocks import races and revalidates native TT without autoconnect',
    () async {
      final store = _Store();
      final pending = Completer<StorageReply>();
      store.answer = pending.future;
      final inspector = _Inspector(NativeImportStatus.accepted);
      final controller = AppController(storage: store, inspector: inspector);
      addTearDown(controller.dispose);
      final ready = controller.initializeStorage();
      controller.import(hy2);
      expect(controller.connections, isEmpty);
      final link = parseLink(tt);
      pending.complete(
        StorageReply(
          StorageCode.ok,
          payload: ProfileCache(
            links: [link],
            selectedId: link.localId,
          ).encode(),
          revision: revision,
        ),
      );
      await ready;
      expect(inspector.calls, 1);
      expect(
        controller.connections.single.inspection?.status,
        NativeImportStatus.accepted,
      );
      expect(controller.selectedId, link.localId);
      expect(controller.stopPossible, false);
      expect(store.saves, isEmpty);
    },
  );

  test(
    'serialized writes coalesce changes and use the latest committed revision',
    () async {
      final store = _Store();
      final first = Completer<StorageReply>();
      store.onSave = () => store.saves.length == 1
          ? first.future
          : Future.value(
              const StorageReply(StorageCode.ok, revision: nextRevision),
            );
      final controller = AppController(storage: store);
      addTearDown(controller.dispose);
      await controller.initializeStorage();
      controller.import(hy2);
      controller.import(vless);
      controller.select(controller.connections.last);
      expect(store.saves, hasLength(1));
      expect(controller.storageState, ProfileStorageState.saving);
      first.complete(const StorageReply(StorageCode.ok, revision: revision));
      await settle();
      expect(store.saves, hasLength(2));
      expect(store.saves.last.$2, revision);
      final cached = ProfileCache.decode(store.saves.last.$1);
      expect(cached.links, hasLength(2));
      expect(cached.selectedId, parseLink(vless).localId);
      expect(controller.storageState, ProfileStorageState.saved);
    },
  );

  for (final code in [
    StorageCode.corrupt,
    StorageCode.unsupported,
    StorageCode.denied,
    StorageCode.busy,
    StorageCode.failed,
  ]) {
    test(
      'load $code preserves existing file and permits only memory imports',
      () async {
        final store = _Store()..answer = Future.value(StorageReply(code));
        final controller = AppController(storage: store);
        addTearDown(controller.dispose);
        await controller.initializeStorage();
        controller.import(hy2);
        await settle();
        expect(controller.connections, hasLength(1));
        expect(controller.storageState, ProfileStorageState.blocked);
        expect(store.saves, isEmpty);
        expect(controller.journal.exportZip(), isNotEmpty);
      },
    );
  }

  test('save conflict stops retries and keeps newer memory changes', () async {
    final store = _Store()
      ..onSave = () async => const StorageReply(StorageCode.conflict);
    final controller = AppController(storage: store);
    addTearDown(controller.dispose);
    await controller.initializeStorage();
    controller.import(hy2);
    await settle();
    controller.import(vless);
    await settle();
    expect(controller.connections, hasLength(2));
    expect(store.saves, hasLength(1));
    expect(controller.storageCode, StorageCode.conflict);
    expect(controller.storageNotice, contains('Другое окно'));
  });

  test(
    'cached native rejection is atomic and never rewrites old data',
    () async {
      final store = _Store()
        ..answer = Future.value(
          StorageReply(
            StorageCode.ok,
            payload: ProfileCache(
              links: [parseLink(hy2), parseLink(tt)],
            ).encode(),
            revision: revision,
          ),
        );
      final controller = AppController(
        storage: store,
        inspector: _Inspector(NativeImportStatus.insecure),
      );
      addTearDown(controller.dispose);
      await controller.initializeStorage();
      expect(controller.connections, isEmpty);
      expect(controller.storageState, ProfileStorageState.blocked);
      expect(store.saves, isEmpty);
    },
  );

  test('late load and save results are ignored after disposal', () async {
    final pending = Completer<StorageReply>();
    final store = _Store()..answer = pending.future;
    final controller = AppController(storage: store);
    final ready = controller.initializeStorage();
    controller.dispose();
    pending.complete(const StorageReply(StorageCode.missing));
    await ready;
    expect(store.saves, isEmpty);
    final saving = Completer<StorageReply>();
    final next = _Store()..onSave = () => saving.future;
    final app = AppController(storage: next);
    await app.initializeStorage();
    app.import(hy2);
    app.dispose();
    saving.complete(const StorageReply(StorageCode.ok, revision: revision));
    await settle();
  });
}
