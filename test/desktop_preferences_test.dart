import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/profile_cache.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/domain/subscription.dart';
import 'fixtures.dart';
import 'package:liwetun/native/desktop.dart';
import 'package:liwetun/native/storage.dart';

final class _Desktop implements DesktopGateway {
  bool available = true;
  bool enabled = false;
  bool throws = false;
  @override
  Future<DesktopStatus> configure(bool closeToTray) async {
    if (throws) throw StateError('SYNTHETIC_PRIVATE_EXCEPTION');
    enabled = closeToTray && available;
    return DesktopStatus(
      available: available,
      closeToTray: enabled,
      visible: true,
    );
  }
}

final class _Storage implements StorageGateway {
  String? payload;
  String revision = '';
  int writes = 0;
  @override
  Future<StorageReply> load() async => payload == null
      ? const StorageReply(StorageCode.missing)
      : StorageReply(StorageCode.ok, payload: payload, revision: revision);
  @override
  Future<StorageReply> save(String text, String expected) async {
    if (expected != revision) return const StorageReply(StorageCode.conflict);
    payload = text;
    revision = (++writes).toString().padLeft(64, '0');
    return StorageReply(StorageCode.ok, revision: revision);
  }

  @override
  Future<StorageReply> clear(String expected) async =>
      const StorageReply(StorageCode.denied);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('tray preference migrates legacy cache and roundtrips strict v3', () {
    final legacy = ProfileCache(links: []).encode();
    expect(jsonDecode(legacy)['schema_version'], 1);
    expect(ProfileCache.decode(legacy).closeToTray, false);
    final encoded = ProfileCache(links: [], closeToTray: true).encode();
    expect(jsonDecode(encoded)['schema_version'], 3);
    expect(ProfileCache.decode(encoded).closeToTray, true);
    final source = parseLink(
      'https://subscription.example.invalid/SYNTHETIC_TRAY_SOURCE',
    );
    final store = SubscriptionStore()..apply(feed(), now);
    final withSubscription = ProfileCache(
      links: [source],
      closeToTray: true,
      subscriptions: {source.localId: store},
      selectedId: ProfileCache.subscriptionSelectionId(source.localId, 'one'),
    );
    final restored = ProfileCache.decode(withSubscription.encode(), now: now);
    expect(restored.closeToTray, true);
    expect(restored.selectedId, withSubscription.selectedId);
    expect(restored.subscriptions[source.localId]!.revision, 1);
    expect(
      restored.subscriptions[source.localId]!.encodeCache(),
      store.encodeCache(),
    );
    for (final replacement in [null, 1, 'true']) {
      final changed = jsonDecode(encoded) as Map<String, dynamic>;
      changed['close_to_tray'] = replacement;
      expect(
        () => ProfileCache.decode(jsonEncode(changed)),
        throwsA(isA<CacheException>()),
      );
    }
  });
  test(
    'enabled preference persists without profiles and reconfigures next launch',
    () async {
      final storage = _Storage();
      final desktop = _Desktop();
      final first = AppController(storage: storage, desktop: desktop);
      await first.initializeStorage();
      await first.initializeDesktop();
      expect(first.desktopAvailable, true);
      expect(first.closeToTray, false);
      await first.setCloseToTray(true);
      await Future<void>.delayed(Duration.zero);
      expect(first.closeToTray, true);
      expect(ProfileCache.decode(storage.payload!).closeToTray, true);
      first.dispose();
      final next = AppController(storage: storage, desktop: desktop);
      try {
        desktop.enabled = false;
        await next.initializeStorage();
        expect(next.closeToTray, true);
        await next.initializeDesktop();
        expect(desktop.enabled, true);
        expect(next.stopPossible, false);
        await next.setCloseToTray(false);
        await Future<void>.delayed(Duration.zero);
        expect(ProfileCache.decode(storage.payload!).closeToTray, false);
      } finally {
        next.dispose();
      }
    },
  );
  test(
    'unavailable tray or channel exception never commits enable preference',
    () async {
      final storage = _Storage();
      final desktop = _Desktop()..available = false;
      final controller = AppController(storage: storage, desktop: desktop);
      try {
        await controller.initializeStorage();
        expect(await controller.setCloseToTray(true), contains('Не удалось'));
        expect(controller.closeToTray, false);
        expect(storage.payload, null);
        desktop.throws = true;
        final message = await controller.setCloseToTray(true);
        expect(message, isNot(contains('SYNTHETIC_PRIVATE_EXCEPTION')));
        expect(controller.closeToTray, false);
        expect(controller.desktopBusy, false);
        expect(storage.payload, null);
      } finally {
        controller.dispose();
      }
    },
  );
}
