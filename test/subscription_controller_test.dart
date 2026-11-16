import 'dart:async';
import 'dart:convert';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/domain/profile_cache.dart';
import 'package:liwetun/native/service.dart';
import 'package:liwetun/native/storage.dart';
import 'package:liwetun/native/trusttunnel.dart';

import 'fixtures.dart';

const sourceUri = 'https://feed.example.invalid/PRIVATE_CANARY';

final class _Storage implements StorageGateway {
  String? payload;
  String revision = '';
  int writes = 0;
  @override
  Future<StorageReply> load() async => payload == null
      ? const StorageReply(StorageCode.missing)
      : StorageReply(StorageCode.ok, payload: payload, revision: revision);
  @override
  Future<StorageReply> save(String value, String expectedRevision) async {
    if (expectedRevision != revision) {
      return const StorageReply(StorageCode.conflict);
    }
    payload = value;
    revision = (++writes).toRadixString(16).padLeft(64, '0');
    return StorageReply(StorageCode.ok, revision: revision);
  }

  @override
  Future<StorageReply> clear(String expectedRevision) async =>
      const StorageReply(StorageCode.denied);
}

final class _Inspector implements TrustTunnelInspector {
  NativeImportStatus status = NativeImportStatus.accepted;
  @override
  Future<NativeInspection> inspect(SecretLink link) async =>
      NativeInspection(status);
}

final class _Service implements ServiceGateway {
  int starts = 0, stops = 0;
  Future<ServiceStatus>? startAnswer, stopAnswer;
  ServiceStatus current = const ServiceStatus(code: ServiceCode.ok);
  @override
  Future<ServiceStatus> query() async => current;
  @override
  Future<ServiceStatus> start(SecretLink link) async {
    starts++;
    return current =
        await (startAnswer ??
            Future.value(
              const ServiceStatus(
                code: ServiceCode.ok,
                state: ServiceState.tunnelReady,
                runtimeReady: true,
              ),
            ));
  }

  @override
  Future<ServiceStatus> stop() async {
    stops++;
    return current =
        await (stopAnswer ??
            Future.value(const ServiceStatus(code: ServiceCode.ok)));
  }
}

Future<void> settle() => Future<void>.delayed(Duration.zero);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _Storage storage;
  late _Inspector inspector;
  late _Service service;
  late DateTime clock;
  late AppController controller;
  final sourceId = parseLink(sourceUri).localId;
  setUp(() async {
    storage = _Storage();
    inspector = _Inspector();
    service = _Service();
    clock = now;
    controller = AppController(
      storage: storage,
      inspector: inspector,
      service: service,
      clock: () => clock,
    );
    await controller.initializeStorage();
    controller.import(sourceUri);
    await settle();
  });
  tearDown(() => controller.dispose());

  Future<void> prepareSelected() async {
    await controller.applySubscriptionSnapshot(sourceId, feed());
    controller.select(
      controller.connections.singleWhere((item) => item.sourceId != null),
    );
    await settle();
  }

  test(
    'protected envelope restores derived selection without auto-start',
    () async {
      await prepareSelected();
      final selection = controller.selectedId;
      final cached = ProfileCache.decode(storage.payload!, now: now);
      expect(cached.subscriptions[sourceId]!.revision, 1);
      final restored = AppController(
        storage: storage,
        inspector: inspector,
        service: service,
        clock: () => now.add(const Duration(hours: 2)),
      );
      addTearDown(restored.dispose);
      await restored.initializeStorage();
      expect(restored.selectedId, selection);
      expect(restored.selected!.title, 'Synthetic one');
      expect(restored.eligible(restored.selected!), isFalse);
      expect(service.starts, 0);
      expect(await restored.toggleConnection(), contains('истёк'));
      expect(service.starts, 0);
    },
  );

  test('invalid native snapshot and replay never replace saved list', () async {
    await prepareSelected();
    final before = storage.payload;
    inspector.status = NativeImportStatus.malformed;
    await controller.applySubscriptionSnapshot(
      sourceId,
      feed(revision: 2, profiles: [profile('two')]),
    );
    await settle();
    expect(storage.payload, before);
    expect(controller.selected!.title, 'Synthetic one');
    inspector.status = NativeImportStatus.accepted;
    await controller.applySubscriptionSnapshot(sourceId, feed(profiles: []));
    expect(storage.payload, before);
    final events = jsonEncode(
      controller.journal.events.map((event) => event.toJson()).toList(),
    );
    expect(events, isNot(contains('PRIVATE_CANARY')));
    expect(events, isNot(contains(ttPayload)));
    expect(events, isNot(contains(sourceId)));
    for (final file
        in ZipDecoder().decodeBytes(controller.journal.exportZip()).files) {
      final body = utf8.decode(file.content as List<int>);
      expect(body, isNot(contains('PRIVATE_CANARY')));
      expect(body, isNot(contains(ttPayload)));
      expect(body, isNot(contains(sourceId)));
    }
  });

  test(
    'revoke clears selection, persists replay floor and queues one Stop',
    () async {
      await prepareSelected();
      await controller.toggleConnection();
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(revision: 2, access: 'revoked', profiles: []),
      );
      await settle();
      expect(service.starts, 1);
      expect(service.stops, 1);
      expect(controller.selected, isNull);
      expect(
        controller.connections.where((item) => item.sourceId != null),
        isEmpty,
      );
      final saved = ProfileCache.decode(storage.payload!, now: now);
      expect(saved.subscriptions[sourceId]!.revision, 2);
      expect(saved.subscriptions[sourceId]!.profiles, isEmpty);
    },
  );

  test('revocation during pending Start stops it after completion', () async {
    await prepareSelected();
    final pending = Completer<ServiceStatus>();
    service.startAnswer = pending.future;
    final launching = controller.toggleConnection();
    await controller.applySubscriptionSnapshot(
      sourceId,
      feed(revision: 2, access: 'revoked', profiles: []),
    );
    expect(service.stops, 0);
    pending.complete(
      const ServiceStatus(
        code: ServiceCode.ok,
        state: ServiceState.tunnelReady,
        runtimeReady: true,
      ),
    );
    await launching;
    await settle();
    expect(service.stops, 1);
  });

  test(
    'unknown Stop is never automatically resent after another update',
    () async {
      await prepareSelected();
      await controller.toggleConnection();
      service.stopAnswer = Future.value(
        const ServiceStatus(
          code: ServiceCode.timeout,
          state: ServiceState.error,
        ),
      );
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(revision: 2, access: 'revoked', profiles: []),
      );
      await settle();
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(revision: 3, access: 'revoked', profiles: []),
      );
      expect(service.stops, 1);
      expect(controller.stopPossible, isTrue);
      expect(controller.serviceStatus.state, ServiceState.error);
    },
  );

  test(
    'revocation during manual uncertain Stop does not duplicate Stop',
    () async {
      await prepareSelected();
      await controller.toggleConnection();
      final pending = Completer<ServiceStatus>();
      service.stopAnswer = pending.future;
      final stopping = controller.toggleConnection();
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(revision: 2, access: 'revoked', profiles: []),
      );
      pending.complete(
        const ServiceStatus(
          code: ServiceCode.timeout,
          state: ServiceState.error,
        ),
      );
      await stopping;
      await settle();
      expect(service.stops, 1);
      expect(controller.stopPossible, isTrue);
    },
  );

  test(
    'changed active URI stops old session without automatic reconnect',
    () async {
      await prepareSelected();
      await controller.toggleConnection();
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(
          revision: 2,
          profiles: [
            {...profile('one'), 'uri': 'tt://?${'B' * 30}'},
          ],
        ),
      );
      await settle();
      expect(service.stops, 1);
      expect(service.starts, 1);
      expect(controller.selected!.link.secret.value, 'tt://?${'B' * 30}');
    },
  );
  test(
    'oversized merged envelope never changes selection or accepted revision',
    () async {
      await prepareSelected();
      final before = storage.payload;
      final selected = controller.selectedId;
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(revision: 2, profiles: List.generate(100, (i) => profile('p$i'))),
      );
      await settle();
      expect(controller.selectedId, selected);
      expect(storage.payload, before);
      expect(controller.connections.length, 2);
    },
  );

  test(
    'revocation of another source does not stop the active source',
    () async {
      await prepareSelected();
      const otherUri = 'https://other.example.invalid/OTHER_SYNTHETIC';
      final otherId = parseLink(otherUri).localId;
      controller.import(otherUri);
      await controller.applySubscriptionSnapshot(otherId, feed());
      final selections = controller.connections
          .where((item) => item.sourceId != null)
          .map((item) => item.selectionId)
          .toSet();
      expect(selections.length, 2);
      await controller.toggleConnection();
      await controller.applySubscriptionSnapshot(
        otherId,
        feed(revision: 2, access: 'revoked', profiles: []),
      );
      expect(service.starts, 1);
      expect(service.stops, 0);
      expect(controller.selected!.sourceId, sourceId);
    },
  );

  test('partial response never renews an omitted selected profile', () async {
    await prepareSelected();
    await controller.applySubscriptionSnapshot(
      sourceId,
      feed(
        revision: 2,
        complete: false,
        profiles: [profile('two')],
        validUntil: '2026-11-15T14:00:00Z',
      ),
    );
    clock = now.add(const Duration(minutes: 90));
    expect(await controller.toggleConnection(), contains('истёк'));
    expect(service.starts, 0);
    controller.select(
      controller.connections.singleWhere(
        (item) => item.title == 'Synthetic two',
      ),
    );
    await controller.toggleConnection();
    expect(service.starts, 1);
  });

  test(
    'active cache expiry queues Stop without waiting for a user action',
    () async {
      await prepareSelected();
      await controller.toggleConnection();
      clock = now.add(const Duration(hours: 2));
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(service.stops, 1);
      expect(service.starts, 1);
    },
  );
}
