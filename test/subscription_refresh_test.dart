import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/domain/profile_cache.dart';
import 'package:liwetun/domain/subscription_refresh.dart';
import 'package:liwetun/native/storage.dart';
import 'package:liwetun/native/trusttunnel.dart';
import 'package:liwetun/network/subscription_transport.dart';

import 'fixtures.dart';

const sourceUri = 'https://feed.example.invalid/PRIVATE_REFRESH_CANARY';

final class _Storage implements StorageGateway {
  String? payload;
  String revision = '';
  int writes = 0;
  @override
  Future<StorageReply> load() async => payload == null
      ? const StorageReply(StorageCode.missing)
      : StorageReply(StorageCode.ok, payload: payload, revision: revision);
  @override
  Future<StorageReply> save(String value, String expected) async {
    if (expected != revision) return const StorageReply(StorageCode.conflict);
    payload = value;
    revision = (++writes).toRadixString(16).padLeft(64, '0');
    return StorageReply(StorageCode.ok, revision: revision);
  }

  @override
  Future<StorageReply> clear(String expected) async =>
      const StorageReply(StorageCode.denied);
}

final class _Inspector implements TrustTunnelInspector {
  @override
  Future<NativeInspection> inspect(SecretLink link) async =>
      const NativeInspection(
        NativeImportStatus.accepted,
        transport: 2,
        customCertificate: false,
        hasIpv6: false,
      );
}

final class _Transport implements SubscriptionTransport {
  int calls = 0;
  bool closed = false;
  late Future<SubscriptionFetchReply> Function() answer;
  @override
  Future<SubscriptionFetchReply> fetch(SecretLink source) {
    calls++;
    return answer();
  }

  @override
  void close() {
    closed = true;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late AppController controller;
  late _Storage storage;
  late _Transport transport;
  late DateTime clock;
  late bool disposed;
  final sourceId = parseLink(sourceUri).localId;
  Future<void> settle() => Future<void>.delayed(Duration.zero);
  void dispose() {
    if (!disposed) {
      disposed = true;
      controller.dispose();
    }
  }

  setUp(() async {
    clock = now;
    disposed = false;
    storage = _Storage();
    transport = _Transport();
    transport.answer = () async => SubscriptionFetchReply(
      SubscriptionFetchCode.ok,
      payload: feed(revision: transport.calls),
    );
    controller = AppController(
      storage: storage,
      inspector: _Inspector(),
      subscriptionTransport: transport,
      clock: () => clock,
      jitter: (_) => 0,
    );
    await controller.initializeStorage();
    controller.import(sourceUri);
    await settle();
  });
  tearDown(dispose);

  test(
    'manual refresh applies only to its source and records actual application time',
    () async {
      expect(transport.calls, 0);
      expect(await controller.refreshSubscription(), contains('обновлён'));
      await settle();
      expect(transport.calls, 1);
      expect(
        controller.connections
            .where((item) => item.sourceId == sourceId)
            .length,
        1,
      );
      final cached = ProfileCache.decode(storage.payload!, now: clock);
      expect(cached.subscriptions[sourceId]!.lastAppliedAt, clock);
      expect(
        controller.subscriptionNotice(controller.connections.first),
        contains('Обновлено'),
      );
      final events = jsonEncode(
        controller.journal.events.map((event) => event.toJson()).toList(),
      );
      expect(events, isNot(contains('PRIVATE_REFRESH_CANARY')));
      expect(events, isNot(contains(ttPayload)));
      expect(events, isNot(contains(sourceId)));
    },
  );

  test('HTTP failure never revokes or extends the previous cache', () async {
    await controller.refreshSubscription();
    await settle();
    final before = storage.payload;
    clock = clock.add(const Duration(minutes: 1));
    transport.answer = () async => const SubscriptionFetchReply(
      SubscriptionFetchCode.httpStatus,
      payload: 'PRIVATE_REFRESH_CANARY',
    );
    await controller.refreshSubscription(sourceId);
    await settle();
    expect(storage.payload, before);
    expect(controller.connections.length, 2);
    expect(
      ProfileCache.decode(
        storage.payload!,
        now: clock,
      ).subscriptions[sourceId]!.lastAppliedAt,
      now,
    );
  });

  test(
    'transport exceptions and malformed payload preserve the cache without secret output',
    () async {
      await controller.refreshSubscription();
      await settle();
      final before = storage.payload;
      for (final malformed in [true, false]) {
        clock = clock.add(const Duration(seconds: 6));
        transport.answer = () async {
          if (malformed) {
            return const SubscriptionFetchReply(
              SubscriptionFetchCode.ok,
              payload: 'PRIVATE_REFRESH_CANARY',
            );
          }
          throw StateError('PRIVATE_REFRESH_CANARY');
        };
        final message = await controller.refreshSubscription(sourceId);
        expect(message, isNot(contains('PRIVATE_REFRESH_CANARY')));
        await settle();
        expect(storage.payload, before);
      }
    },
  );

  test(
    'overlapping and rapid repeat actions never issue overlapping requests',
    () async {
      final pending = Completer<SubscriptionFetchReply>();
      transport.answer = () => pending.future;
      final first = controller.refreshSubscription(sourceId);
      expect(controller.refreshingSubscription, isTrue);
      expect(
        await controller.refreshSubscription(sourceId),
        contains('уже выполняется'),
      );
      expect(transport.calls, 1);
      pending.complete(
        SubscriptionFetchReply(SubscriptionFetchCode.ok, payload: feed()),
      );
      await first;
      await controller.refreshSubscription(sourceId);
      expect(transport.calls, 1);
    },
  );

  test('dispose ignores late valid data and closes the transport', () async {
    final pending = Completer<SubscriptionFetchReply>();
    transport.answer = () => pending.future;
    final refreshing = controller.refreshSubscription(sourceId);
    dispose();
    pending.complete(
      SubscriptionFetchReply(SubscriptionFetchCode.ok, payload: feed()),
    );
    await refreshing;
    expect(transport.closed, isTrue);
    expect(controller.connections.length, 1);
    expect(
      ProfileCache.decode(storage.payload!, now: clock).subscriptions,
      isEmpty,
    );
  });

  test(
    'multiple sources require an explicit manual source selection',
    () async {
      controller.import('https://second.example.invalid/SYNTHETIC');
      expect(
        await controller.refreshSubscription(),
        contains('нужной подписки'),
      );
      expect(transport.calls, 0);
      await controller.refreshSubscription(sourceId);
      expect(transport.calls, 1);
    },
  );

  testWidgets('startup and periodic refresh are opt-in and serialized', (
    tester,
  ) async {
    try {
      expect(transport.calls, 0);
      controller.enableAutomaticSubscriptionRefresh();
      await tester.pump(Duration.zero);
      expect(transport.calls, 1);
      clock = clock.add(const Duration(minutes: 15));
      await tester.pump(const Duration(minutes: 15));
      expect(transport.calls, 2);
      expect(controller.refreshingSubscription, isFalse);
    } finally {
      dispose();
    }
  });

  testWidgets('automatic failure retries use increasing bounded backoff', (
    tester,
  ) async {
    try {
      transport.answer = () async =>
          const SubscriptionFetchReply(SubscriptionFetchCode.network);
      controller.enableAutomaticSubscriptionRefresh();
      await tester.pump(Duration.zero);
      expect(transport.calls, 1);
      clock = clock.add(const Duration(seconds: 29));
      await tester.pump(const Duration(seconds: 29));
      expect(transport.calls, 1);
      clock = clock.add(const Duration(seconds: 1));
      await tester.pump(const Duration(seconds: 1));
      expect(transport.calls, 2);
      clock = clock.add(const Duration(seconds: 59));
      await tester.pump(const Duration(seconds: 59));
      expect(transport.calls, 2);
      clock = clock.add(const Duration(seconds: 1));
      await tester.pump(const Duration(seconds: 1));
      expect(transport.calls, 3);
    } finally {
      dispose();
    }
  });

  testWidgets(
    'refresh button applies a synthetic feed without showing its URL',
    (tester) async {
      try {
        await tester.pumpWidget(LiWeTunApp(controller: controller));
        await tester.tap(find.text('Серверы').last);
        await tester.pumpAndSettle();
        await tester.tap(
          find.widgetWithText(OutlinedButton, 'Обновить подписку'),
        );
        await tester.pumpAndSettle();
        expect(transport.calls, 1);
        expect(find.text('Synthetic one'), findsOneWidget);
        expect(find.textContaining('Обновлено'), findsOneWidget);
        expect(find.textContaining('PRIVATE_REFRESH_CANARY'), findsNothing);
        expect(find.textContaining(ttPayload), findsNothing);
        expect(tester.takeException(), isNull);
      } finally {
        dispose();
      }
    },
  );

  testWidgets('country/search filters retain source controls and selection', (
    tester,
  ) async {
    try {
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(
          profiles: [
            profile('one'),
            {...profile('two'), 'country': 'DE'},
          ],
        ),
      );
      controller.select(controller.connections.last);
      final selected = controller.selectedId;
      await tester.pumpWidget(LiWeTunApp(controller: controller));
      await tester.tap(find.text('Серверы').last);
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(ChoiceChip, 'NL'));
      await tester.pumpAndSettle();
      expect(find.text('Synthetic one'), findsOneWidget);
      expect(find.text('Synthetic two'), findsNothing);
      expect(controller.selectedId, selected);
      await tester.enterText(find.byType(TextField), 'missing');
      await tester.pumpAndSettle();
      expect(find.textContaining('Подключения не найдены'), findsOneWidget);
      expect(find.byTooltip('Обновить подписку'), findsOneWidget);
      expect(find.textContaining('Пока ничего нет'), findsNothing);
      // Refresh removes the active country's last profile. Reset its filter.
      await controller.applySubscriptionSnapshot(
        sourceId,
        feed(
          revision: 2,
          profiles: [
            {...profile('two'), 'country': 'DE'},
          ],
        ),
      );
      await tester.enterText(find.byType(TextField), '');
      await tester.pumpAndSettle();
      expect(find.text('Synthetic two'), findsOneWidget);
      expect(find.text(sourceUri), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      dispose();
    }
  });

  test(
    'timing policy bounds jitter and retries and refreshes before data expiry',
    () {
      expect(
        subscriptionRefreshDelay(now: now, failures: 0, jitterSeconds: 0),
        const Duration(minutes: 15),
      );
      expect(
        subscriptionRefreshDelay(now: now, failures: 0, jitterSeconds: 120),
        const Duration(minutes: 17),
      );
      expect(
        subscriptionRefreshDelay(now: now, failures: 1, jitterSeconds: 0),
        const Duration(seconds: 30),
      );
      expect(
        subscriptionRefreshDelay(now: now, failures: 2, jitterSeconds: 0),
        const Duration(minutes: 1),
      );
      expect(
        subscriptionRefreshDelay(now: now, failures: 100, jitterSeconds: 30),
        const Duration(minutes: 15, seconds: 30),
      );
      expect(
        subscriptionRefreshDelay(
          now: now,
          failures: 0,
          jitterSeconds: 0,
          earliestDeadline: now.add(const Duration(minutes: 2)),
        ),
        const Duration(seconds: 90),
      );
      expect(
        subscriptionRefreshDelay(
          now: now,
          failures: 0,
          jitterSeconds: 0,
          earliestDeadline: now.add(const Duration(seconds: 5)),
        ),
        const Duration(seconds: 30),
      );
    },
  );
}
