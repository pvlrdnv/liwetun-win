import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/domain/subscription.dart';

import 'fixtures.dart';

void main() {
  test('restart preserves partial deadlines and replay floor', () {
    final store = SubscriptionStore()..apply(feed(), now);
    store.apply(
      feed(
        revision: 2,
        complete: false,
        profiles: [profile('two')],
        validUntil: '2026-11-15T14:00:00Z',
      ),
      now,
    );
    final later = now.add(const Duration(minutes: 90));
    final restored = SubscriptionStore.restoreCache(store.encodeCache(), later);
    expect(restored.revision, 2);
    expect(restored.profiles['one']!.canUse(later), isFalse);
    expect(restored.profiles['two']!.canUse(later), isTrue);
    expect(
      () => restored.apply(feed(revision: 2), now),
      throwsA(isA<SnapshotException>()),
    );
    expect(restored.profiles.length, 2);
  });

  test(
    'restart never resurrects revoked access and keeps stale profiles stale',
    () {
      final store = SubscriptionStore()..apply(feed(), now);
      final expired = SubscriptionStore.restoreCache(
        store.encodeCache(),
        now.add(const Duration(days: 2)),
      );
      expect(
        expired.profiles['one']!.canUse(now.add(const Duration(days: 2))),
        isFalse,
      );
      store.apply(feed(revision: 2, access: 'revoked', profiles: []), now);
      final revoked = SubscriptionStore.restoreCache(store.encodeCache(), now);
      expect(revoked.access, Access.revoked);
      expect(revoked.profiles, isEmpty);
      expect(
        () => revoked.apply(feed(), now),
        throwsA(isA<SnapshotException>()),
      );
      expect(revoked.revision, 2);
    },
  );

  test('uninitialized store roundtrip grants no profile', () {
    final restored = SubscriptionStore.restoreCache(
      SubscriptionStore().encodeCache(),
      now,
    );
    expect(restored.revision, -1);
    expect(restored.profiles, isEmpty);
  });

  test('partial accumulation limit is atomic', () {
    final store = SubscriptionStore()
      ..apply(feed(profiles: List.generate(100, (i) => profile('p$i'))), now);
    expect(
      () => store.apply(
        feed(revision: 2, complete: false, profiles: [profile('overflow')]),
        now,
      ),
      throwsA(isA<SnapshotException>()),
    );
    expect(store.revision, 1);
    expect(store.profiles.length, 100);
  });

  test(
    'legacy cache keeps unknown application time instead of inventing one',
    () {
      final store = SubscriptionStore()..apply(feed(), now);
      expect(store.lastAppliedAt, now);
      final data = jsonDecode(store.encodeCache()) as Map<String, dynamic>;
      data['schema_version'] = 1;
      data.remove('applied_at');
      final restored = SubscriptionStore.restoreCache(jsonEncode(data), now);
      expect(restored.revision, 1);
      expect(restored.lastAppliedAt, isNull);
      final next = SubscriptionStore.restoreCache(store.encodeCache(), now);
      expect(next.lastAppliedAt, now);
      expect(
        () => next.apply(feed(), now.add(const Duration(minutes: 5))),
        throwsA(isA<SnapshotException>()),
      );
      expect(next.lastAppliedAt, now);
    },
  );

  final mutations = <void Function(Map<String, dynamic>)>[
    (data) => data['schema_version'] = 99,
    (data) => data['revision'] = -2,
    (data) => data['applied_at'] = '2026-11-15T13:00:00Z',
    (data) => data['access'] = 'revoked',
    (data) => data['unexpected'] = 'PRIVATE_CANARY',
    (data) => data['profiles'].add(data['profiles'][0]),
    (data) => data['profiles'][0]['profile']['allowed'] = false,
    (data) => data['profiles'][0]['profile']['uri'] = 'PRIVATE_CANARY',
    (data) => data['profiles'][0]['profile']['uri'] = ' $tt',
    (data) => data['profiles'][0]['generated_at'] = '2026-11-15T13:00:00Z',
    (data) => data['profiles'][0]['valid_until'] = '2026-11-17T13:00:00Z',
    (data) => data['profiles'][0]['access_expires_at'] = '2026-11-15T12:30:00Z',
  ];
  for (var index = 0; index < mutations.length; index++) {
    test('invalid cache rejected without leaking input #$index', () {
      final text = (SubscriptionStore()..apply(feed(), now)).encodeCache();
      final data = jsonDecode(text) as Map<String, dynamic>;
      mutations[index](data);
      try {
        SubscriptionStore.restoreCache(jsonEncode(data), now);
        fail('Invalid cache accepted');
      } on SnapshotException catch (error) {
        expect(error.toString(), isNot(contains('PRIVATE_CANARY')));
        expect(error.toString(), isNot(contains(ttPayload)));
      }
    });
  }
}
