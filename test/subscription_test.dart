import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/domain/subscription.dart';

import 'fixtures.dart';

void main() {
  test('full empty response removes all profiles', () {
    final store = SubscriptionStore()..apply(feed(), now);
    expect(store.profiles.keys, ['one']);
    store.apply(feed(revision: 2, profiles: []), now);
    expect(store.profiles, isEmpty);
    expect(store.revision, 2);
  });

  test(
    'partial preserves absent profiles without extending their lifetime',
    () {
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
      expect(store.profiles.length, 2);
      final later = now.add(const Duration(minutes: 90));
      expect(store.profiles['one']!.canUse(later), isFalse);
      expect(store.profiles['two']!.canUse(later), isTrue);
    },
  );

  test('explicit partial revoke and denied flag remove eligibility', () {
    final store = SubscriptionStore()
      ..apply(feed(profiles: [profile('one'), profile('two')]), now);
    store.apply(
      feed(
        revision: 2,
        complete: false,
        profiles: [profile('two', allowed: false)],
        revoked: ['one'],
      ),
      now,
    );
    expect(store.profiles, isEmpty);
  });

  test('revoked access clears cache', () {
    final store = SubscriptionStore()..apply(feed(), now);
    store.apply(feed(revision: 2, access: 'revoked', profiles: []), now);
    expect(store.access, Access.revoked);
    expect(store.profiles, isEmpty);
  });

  test('expired access clears cache even with past entitlement deadline', () {
    final store = SubscriptionStore()..apply(feed(), now);
    store.apply(
      feed(
        revision: 2,
        access: 'expired',
        profiles: [],
        accessExpires: '2026-11-14T12:00:00Z',
      ),
      now,
    );
    expect(store.access, Access.expired);
    expect(store.profiles, isEmpty);
  });

  test('replay does not alter accepted revision or profiles', () {
    final store = SubscriptionStore()..apply(feed(revision: 3), now);
    for (final revision in [1, 3]) {
      expect(
        () => store.apply(feed(revision: revision, profiles: []), now),
        throwsA(isA<SnapshotException>()),
      );
      expect(store.revision, 3);
      expect(store.profiles.keys, ['one']);
    }
  });

  test('invalid second profile cannot partially apply first profile', () {
    final store = SubscriptionStore()..apply(feed(), now);
    expect(
      () => store.apply(
        feed(
          revision: 2,
          profiles: [
            profile('two'),
            {...profile('three'), 'uri': 'secret malformed URI'},
          ],
        ),
        now,
      ),
      throwsA(isA<SnapshotException>()),
    );
    expect(store.profiles.keys, ['one']);
    expect(store.revision, 1);
  });

  test('cached profile expires exactly at snapshot deadline', () {
    final store = SubscriptionStore()..apply(feed(), now);
    expect(store.profiles['one']!.canUse(now), isTrue);
    expect(
      store.profiles['one']!.canUse(now.add(const Duration(hours: 1))),
      isFalse,
    );
  });

  for (final mutate in <void Function(Map<String, dynamic>)>[
    (data) => data['schema_version'] = 2,
    (data) => data['schema_version'] = 1.0,
    (data) => data['complete'] = 'true',
    (data) => data['revision'] = -1,
    (data) => data['revision'] = 1.5,
    (data) => data['generated_at'] = '2026-11-15T13:00:00Z',
    (data) => data['generated_at'] = '2026-11-15T12:00:00',
    (data) => data['generated_at'] = '2026-11-31T12:00:00Z',
    (data) => data['valid_until'] = '2026-11-15T12:00:00Z',
    (data) => data['valid_until'] = '2026-11-17T12:00:00Z',
    (data) => data['access_expires_at'] = '2026-11-15T12:30:00Z',
    (data) => data['profiles'] = [profile('same'), profile('same')],
    (data) => data['profiles'] = [
      {...profile('one'), 'protocol': 'vless'},
    ],
    (data) => data['revoked_profile_ids'] = ['one'],
    (data) => data['revoked_profile_ids'] = ['other', 'other'],
    (data) => data['access'] = 'revoked',
    (data) => data['access'] = 'expired',
    (data) => data['secret_unknown_field'] = 'not permitted',
  ]) {
    test('invalid snapshot atomic rejection #${mutate.hashCode}', () {
      final store = SubscriptionStore()..apply(feed(), now);
      final data = jsonDecode(feed(revision: 2)) as Map<String, dynamic>;
      mutate(data);
      expect(
        () => store.apply(jsonEncode(data), now),
        throwsA(isA<SnapshotException>()),
      );
      expect(store.revision, 1);
      expect(store.profiles.keys, ['one']);
    });
  }
}
