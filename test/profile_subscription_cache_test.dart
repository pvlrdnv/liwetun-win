import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/domain/profile_cache.dart';
import 'package:liwetun/domain/subscription.dart';

import 'fixtures.dart';

void main() {
  final source = parseLink('https://feed.example.invalid/PRIVATE_CANARY');
  final other = parseLink('https://feed.example.invalid/OTHER_SYNTHETIC');

  test('one private envelope binds source, cached deadlines and selection', () {
    final store = SubscriptionStore()..apply(feed(), now);
    final selected = ProfileCache.subscriptionSelectionId(
      source.localId,
      'one',
    );
    final cache = ProfileCache(
      links: [source, parseLink(hy2)],
      selectedId: selected,
      subscriptions: {source.localId: store},
    );
    final text = cache.encode();
    expect(jsonDecode(text)['schema_version'], 2);
    final restored = ProfileCache.decode(
      text,
      now: now.add(const Duration(hours: 2)),
    );
    expect(restored.selectedId, selected);
    expect(restored.subscriptions[source.localId]!.revision, 1);
    expect(
      restored.subscriptions[source.localId]!.profiles['one']!.canUse(
        now.add(const Duration(hours: 2)),
      ),
      isFalse,
    );
    expect(restored.toString(), isNot(contains('PRIVATE_CANARY')));
    expect(restored.encode(), text);
  });

  test('revoked cache stays empty with replay floor in private envelope', () {
    final store = SubscriptionStore()
      ..apply(feed(), now)
      ..apply(feed(revision: 2, access: 'revoked', profiles: []), now);
    final restored = ProfileCache.decode(
      ProfileCache(
        links: [source],
        subscriptions: {source.localId: store},
      ).encode(),
      now: now,
    );
    final cached = restored.subscriptions[source.localId]!;
    expect(cached.access, Access.revoked);
    expect(cached.profiles, isEmpty);
    expect(() => cached.apply(feed(), now), throwsA(isA<SnapshotException>()));
  });

  test(
    'different feeds never share a selection even with equal remote IDs',
    () {
      expect(
        ProfileCache.subscriptionSelectionId(source.localId, 'one'),
        isNot(ProfileCache.subscriptionSelectionId(other.localId, 'one')),
      );
      final store = SubscriptionStore()..apply(feed(), now);
      expect(
        () => ProfileCache(
          links: [other],
          selectedId: ProfileCache.subscriptionSelectionId(
            source.localId,
            'one',
          ),
          subscriptions: {other.localId: store},
        ).encode(),
        throwsA(isA<CacheException>()),
      );
    },
  );

  test('orphaned or source-swapped cache is rejected before restoration', () {
    final store = SubscriptionStore()..apply(feed(), now);
    expect(
      () => ProfileCache(
        links: [other],
        subscriptions: {source.localId: store},
      ).encode(),
      throwsA(isA<CacheException>()),
    );
    final text = ProfileCache(
      links: [source],
      subscriptions: {source.localId: store},
    ).encode();
    final data = jsonDecode(text) as Map<String, dynamic>;
    data['links'] = [other.secret.value];
    expect(
      () => ProfileCache.decode(jsonEncode(data), now: now),
      throwsA(isA<CacheException>()),
    );
  });

  test(
    'combined root and derived capacity cannot exceed protected cache limit',
    () {
      final store = SubscriptionStore()
        ..apply(feed(profiles: List.generate(100, (i) => profile('p$i'))), now);
      expect(
        () => ProfileCache(
          links: [source],
          subscriptions: {source.localId: store},
        ).encode(),
        throwsA(isA<CacheException>()),
      );
      expect(store.profiles.length, 100);
    },
  );

  test('nested malformed cache emits only closed cache exceptions', () {
    final store = SubscriptionStore()..apply(feed(), now);
    final data =
        jsonDecode(
              ProfileCache(
                links: [source],
                subscriptions: {source.localId: store},
              ).encode(),
            )
            as Map<String, dynamic>;
    data['subscriptions'][source.localId]['profiles'][0]['profile']['uri'] =
        'PRIVATE_CANARY';
    try {
      ProfileCache.decode(jsonEncode(data), now: now);
      fail('Malformed nested cache accepted');
    } on CacheException catch (error) {
      expect(error.toString(), isNot(contains('PRIVATE_CANARY')));
      expect(error.toString(), isNot(contains(ttPayload)));
    }
  });
}
