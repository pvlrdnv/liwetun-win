import 'dart:async';
import 'dart:convert';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/diagnostics/journal.dart';
import 'package:liwetun/native/storage.dart';

final base = DateTime.utc(2026, 11, 15, 12);
String revision(int value) => value.toRadixString(16).padLeft(64, '0');
String history(List<DiagnosticEvent> events) => jsonEncode({
  'schema_version': 1,
  'events': events.map((event) => event.toJson()).toList(),
});
Future<void> settle() => Future<void>.delayed(Duration.zero);

final class _Store implements StorageGateway {
  _Store({this.payload, this.code = StorageCode.missing}) {
    if (payload != null || code == StorageCode.corrupt) {
      code = payload == null ? code : StorageCode.ok;
      token = revision(1);
    }
  }
  String? payload;
  String token = '';
  StorageCode code;
  int serial = 1;
  Future<StorageReply>? loadPending;
  Future<StorageReply> Function()? onSave;
  Future<StorageReply> Function()? onClear;
  final saves = <(String, String)>[];
  final clears = <String>[];
  @override
  Future<StorageReply> load() async => loadPending == null
      ? StorageReply(
          code,
          payload: code == StorageCode.ok ? payload : null,
          revision: token,
        )
      : await loadPending!;
  @override
  Future<StorageReply> save(String value, String expected) async {
    saves.add((value, expected));
    final answer = onSave == null
        ? StorageReply(
            expected == token ? StorageCode.ok : StorageCode.conflict,
            revision: revision(++serial),
          )
        : await onSave!();
    if (answer.code == StorageCode.ok) {
      payload = value;
      token = answer.revision;
      code = StorageCode.ok;
    }
    return answer;
  }

  @override
  Future<StorageReply> clear(String expected) async {
    clears.add(expected);
    final answer = onClear == null
        ? StorageReply(
            expected == token ? StorageCode.ok : StorageCode.conflict,
          )
        : await onClear!();
    if (answer.code == StorageCode.ok) {
      payload = null;
      token = '';
      code = StorageCode.missing;
    }
    return answer;
  }
}

Journal journal() {
  final value = Journal(clock: () => base);
  addTearDown(value.disposePersistence);
  return value;
}

void main() {
  test('history and events arriving during load merge atomically', () async {
    final old = DiagnosticEvent(
      at: base.subtract(const Duration(days: 1)),
      event: EventId.importAccepted,
    );
    final store = _Store(payload: history([old]));
    final pending = Completer<StorageReply>();
    store.loadPending = pending.future;
    final log = journal()..record(EventId.appStarted);
    final ready = log.initializePersistence(store);
    log.record(EventId.profilesRestored);
    pending.complete(
      StorageReply(
        StorageCode.ok,
        payload: store.payload,
        revision: store.token,
      ),
    );
    await ready;
    await settle();
    expect(log.events.map((event) => event.event), [
      EventId.importAccepted,
      EventId.appStarted,
      EventId.profilesRestored,
    ]);
    expect(jsonDecode(store.payload!)['events'], hasLength(3));
    expect(log.persistenceState, JournalPersistenceState.saved);
  });

  test(
    'restart preserves typed events with no plaintext or raw logger sink',
    () async {
      final store = _Store();
      final first = journal()..record(EventId.appStarted);
      await first.initializePersistence(store);
      await settle();
      first.disposePersistence();
      final second = journal()..record(EventId.profilesRestored);
      await second.initializePersistence(store);
      await settle();
      expect(second.events.map((event) => event.event), [
        EventId.appStarted,
        EventId.profilesRestored,
      ]);
    },
  );

  test('age and count bounds apply before writing disk snapshots', () async {
    final old = DiagnosticEvent(
      at: base.subtract(const Duration(days: 7)),
      event: EventId.importAccepted,
    );
    final store = _Store(payload: history([old]));
    final log = journal();
    await log.initializePersistence(store);
    for (var i = 0; i < 1100; i++) {
      log.record(EventId.serviceStateObserved);
    }
    await settle();
    expect(log.events, hasLength(1000));
    final saved = jsonDecode(store.payload!)['events'] as List;
    expect(saved, hasLength(1000));
    expect(saved.any((item) => item['event_id'] == 'importAccepted'), false);
    expect(utf8.encode(store.payload!).length, lessThan(1024 * 1024));
  });

  testWidgets(
    'oldest event expires without requiring another connection event',
    (tester) async {
      var now = base;
      final log = Journal(clock: () => now);
      addTearDown(log.disposePersistence);
      final store = _Store();
      log.record(EventId.appStarted);
      await log.initializePersistence(store);
      await tester.pump();
      now = base.add(const Duration(days: 7));
      await tester.pump(const Duration(days: 7));
      await tester.pump();
      expect(log.events, isEmpty);
      expect(jsonDecode(store.payload!)['events'], isEmpty);
    },
  );

  test(
    'records coalesce behind an in-flight write with a fresh revision',
    () async {
      final store = _Store();
      final held = Completer<StorageReply>();
      store.onSave = () => store.saves.length == 1
          ? held.future
          : Future.value(StorageReply(StorageCode.ok, revision: revision(3)));
      final log = journal()..record(EventId.appStarted);
      await log.initializePersistence(store);
      log.record(EventId.profilesSaved);
      expect(store.saves, hasLength(1));
      held.complete(StorageReply(StorageCode.ok, revision: revision(2)));
      await settle();
      expect(store.saves, hasLength(2));
      expect(store.saves.last.$2, revision(2));
      expect(jsonDecode(store.saves.last.$1)['events'], hasLength(2));
    },
  );

  test(
    'clear during pending write serializes deletion before later records',
    () async {
      final store = _Store();
      final held = Completer<StorageReply>();
      store.onSave = () => store.saves.length == 1
          ? held.future
          : Future.value(StorageReply(StorageCode.ok, revision: revision(4)));
      final log = journal()..record(EventId.appStarted);
      await log.initializePersistence(store);
      log.clear();
      log.record(EventId.importRejected);
      held.complete(StorageReply(StorageCode.ok, revision: revision(2)));
      await settle();
      expect(store.clears, [revision(2)]);
      expect(
        jsonDecode(store.payload!)['events'].single['event_id'],
        'importRejected',
      );
      expect(log.events.single.event, EventId.importRejected);
    },
  );

  test('clear during load never resurrects previous history', () async {
    final store = _Store(
      payload: history([
        DiagnosticEvent(at: base, event: EventId.importAccepted),
      ]),
    );
    final pending = Completer<StorageReply>();
    store.loadPending = pending.future;
    final log = journal();
    final ready = log.initializePersistence(store);
    log.clear();
    log.record(EventId.appStarted);
    pending.complete(
      StorageReply(
        StorageCode.ok,
        payload: store.payload,
        revision: store.token,
      ),
    );
    await ready;
    await settle();
    expect(log.events.single.event, EventId.appStarted);
    expect(store.clears, hasLength(1));
    expect(
      jsonDecode(store.payload!)['events'].single['event_id'],
      'appStarted',
    );
  });

  test('corrupt cache stays unchanged until an explicit user clear', () async {
    final store = _Store(code: StorageCode.corrupt);
    final log = journal()..record(EventId.appStarted);
    await log.initializePersistence(store);
    expect(log.persistenceState, JournalPersistenceState.blocked);
    expect(store.saves, isEmpty);
    log.clear();
    await settle();
    expect(store.clears, [revision(1)]);
    expect(store.payload, isNull);
    expect(log.persistenceState, JournalPersistenceState.saved);
  });

  for (final payload in [
    '{PRIVATE_CANARY',
    jsonEncode({'schema_version': 2, 'events': []}),
    jsonEncode({
      'schema_version': 1,
      'events': [
        {
          'schema_version': 1,
          'at': base.toIso8601String(),
          'event_id': 'appStarted',
          'reason_code': 'PRIVATE_CANARY',
        },
      ],
    }),
    jsonEncode({
      'schema_version': 1,
      'events': [
        {
          'schema_version': 1,
          'at': base.toIso8601String(),
          'event_id': 'appStarted',
          'reason_code': 'none',
          'url': 'PRIVATE_CANARY',
        },
      ],
    }),
    history([
      DiagnosticEvent(
        at: base.add(const Duration(hours: 1)),
        event: EventId.appStarted,
      ),
    ]),
  ]) {
    test(
      'unsafe cached history is rejected atomically ${payload.hashCode}',
      () async {
        final store = _Store(payload: payload);
        final log = journal()..record(EventId.appStarted);
        await log.initializePersistence(store);
        expect(log.persistenceState, JournalPersistenceState.blocked);
        expect(log.events, hasLength(1));
        expect(store.saves, isEmpty);
        expect(store.clears, isEmpty);
        final zip = ZipDecoder().decodeBytes(log.exportZip());
        for (final file in zip.files) {
          expect(
            utf8.decode(file.content as List<int>),
            isNot(contains('PRIVATE_CANARY')),
          );
        }
      },
    );
  }

  test(
    'failed or uncertain save stops retries without disrupting new events',
    () async {
      final store = _Store()
        ..onSave = () async => throw const FormatException('PRIVATE_CANARY');
      final log = journal()..record(EventId.appStarted);
      await log.initializePersistence(store);
      await settle();
      log.record(EventId.serviceRequestAccepted);
      await settle();
      expect(log.persistenceState, JournalPersistenceState.blocked);
      expect(log.events, hasLength(2));
      expect(store.saves, hasLength(1));
      expect(store.clears, isEmpty);
    },
  );

  test('failed clear is reported and does not pretend disk deletion', () async {
    final store = _Store(
      payload: history([DiagnosticEvent(at: base, event: EventId.appStarted)]),
    );
    final log = journal();
    await log.initializePersistence(store);
    await settle();
    store.onClear = () async => const StorageReply(StorageCode.denied);
    log.clear();
    await settle();
    expect(log.events, isEmpty);
    expect(store.payload, isNotNull);
    expect(log.persistenceState, JournalPersistenceState.blocked);
  });

  test(
    'disposal ignores a late load and never schedules a new disk write',
    () async {
      final store = _Store();
      final pending = Completer<StorageReply>();
      store.loadPending = pending.future;
      final log = journal();
      final ready = log.initializePersistence(store);
      log.disposePersistence();
      pending.complete(const StorageReply(StorageCode.missing));
      await ready;
      expect(store.saves, isEmpty);
    },
  );
}
