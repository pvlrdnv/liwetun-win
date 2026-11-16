part of 'journal.dart';

enum JournalPersistenceState { memoryOnly, loading, saving, saved, blocked }

final class _JournalDisk {
  _JournalDisk(this.journal);
  final Journal journal;
  StorageGateway? _storage;
  Future<void>? _initialization;
  JournalPersistenceState state = JournalPersistenceState.memoryOnly;
  String _revision = '';
  bool _writable = false, _writing = false, _disposed = false;
  bool _needsClear = false, _canReset = false;
  int _generation = 0;
  Timer? _expiry;

  Future<void> initialize(StorageGateway storage) =>
      _initialization ??= _initialize(storage);

  Future<void> _initialize(StorageGateway storage) async {
    if (_disposed) return;
    _storage = storage;
    state = JournalPersistenceState.loading;
    _notify();
    try {
      final reply = await storage.load();
      if (_disposed) return;
      _revision = reply.revision;
      _canReset =
          _revision.isNotEmpty &&
          {
            StorageCode.ok,
            StorageCode.corrupt,
            StorageCode.unsupported,
          }.contains(reply.code);
      if (reply.code == StorageCode.unavailable) {
        state = JournalPersistenceState.memoryOnly;
        _notify();
        return;
      }
      if (reply.code == StorageCode.ok &&
          reply.payload != null &&
          _revision.isNotEmpty) {
        final history = _decode(reply.payload!);
        if (!_needsClear) {
          final recent = journal._events.toList();
          journal._events
            ..clear()
            ..addAll(history)
            ..addAll(recent);
        }
      } else if (reply.code != StorageCode.missing) {
        _failed();
        return;
      }
      _writable = true;
      changed();
    } catch (_) {
      if (!_disposed) _failed();
    }
  }

  void _failed() {
    _writable = false;
    state = JournalPersistenceState.blocked;
    // A user clear issued during loading can reset a corrupt/unsupported file,
    // but a load/parse failure by itself must never delete existing history.
    if (_needsClear && _canReset && !_writing) {
      _writable = true;
      unawaited(_flush());
    } else {
      _notify();
    }
  }

  void changed() {
    if (_disposed) return;
    _generation++;
    _prune();
    if (_writable && !_writing) unawaited(_flush());
  }

  void clear() {
    if (_disposed) return;
    _needsClear = true;
    if (state == JournalPersistenceState.blocked && _canReset) _writable = true;
    changed();
  }

  void _prune() {
    final now = journal._clock().toUtc();
    final cutoff = now.subtract(const Duration(days: 7));
    journal._events.removeWhere((event) => !event.at.isAfter(cutoff));
    final limit = journal.maxEvents < 1000 ? journal.maxEvents : 1000;
    while (journal._events.length > limit) {
      journal._events.removeFirst();
    }
    _expiry?.cancel();
    if (journal._events.isNotEmpty && _storage != null) {
      final first = journal._events
          .map((event) => event.at)
          .reduce((left, right) => left.isBefore(right) ? left : right);
      final remaining = first.add(const Duration(days: 7)).difference(now);
      _expiry = Timer(remaining.isNegative ? Duration.zero : remaining, () {
        changed();
        _notify();
      });
    }
  }

  Future<void> _flush() async {
    _writing = true;
    state = JournalPersistenceState.saving;
    _notify();
    try {
      while (_writable && !_disposed) {
        if (_needsClear) {
          final reply = await _storage!.clear(_revision);
          if (_disposed) return;
          if (reply.code != StorageCode.ok) {
            _canReset = false;
            _failed();
            return;
          }
          _revision = '';
          _needsClear = false;
          _canReset = false;
          if (journal._events.isEmpty) {
            state = JournalPersistenceState.saved;
            break;
          }
        }
        _prune();
        final generation = _generation;
        final payload = jsonEncode({
          'schema_version': 1,
          'events': journal._events.map((event) => event.toJson()).toList(),
        });
        if (utf8.encode(payload).length > 1024 * 1024) {
          _canReset = false;
          _failed();
          return;
        }
        final reply = await _storage!.save(payload, _revision);
        if (_disposed) return;
        if (reply.code != StorageCode.ok || reply.revision.isEmpty) {
          // An uncertain write can have committed; no blind retry/reset follows.
          _canReset = false;
          _failed();
          return;
        }
        _revision = reply.revision;
        _canReset = true;
        if (generation == _generation) {
          state = JournalPersistenceState.saved;
          break;
        }
      }
    } catch (_) {
      if (!_disposed) {
        _canReset = false;
        _failed();
      }
    } finally {
      _writing = false;
    }
    if (!_disposed) _notify();
  }

  List<DiagnosticEvent> _decode(String text) {
    if (text.length > 1024 * 1024 || utf8.encode(text).length > 1024 * 1024) {
      throw const FormatException();
    }
    final data = jsonDecode(text);
    if (data is! Map<String, dynamic> ||
        data.length != 2 ||
        data['schema_version'] is! int ||
        data['schema_version'] != 1 ||
        data['events'] is! List ||
        (data['events'] as List).length > 1000) {
      throw const FormatException();
    }
    final events = <DiagnosticEvent>[];
    for (final item in data['events'] as List) {
      if (item is! Map<String, dynamic> ||
          item.length < 4 ||
          item.length > 5 ||
          !{
            'schema_version',
            'at',
            'event_id',
            'reason_code',
            'protocol',
          }.containsAll(item.keys) ||
          !{
            'schema_version',
            'at',
            'event_id',
            'reason_code',
          }.every(item.containsKey) ||
          item['schema_version'] is! int ||
          item['schema_version'] != 1 ||
          item['at'] is! String) {
        throw const FormatException();
      }
      final at = DateTime.tryParse(item['at'] as String);
      final event = {
        for (final event in EventId.values) event.name: event,
      }[item['event_id']];
      final reason = {
        for (final reason in ReasonCode.values) reason.name: reason,
      }[item['reason_code']];
      final protocol = {
        for (final protocol in Protocol.values) protocol.name: protocol,
      }[item['protocol']];
      if (at == null ||
          !at.isUtc ||
          at.toIso8601String() != item['at'] ||
          at.isAfter(
            journal._clock().toUtc().add(const Duration(minutes: 5)),
          ) ||
          event == null ||
          reason == null ||
          (item.containsKey('protocol') && protocol == null)) {
        throw const FormatException();
      }
      events.add(
        DiagnosticEvent(
          at: at,
          event: event,
          reason: reason,
          protocol: protocol,
        ),
      );
    }
    return events;
  }

  void _notify() {
    if (!_disposed) journal.onPersistenceChanged?.call();
  }

  void dispose() {
    _disposed = true;
    _writable = false;
    _expiry?.cancel();
  }
}
