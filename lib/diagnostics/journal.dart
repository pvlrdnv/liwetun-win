import 'dart:collection';
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../domain/import_link.dart';
import '../native/environment.dart';
import '../native/service.dart';
import '../native/storage.dart';

part 'journal_persistence.dart';

enum EventId {
  appStarted,
  importAccepted,
  nativeImportValidated,
  importRejected,
  coreUnavailable,
  serviceRequestAccepted,
  serviceRequestUncertain,
  serviceRequestRejected,
  serviceStateObserved,
  serviceObservationLost,
  reportSaved,
  reportSaveFailed,
  profilesRestored,
  profilesSaved,
  profileStorageFailed,
  subscriptionApplied,
  subscriptionRejected,
  subscriptionAccessLost,
  subscriptionRefreshStarted,
  subscriptionRefreshFailed,
}

enum ReasonCode {
  none,
  malformed,
  unsupported,
  insecure,
  tooLong,
  notInstalled,
  ioFailure,
  serviceUnavailable,
  serviceDenied,
  coreFailure,
  replay,
  stale,
  accessChanged,
  dnsFailure,
  tlsFailure,
  timeout,
  privateAddress,
  httpStatus,
  networkFailure,
  operationBusy,
}

/// No arbitrary string, URI, exception, remote ID or core output is accepted.
final class DiagnosticEvent {
  const DiagnosticEvent({
    required this.at,
    required this.event,
    this.reason = ReasonCode.none,
    this.protocol,
  });
  final DateTime at;
  final EventId event;
  final ReasonCode reason;
  final Protocol? protocol;

  Map<String, Object> toJson() => {
    'schema_version': 1,
    'at': at.toUtc().toIso8601String(),
    'event_id': event.name,
    'reason_code': reason.name,
    if (protocol != null) 'protocol': protocol!.name,
  };
}

final class ReportPreview {
  const ReportPreview(this.count, this.start, this.end);
  final int count;
  final DateTime? start;
  final DateTime? end;
}

/// Closed typed events only; no raw logger/stdout/file intermediate exists.
final class Journal {
  Journal({DateTime Function()? clock, this.maxEvents = 1000})
    : assert(maxEvents > 0),
      _clock = clock ?? DateTime.now;

  final DateTime Function() _clock;
  final int maxEvents;
  final Queue<DiagnosticEvent> _events = Queue();
  late final _JournalDisk _disk = _JournalDisk(this);
  void Function()? onPersistenceChanged;
  JournalPersistenceState get persistenceState => _disk.state;
  Future<void> initializePersistence(StorageGateway storage) =>
      _disk.initialize(storage);
  void disposePersistence() => _disk.dispose();
  String get persistenceNotice => switch (_disk.state) {
    JournalPersistenceState.loading => 'Загружаем историю диагностики…',
    JournalPersistenceState.saving => 'Сохраняем журнал…',
    JournalPersistenceState.saved =>
      'Журнал защищён в Windows: до 7 дней и 1000 событий.',
    JournalPersistenceState.blocked =>
      'Запись журнала недоступна. Текущие события доступны в памяти; состояние файла не подтверждено.',
    JournalPersistenceState.memoryOnly =>
      'Журнал только в памяти текущего сеанса: до 1000 событий.',
  };
  ClientEnvironment environment = const ClientEnvironment();
  ServiceStatus? _serviceObservation;
  DateTime? _serviceObservedAt;
  void observeService(ServiceStatus status) {
    _serviceObservation = status;
    _serviceObservedAt = _clock().toUtc();
  }

  void record(
    EventId event, {
    ReasonCode reason = ReasonCode.none,
    Protocol? protocol,
  }) {
    _events.add(
      DiagnosticEvent(
        at: _clock(),
        event: event,
        reason: reason,
        protocol: protocol,
      ),
    );
    while (_events.length > maxEvents) {
      _events.removeFirst();
    }
    _disk.changed();
  }

  List<DiagnosticEvent> get events {
    final cutoff = _clock().toUtc().subtract(const Duration(days: 7));
    return List.unmodifiable(
      _events.where((event) => event.at.isAfter(cutoff)),
    );
  }

  ReportPreview get preview {
    final snapshot = events;
    return ReportPreview(
      snapshot.length,
      snapshot.isEmpty ? null : snapshot.first.at,
      snapshot.isEmpty ? null : snapshot.last.at,
    );
  }

  void clear() {
    _events.clear();
    _disk.clear();
  }

  Uint8List exportZip() {
    final snapshot = events;
    final summary = {
      'schema_version': 2,
      'app_version': '0.1.0+1',
      'environment': environment.toJson(),
      'journal_storage': _disk.state.name,
      'journal_retention_days': 7,
      'journal_event_limit': maxEvents < 1000 ? maxEvents : 1000,
      'service_observation': {
        'observed_at': _serviceObservedAt?.toIso8601String(),
        'code': _serviceObservation?.code.name,
        'state': _serviceStateKnown ? _serviceObservation?.state.name : null,
        'runtime_ready': _serviceStateKnown
            ? _serviceObservation?.runtimeReady
            : null,
        'core_state': _serviceStateKnown
            ? _serviceObservation?.coreState
            : null,
      },
      'core_versions': <String, String>{},
      'traffic_metrics': 'unknown',
      'event_count': snapshot.length,
      'period_start': snapshot.isEmpty
          ? null
          : snapshot.first.at.toUtc().toIso8601String(),
      'period_end': snapshot.isEmpty
          ? null
          : snapshot.last.at.toUtc().toIso8601String(),
    };
    final lines = snapshot
        .map((event) => jsonEncode(event.toJson()))
        .join('\n');
    final archive = Archive()
      ..addFile(ArchiveFile.string('summary.json', jsonEncode(summary)))
      ..addFile(
        ArchiveFile.string('events.jsonl', lines.isEmpty ? '' : '$lines\n'),
      );
    return Uint8List.fromList(ZipEncoder().encode(archive));
  }

  bool get _serviceStateKnown =>
      _serviceObservation?.code == ServiceCode.ok ||
      _serviceObservation?.code == ServiceCode.coreFailure;
}
