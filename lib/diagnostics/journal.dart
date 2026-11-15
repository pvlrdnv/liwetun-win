import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../domain/import_link.dart';

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

/// Memory-only first slice; no raw logger/stdout/file intermediate exists.
final class Journal {
  Journal({DateTime Function()? clock, this.maxEvents = 1000})
    : assert(maxEvents > 0),
      _clock = clock ?? DateTime.now;

  final DateTime Function() _clock;
  final int maxEvents;
  final Queue<DiagnosticEvent> _events = Queue();

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
  }

  List<DiagnosticEvent> get events => List.unmodifiable(_events);
  ReportPreview get preview => ReportPreview(
    _events.length,
    _events.isEmpty ? null : _events.first.at,
    _events.isEmpty ? null : _events.last.at,
  );

  void clear() => _events.clear();

  Uint8List exportZip() {
    final snapshot = events;
    final summary = {
      'schema_version': 1,
      'app_version': '0.1.0+1',
      'native_service': 'not_integrated',
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
}
