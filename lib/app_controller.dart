import 'dart:async';

import 'package:flutter/foundation.dart';

import 'diagnostics/journal.dart';
import 'domain/import_link.dart';
import 'native/trusttunnel.dart';
import 'native/service.dart';

final class LocalConnection {
  const LocalConnection(this.number, this.link, {this.inspection});
  final int number;
  final ImportedLink link;
  final NativeInspection? inspection;
  String get title => link.kind == ImportKind.subscription
      ? 'Подписка $number'
      : 'Подключение $number';
}

final class AppController extends ChangeNotifier {
  AppController({
    Journal? journal,
    TrustTunnelInspector? inspector,
    ServiceGateway? service,
  }) : journal = journal ?? Journal(),
       _inspector = inspector ?? const WindowsTrustTunnel(),
       _service = service ?? const WindowsService() {
    this.journal.record(EventId.appStarted);
  }

  final Journal journal;
  final TrustTunnelInspector _inspector;
  final ServiceGateway _service;
  ServiceStatus serviceStatus = const ServiceStatus();
  Timer? _pollTimer;
  bool _requesting = false, _polling = false, _stopPossible = false;
  int _failedPolls = 0;
  int _serviceEpoch = 0;
  bool get requesting => _requesting;
  bool get stopPossible => _stopPossible;
  bool _disposed = false;
  final List<LocalConnection> _connections = [];
  List<LocalConnection> get connections => List.unmodifiable(_connections);
  String? _selectedId;
  String? get selectedId => _selectedId;
  LocalConnection? get selected {
    for (final connection in _connections) {
      if (connection.link.localId == _selectedId) return connection;
    }
    return null;
  }

  Future<String> importValidated(String value) async {
    ImportedLink parsed;
    try {
      parsed = parseLink(value);
    } on LinkException {
      return import(value);
    }
    if (parsed.protocol != Protocol.trusttunnel) return import(value);
    final inspection = await _inspector.inspect(parsed.secret);
    if (_disposed) return 'Приложение закрыто.';
    if (inspection.status != NativeImportStatus.accepted &&
        inspection.status != NativeImportStatus.unavailable) {
      final reason = switch (inspection.status) {
        NativeImportStatus.insecure => ReasonCode.insecure,
        NativeImportStatus.unsupported => ReasonCode.unsupported,
        _ => ReasonCode.malformed,
      };
      journal.record(
        EventId.importRejected,
        reason: reason,
        protocol: Protocol.trusttunnel,
      );
      notifyListeners();
      return switch (inspection.status) {
        NativeImportStatus.insecure =>
          'Ссылка отключает проверку сертификата. Импорт отклонён.',
        NativeImportStatus.unsupported =>
          'Этот вариант TrustTunnel-ссылки пока не поддерживается.',
        _ =>
          'Нативный модуль не смог разобрать TrustTunnel-ссылку. Проверьте её в Like Web.',
      };
    }
    final message = import(value);
    if (inspection.status == NativeImportStatus.accepted) {
      final index = _connections.indexWhere(
        (item) => item.link.localId == parsed.localId,
      );
      _connections[index] = LocalConnection(
        _connections[index].number,
        parsed,
        inspection: inspection,
      );
      journal.record(
        EventId.nativeImportValidated,
        protocol: Protocol.trusttunnel,
      );
      notifyListeners();
      return 'Формат TrustTunnel проверен нативным модулем.';
    }
    return message;
  }

  /// Returns a fixed message; never the user's input or a raw parser exception.
  String import(String value) {
    try {
      final link = parseLink(value);
      if (_connections.any((item) => item.link.localId == link.localId)) {
        return 'Эта ссылка уже добавлена.';
      }
      _connections.add(LocalConnection(_connections.length + 1, link));
      if (link.kind == ImportKind.profile) _selectedId ??= link.localId;
      journal.record(EventId.importAccepted, protocol: link.protocol);
      notifyListeners();
      return link.kind == ImportKind.subscription
          ? 'Ссылка добавлена. Загрузка подписки будет доступна на следующем этапе.'
          : 'Ссылка добавлена. Проверка ядром Windows ещё недоступна.';
    } on LinkException catch (error) {
      final reason = switch (error.reason) {
        ImportFailure.malformed => ReasonCode.malformed,
        ImportFailure.unsupported => ReasonCode.unsupported,
        ImportFailure.insecure => ReasonCode.insecure,
        ImportFailure.tooLong => ReasonCode.tooLong,
      };
      journal.record(EventId.importRejected, reason: reason);
      notifyListeners();
      return switch (error.reason) {
        ImportFailure.insecure =>
          'Ссылка не обеспечивает проверяемое защищённое соединение.',
        ImportFailure.unsupported =>
          'Этот формат ссылки пока не поддерживается.',
        _ => 'Не удалось разобрать ссылку. Проверьте её и попробуйте снова.',
      };
    }
  }

  void select(LocalConnection connection) {
    if (connection.link.kind != ImportKind.profile) return;
    _selectedId = connection.link.localId;
    notifyListeners();
  }

  void connectionUnavailable() {
    journal.record(EventId.coreUnavailable, reason: ReasonCode.notInstalled);
    notifyListeners();
  }

  Future<String> toggleConnection() async {
    if (_requesting || _disposed) return 'Запрос уже выполняется.';
    final connection = selected;
    if (!_stopPossible && connection == null) {
      return 'Сначала добавьте и выберите подключение.';
    }
    if (!_stopPossible && connection!.link.protocol != Protocol.trusttunnel) {
      return 'Подключение этого типа появится позже.';
    }
    _requesting = true;
    _serviceEpoch++;
    notifyListeners();
    final stopping = _stopPossible;
    try {
      final response = stopping
          ? await _safeService(_service.stop)
          : await _safeService(() => _service.start(connection!.link.secret));
      if (_disposed) return 'Приложение закрыто.';
      final uncertain =
          response.code == ServiceCode.timeout ||
          (stopping &&
              response.code != ServiceCode.ok &&
              response.code != ServiceCode.coreFailure);
      serviceStatus = uncertain
          ? ServiceStatus(
              code: response.code,
              state: ServiceState.error,
              runtimeReady: response.runtimeReady,
              coreState: response.coreState,
            )
          : response;
      if (response.code == ServiceCode.ok ||
          response.code == ServiceCode.coreFailure ||
          uncertain) {
        // Timeout is an uncertain outcome: do not issue a second start or claim
        // disconnection until status is reconciled. The next button stops.
        _stopPossible = true;
        _failedPolls = 0;
        _pollTimer?.cancel();
        _pollTimer = Timer.periodic(const Duration(seconds: 1), (_) => _poll());
        if (uncertain) {
          journal.record(
            EventId.serviceRequestUncertain,
            reason: ReasonCode.serviceUnavailable,
          );
        } else if (response.code == ServiceCode.coreFailure) {
          journal.record(
            EventId.serviceRequestRejected,
            reason: ReasonCode.coreFailure,
          );
        } else {
          journal.record(EventId.serviceRequestAccepted);
        }
      } else {
        journal.record(
          EventId.serviceRequestRejected,
          reason: _serviceReason(response.code),
        );
      }
      notifyListeners();
      return _serviceMessage(response.code, stopping);
    } finally {
      _requesting = false;
      if (!_disposed) notifyListeners();
    }
  }

  Future<void> _poll() async {
    if (_polling || _requesting || _disposed) return;
    _polling = true;
    final epoch = _serviceEpoch;
    try {
      final response = await _safeService(_service.query);
      if (_disposed || epoch != _serviceEpoch) return;
      if (response.code == ServiceCode.ok ||
          response.code == ServiceCode.coreFailure) {
        _failedPolls = 0;
        if (response.state != serviceStatus.state) {
          journal.record(EventId.serviceStateObserved);
        }
        serviceStatus = response;
        if (response.state == ServiceState.disconnected) {
          _stopPossible = false;
          _pollTimer?.cancel();
        }
      } else if (++_failedPolls >= 6) {
        serviceStatus = const ServiceStatus(
          code: ServiceCode.timeout,
          state: ServiceState.error,
        );
        _pollTimer?.cancel();
        journal.record(
          EventId.serviceObservationLost,
          reason: ReasonCode.serviceUnavailable,
        );
      }
      notifyListeners();
    } finally {
      _polling = false;
    }
  }

  Future<ServiceStatus> _safeService(
    Future<ServiceStatus> Function() call,
  ) async {
    try {
      return await call().timeout(const Duration(seconds: 16));
    } catch (_) {
      return const ServiceStatus(
        code: ServiceCode.timeout,
        state: ServiceState.error,
      );
    }
  }

  ReasonCode _serviceReason(ServiceCode code) => switch (code) {
    ServiceCode.denied ||
    ServiceCode.untrustedInstallation => ReasonCode.serviceDenied,
    ServiceCode.profileRejected ||
    ServiceCode.malformed => ReasonCode.malformed,
    ServiceCode.coreFailure => ReasonCode.coreFailure,
    _ => ReasonCode.serviceUnavailable,
  };

  String _serviceMessage(ServiceCode code, bool stopping) => switch (code) {
    ServiceCode.ok =>
      stopping
          ? 'Остановка запрошена. Ожидаем подтверждения службы.'
          : 'Запуск запрошен. Работа интернета ещё не подтверждена.',
    ServiceCode.untrustedInstallation =>
      'Для подключения нужна подписанная установленная сборка LiWeTun.',
    ServiceCode.denied =>
      'Служба отклонила доступ. Проверьте установку LiWeTun.',
    ServiceCode.busy =>
      'Подключение занято или ещё останавливается. Повторите после завершения.',
    ServiceCode.profileRejected ||
    ServiceCode.malformed => 'Служба отклонила параметры подключения.',
    ServiceCode.coreFailure =>
      'Ядро не смогло подключиться. Состояние уточняется.',
    ServiceCode.timeout =>
      'Ответ службы не получен. Состояние подключения уточняется.',
    _ =>
      'Служба или ядро Windows ещё не установлены. Сетевые настройки приложением не менялись.',
  };

  void clearJournal() {
    journal.clear();
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _pollTimer?.cancel();
    super.dispose();
  }
}
