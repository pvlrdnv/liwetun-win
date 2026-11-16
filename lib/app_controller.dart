import 'dart:async';

import 'package:flutter/foundation.dart';

import 'diagnostics/journal.dart';
import 'domain/import_link.dart';
import 'domain/profile_cache.dart';
import 'native/trusttunnel.dart';
import 'native/service.dart';
import 'native/storage.dart';

enum ProfileStorageState { memoryOnly, loading, saved, saving, blocked }

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
    StorageGateway? storage,
  }) : journal = journal ?? Journal(),
       _inspector = inspector ?? const WindowsTrustTunnel(),
       _service = service ?? const WindowsService(),
       _storage = storage ?? const WindowsStorage() {
    this.journal.record(EventId.appStarted);
    this.journal.onPersistenceChanged = () {
      if (!_disposed) notifyListeners();
    };
  }

  final Journal journal;
  final TrustTunnelInspector _inspector;
  final ServiceGateway _service;
  final StorageGateway _storage;
  Future<void> initializeJournal() =>
      journal.initializePersistence(const WindowsStorage.journal());
  ProfileStorageState storageState = ProfileStorageState.memoryOnly;
  StorageCode storageCode = StorageCode.unavailable;
  bool _storageInitialized = false, _storageWritable = false;
  String _storageRevision = '';
  int _profileVersion = 0;
  bool _saving = false;
  String get storageNotice => switch (storageState) {
    ProfileStorageState.loading => 'Загружаем сохранённые подключения…',
    ProfileStorageState.saving => 'Сохраняем подключения…',
    ProfileStorageState.saved =>
      storageCode == StorageCode.missing
          ? 'Защищённое сохранение подключений доступно.'
          : 'Подключения сохранены с защитой вашей учётной записи Windows.',
    ProfileStorageState.memoryOnly =>
      'Ссылки сохраняются только до закрытия приложения.',
    ProfileStorageState.blocked =>
      storageCode == StorageCode.conflict
          ? 'Другое окно изменило подключения. Новые изменения только в памяти; откройте приложение заново.'
          : 'Сохранение не подтверждено. Новые изменения могут остаться только в этом сеансе; проверьте их после перезапуска.',
  };

  Future<void> initializeStorage() async {
    if (_storageInitialized || _disposed) return;
    _storageInitialized = true;
    if (_connections.isNotEmpty) {
      _blockStorage(StorageCode.conflict);
      return;
    }
    storageState = ProfileStorageState.loading;
    notifyListeners();
    try {
      final reply = await _storage.load();
      if (_disposed) return;
      if (reply.code == StorageCode.unavailable) {
        storageState = ProfileStorageState.memoryOnly;
      } else if (reply.code == StorageCode.missing) {
        _storageWritable = true;
        storageState = ProfileStorageState.saved;
      } else if (reply.code == StorageCode.ok &&
          reply.payload != null &&
          reply.revision.isNotEmpty) {
        final cache = ProfileCache.decode(reply.payload!);
        final restored = <LocalConnection>[];
        for (final link in cache.links) {
          NativeInspection? inspection;
          if (link.protocol == Protocol.trusttunnel) {
            inspection = await _inspector.inspect(link.secret);
            if (_disposed) return;
            if (inspection.status != NativeImportStatus.accepted &&
                inspection.status != NativeImportStatus.unavailable) {
              _blockStorage(StorageCode.corrupt);
              return;
            }
          }
          restored.add(
            LocalConnection(restored.length + 1, link, inspection: inspection),
          );
        }
        _connections.addAll(restored);
        _selectedId = cache.selectedId;
        _storageRevision = reply.revision;
        _storageWritable = true;
        storageState = ProfileStorageState.saved;
        journal.record(EventId.profilesRestored);
      } else {
        _blockStorage(
          reply.code == StorageCode.ok ? StorageCode.failed : reply.code,
        );
        return;
      }
      storageCode = reply.code;
      notifyListeners();
    } on CacheException catch (error) {
      if (!_disposed) {
        _blockStorage(
          error.reason == CacheFailure.unsupported
              ? StorageCode.unsupported
              : StorageCode.corrupt,
        );
      }
    } catch (_) {
      if (!_disposed) _blockStorage(StorageCode.failed);
    }
  }

  void _blockStorage(StorageCode code) {
    _storageWritable = false;
    storageCode = code;
    storageState = ProfileStorageState.blocked;
    journal.record(EventId.profileStorageFailed, reason: ReasonCode.ioFailure);
    notifyListeners();
  }

  void _profilesChanged() {
    _profileVersion++;
    if (_storageWritable && !_saving) unawaited(_saveProfiles());
  }

  Future<void> _saveProfiles() async {
    _saving = true;
    storageState = ProfileStorageState.saving;
    try {
      while (_storageWritable && !_disposed) {
        final version = _profileVersion;
        final payload = ProfileCache(
          links: _connections.map((connection) => connection.link),
          selectedId: _selectedId,
        ).encode();
        final reply = await _storage.save(payload, _storageRevision);
        if (_disposed) return;
        if (reply.code != StorageCode.ok || reply.revision.isEmpty) {
          _blockStorage(
            reply.code == StorageCode.ok ? StorageCode.failed : reply.code,
          );
          return;
        }
        _storageRevision = reply.revision;
        storageCode = StorageCode.ok;
        if (version == _profileVersion) {
          storageState = ProfileStorageState.saved;
          journal.record(EventId.profilesSaved);
          break;
        }
      }
    } catch (_) {
      if (!_disposed) _blockStorage(StorageCode.failed);
    } finally {
      _saving = false;
    }
    if (!_disposed) notifyListeners();
  }

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
    if (storageState == ProfileStorageState.loading) {
      return 'Дождитесь загрузки подключений.';
    }
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
      if (index < 0) return message;
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
    if (_disposed) return 'Приложение закрыто.';
    if (storageState == ProfileStorageState.loading) {
      return 'Дождитесь загрузки подключений.';
    }
    try {
      final link = parseLink(value);
      if (_connections.any((item) => item.link.localId == link.localId)) {
        return 'Эта ссылка уже добавлена.';
      }
      if (_connections.length >= ProfileCache.maxProfiles) {
        return 'Достигнут предел: 100 подключений и подписок.';
      }
      _connections.add(LocalConnection(_connections.length + 1, link));
      if (link.kind == ImportKind.profile) _selectedId ??= link.localId;
      journal.record(EventId.importAccepted, protocol: link.protocol);
      _profilesChanged();
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
    if (_disposed ||
        connection.link.kind != ImportKind.profile ||
        !_connections.contains(connection) ||
        _selectedId == connection.link.localId) {
      return;
    }
    _selectedId = connection.link.localId;
    _profilesChanged();
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
      journal.observeService(response);
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
      journal.observeService(response);
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
    journal.onPersistenceChanged = null;
    journal.disposePersistence();
    super.dispose();
  }
}
