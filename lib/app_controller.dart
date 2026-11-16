import 'dart:async';

import 'package:flutter/foundation.dart';

import 'diagnostics/journal.dart';
import 'domain/import_link.dart';
import 'domain/profile_cache.dart';
import 'domain/subscription.dart';
import 'native/trusttunnel.dart';
import 'native/service.dart';
import 'native/storage.dart';

enum ProfileStorageState { memoryOnly, loading, saved, saving, blocked }

final class LocalConnection {
  const LocalConnection(
    this.number,
    this.link, {
    this.inspection,
    this.sourceId,
    this.cachedProfile,
  });
  final int number;
  final ImportedLink link;
  final NativeInspection? inspection;
  final String? sourceId;
  final CachedProfile? cachedProfile;
  String get selectionId => sourceId == null
      ? link.localId
      : ProfileCache.subscriptionSelectionId(
          sourceId!,
          cachedProfile!.profile.id,
        );
  String get title =>
      cachedProfile?.profile.name ??
      (link.kind == ImportKind.subscription
          ? 'Подписка $number'
          : 'Подключение $number');
}

final class AppController extends ChangeNotifier {
  AppController({
    Journal? journal,
    TrustTunnelInspector? inspector,
    ServiceGateway? service,
    StorageGateway? storage,
    DateTime Function()? clock,
  }) : journal = journal ?? Journal(),
       _inspector = inspector ?? const WindowsTrustTunnel(),
       _service = service ?? const WindowsService(),
       _storage = storage ?? const WindowsStorage(),
       _clock = clock ?? DateTime.now {
    this.journal.record(EventId.appStarted);
    this.journal.onPersistenceChanged = () {
      if (!_disposed) notifyListeners();
    };
  }

  final Journal journal;
  final TrustTunnelInspector _inspector;
  final ServiceGateway _service;
  final StorageGateway _storage;
  final DateTime Function() _clock;
  Map<String, SubscriptionStore> _subscriptions = {};
  List<LocalConnection> _derivedConnections = [];
  bool _applyingSubscription = false;
  Timer? _subscriptionExpiry;
  LocalConnection? _activeConnection;
  bool _subscriptionStopQueued = false;
  bool get applyingSubscription => _applyingSubscription;

  bool eligible(LocalConnection connection) =>
      connection.cachedProfile?.canUse(_clock()) ?? true;

  String subscriptionNotice(LocalConnection source) {
    final store = _subscriptions[source.link.localId];
    if (store == null || store.revision < 0) return 'Обновлений ещё не было.';
    if (store.access == Access.revoked) return 'Доступ отозван.';
    if (store.access == Access.expired) return 'Срок доступа завершён.';
    final usable = store.profiles.values
        .where((profile) => profile.canUse(_clock()))
        .length;
    return 'Серверов: ${store.profiles.length} · актуальных: $usable · ревизия ${store.revision}';
  }

  Future<List<LocalConnection>> _inspectSubscription(
    String sourceId,
    SubscriptionStore store,
  ) async {
    final rows = <LocalConnection>[];
    final watch = Stopwatch()..start();
    for (final cached in store.profiles.values) {
      if (_disposed || watch.elapsed >= const Duration(seconds: 15)) {
        throw const SnapshotException(SnapshotFailure.malformed);
      }
      NativeInspection? inspection;
      if (cached.profile.link.protocol == Protocol.trusttunnel) {
        inspection = await _inspector
            .inspect(cached.profile.link.secret)
            .timeout(const Duration(seconds: 15) - watch.elapsed);
        if (inspection.status != NativeImportStatus.accepted &&
            inspection.status != NativeImportStatus.unavailable) {
          throw const SnapshotException(SnapshotFailure.malformed);
        }
        if (inspection.status == NativeImportStatus.unavailable) {
          inspection = null;
        }
      }
      rows.add(
        LocalConnection(
          rows.length + 1,
          cached.profile.link,
          inspection: inspection,
          sourceId: sourceId,
          cachedProfile: cached,
        ),
      );
    }
    return rows;
  }

  /// Only a validated transport may supply a snapshot; never expose its body to logs.
  Future<String> applySubscriptionSnapshot(String sourceId, String text) async {
    if (_disposed) return 'Приложение закрыто.';
    if (_applyingSubscription || storageState == ProfileStorageState.loading) {
      return 'Дождитесь завершения текущей операции.';
    }
    if (!_connections.any(
      (item) =>
          item.link.localId == sourceId &&
          item.link.kind == ImportKind.subscription,
    )) {
      return 'Подписка не найдена.';
    }
    _applyingSubscription = true;
    notifyListeners();
    try {
      final previous = _subscriptions[sourceId];
      final next = previous == null
          ? SubscriptionStore()
          : SubscriptionStore.restoreCache(previous.encodeCache(), _clock());
      next.apply(text, _clock());
      final inspected = await _inspectSubscription(sourceId, next);
      if (_disposed) return 'Приложение закрыто.';
      final stores = {..._subscriptions, sourceId: next};
      final derived = [
        ..._derivedConnections.where((item) => item.sourceId != sourceId),
        ...inspected,
      ];
      final all = [..._connections, ...derived];
      var selection = _selectedId;
      if (!all.any((item) => item.selectionId == selection)) selection = null;
      // Validate capacity, source binding and the entire private envelope before
      // committing any UI/cache/revision changes.
      ProfileCache(
        links: _connections.map((item) => item.link),
        subscriptions: stores,
        selectedId: selection,
      ).encode();
      _subscriptions = stores;
      _derivedConnections = derived;
      _selectedId = selection;
      _profilesChanged();
      journal.record(EventId.subscriptionApplied);
      _scheduleSubscriptionExpiry();
      _enforceSubscriptionAccess();
      notifyListeners();
      return 'Список подписки обновлён.';
    } on SnapshotException catch (error) {
      if (!_disposed) {
        journal.record(
          EventId.subscriptionRejected,
          reason: error.reason == SnapshotFailure.replay
              ? ReasonCode.replay
              : error.reason == SnapshotFailure.stale
              ? ReasonCode.stale
              : ReasonCode.malformed,
        );
      }
      return 'Подписка отклонена. Прежний список сохранён.';
    } on CacheException {
      if (!_disposed) {
        journal.record(
          EventId.subscriptionRejected,
          reason: ReasonCode.tooLong,
        );
      }
      return 'Список слишком большой. Прежние подключения сохранены.';
    } catch (_) {
      if (!_disposed) {
        journal.record(
          EventId.subscriptionRejected,
          reason: ReasonCode.ioFailure,
        );
      }
      return 'Не удалось проверить подписку. Прежний список сохранён.';
    } finally {
      _applyingSubscription = false;
      if (!_disposed) notifyListeners();
    }
  }

  void _scheduleSubscriptionExpiry() {
    _subscriptionExpiry?.cancel();
    DateTime? next;
    final now = _clock();
    for (final store in _subscriptions.values) {
      for (final profile in store.profiles.values) {
        if (!profile.canUse(now)) continue;
        final deadline = profile.validUntil.isBefore(profile.accessExpiresAt)
            ? profile.validUntil
            : profile.accessExpiresAt;
        if (next == null || deadline.isBefore(next)) next = deadline;
      }
    }
    if (next == null || _disposed) return;
    _subscriptionExpiry = Timer(next.difference(now), () {
      if (_disposed) return;
      _enforceSubscriptionAccess();
      _scheduleSubscriptionExpiry();
      notifyListeners();
    });
  }

  bool get _activeSubscriptionAllowed {
    final active = _activeConnection;
    if (active?.sourceId == null) return true;
    final current = _subscriptions[active!.sourceId]
        ?.profiles[active.cachedProfile!.profile.id];
    return current != null &&
        current.canUse(_clock()) &&
        current.profile.link.localId == active.link.localId;
  }

  void _enforceSubscriptionAccess() {
    if (_disposed ||
        _requesting ||
        !_stopPossible ||
        _subscriptionStopQueued ||
        _activeSubscriptionAllowed) {
      return;
    }
    _subscriptionStopQueued = true;
    journal.record(
      EventId.subscriptionAccessLost,
      reason: ReasonCode.accessChanged,
    );
    unawaited(toggleConnection());
  }

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
        final cache = ProfileCache.decode(reply.payload!, now: _clock());
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
            if (inspection.status == NativeImportStatus.unavailable) {
              inspection = null;
            }
          }
          restored.add(
            LocalConnection(restored.length + 1, link, inspection: inspection),
          );
        }
        final derived = <LocalConnection>[];
        for (final entry in cache.subscriptions.entries) {
          derived.addAll(await _inspectSubscription(entry.key, entry.value));
          if (_disposed) return;
        }
        _subscriptions = Map.of(cache.subscriptions);
        _derivedConnections = derived;
        _connections.addAll(restored);
        _scheduleSubscriptionExpiry();
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
    } on SnapshotException {
      if (!_disposed) _blockStorage(StorageCode.corrupt);
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
          subscriptions: _subscriptions,
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
  List<LocalConnection> get connections =>
      List.unmodifiable([..._connections, ..._derivedConnections]);
  String? _selectedId;
  String? get selectedId => _selectedId;
  LocalConnection? get selected {
    for (final connection in connections) {
      if (connection.selectionId == _selectedId) return connection;
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
      if (connections.length >= ProfileCache.maxProfiles) {
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
        !connections.contains(connection) ||
        _selectedId == connection.selectionId) {
      return;
    }
    _selectedId = connection.selectionId;
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
    if (!_stopPossible && !eligible(connection!)) {
      journal.record(EventId.subscriptionRejected, reason: ReasonCode.stale);
      notifyListeners();
      return 'Срок данных подписки истёк. Обновите список перед подключением.';
    }
    if (!_stopPossible) {
      _activeConnection = connection;
      _subscriptionStopQueued = false;
    }
    _requesting = true;
    _serviceEpoch++;
    notifyListeners();
    final stopping = _stopPossible;
    if (stopping && _activeConnection?.sourceId != null) {
      _subscriptionStopQueued = true;
    }
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
        if (!stopping) _activeConnection = null;
        journal.record(
          EventId.serviceRequestRejected,
          reason: _serviceReason(response.code),
        );
      }
      notifyListeners();
      return _serviceMessage(response.code, stopping);
    } finally {
      _requesting = false;
      _enforceSubscriptionAccess();
      if (!_disposed) notifyListeners();
    }
  }

  Future<void> _poll() async {
    if (_polling || _requesting || _disposed) return;
    _enforceSubscriptionAccess();
    if (_requesting) return;
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
          _activeConnection = null;
          _subscriptionStopQueued = false;
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
    _subscriptionExpiry?.cancel();
    journal.onPersistenceChanged = null;
    journal.disposePersistence();
    super.dispose();
  }
}
