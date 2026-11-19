import 'dart:async';
import 'dart:math';

import 'package:flutter/foundation.dart';

import 'diagnostics/journal.dart';
import 'domain/import_link.dart';
import 'domain/profile_cache.dart';
import 'domain/subscription.dart';
import 'domain/subscription_refresh.dart';
import 'network/subscription_transport.dart';
import 'native/trusttunnel.dart';
import 'native/service.dart';
import 'native/storage.dart';
import 'native/desktop.dart';
import 'native/traffic.dart';
import 'domain/traffic_health.dart';

enum ProfileStorageState { memoryOnly, loading, saved, saving, blocked }

enum SubscriptionApplyCode {
  applied,
  closed,
  busy,
  missing,
  rejected,
  unsupported,
  stale,
  replay,
  capacity,
  unavailable,
}

final class _RefreshOutcome {
  const _RefreshOutcome.fetch(this.fetchCode) : applyCode = null;
  const _RefreshOutcome.apply(this.applyCode) : fetchCode = null;
  final SubscriptionFetchCode? fetchCode;
  final SubscriptionApplyCode? applyCode;
  bool get applied => applyCode == SubscriptionApplyCode.applied;
  bool get unchanged => applyCode == SubscriptionApplyCode.replay;
  String get message {
    if (applyCode != null) {
      return switch (applyCode!) {
        SubscriptionApplyCode.applied => 'Список подписки обновлён.',
        SubscriptionApplyCode.closed => 'Приложение закрыто.',
        SubscriptionApplyCode.busy =>
          'Обновление уже выполняется. Повторите через несколько секунд.',
        SubscriptionApplyCode.missing =>
          'Добавьте или выберите подписку для обновления.',
        SubscriptionApplyCode.replay =>
          'Получена устаревшая версия подписки. Прежний список сохранён.',
        SubscriptionApplyCode.stale =>
          'Срок данных в ответе истёк. Прежний список сохранён.',
        SubscriptionApplyCode.capacity =>
          'Список слишком большой. Прежние подключения сохранены.',
        SubscriptionApplyCode.unavailable =>
          'Не удалось проверить новые подключения. Прежний список сохранён.',
        _ => 'Не удалось проверить формат подписки. Прежний список сохранён.',
      };
    }
    return switch (fetchCode) {
      SubscriptionFetchCode.privateAddress =>
        'Для подписки нужен публичный HTTPS-адрес. Прежний список сохранён.',
      SubscriptionFetchCode.unsupportedProxy =>
        'Обновление через настроенный HTTPS-прокси пока не поддерживается. Прежний список сохранён.',
      SubscriptionFetchCode.tls =>
        'Не удалось проверить защищённое соединение. Прежний список сохранён.',
      SubscriptionFetchCode.timeout =>
        'Сервис подписки не ответил вовремя. Прежний список сохранён.',
      SubscriptionFetchCode.dns =>
        'Не удалось найти сервис подписки. Прежний список сохранён.',
      SubscriptionFetchCode.tooLarge =>
        'Ответ подписки слишком большой. Прежний список сохранён.',
      SubscriptionFetchCode.cancelled => 'Обновление отменено.',
      SubscriptionFetchCode.contentType ||
      SubscriptionFetchCode.malformedBody =>
        'Сервис вернул неподдерживаемый формат подписки. Прежний список сохранён.',
      SubscriptionFetchCode.malformedSource =>
        'Проверьте HTTPS-ссылку подписки. Прежний список сохранён.',
      _ => 'Не удалось обновить подписку. Прежний список сохранён.',
    };
  }
}

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
      (inspection?.name?.isNotEmpty == true ? inspection!.name : null) ??
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
    DesktopGateway? desktop,
    TrafficGateway? traffic,
    DateTime Function()? clock,
    SubscriptionTransport? subscriptionTransport,
    int Function(int maximum)? jitter,
  }) : journal = journal ?? Journal(),
       _inspector = inspector ?? const WindowsTrustTunnel(),
       _service = service ?? const WindowsService(),
       _storage = storage ?? const WindowsStorage(),
       _desktop = desktop ?? const WindowsDesktop(),
       _traffic = traffic ?? const WindowsTraffic(),
       _clock = clock ?? DateTime.now,
       _subscriptionTransport =
           subscriptionTransport ?? HttpSubscriptionTransport(),
       _jitter = jitter ?? Random().nextInt {
    this.journal.record(EventId.appStarted);
    this.journal.onPersistenceChanged = () {
      if (!_disposed) notifyListeners();
    };
  }

  final Journal journal;
  final TrustTunnelInspector _inspector;
  final ServiceGateway _service;
  final StorageGateway _storage;
  final DesktopGateway _desktop;
  final TrafficGateway _traffic;
  String get trafficNotice {
    final observation = journal.trafficObservation;
    if (!observation.usable) return 'Показатели трафика пока недоступны.';
    final window = switch (journal.trafficHealth) {
      TrafficHealth.unknown => 'Набираем окно наблюдения 20 секунд.',
      TrafficHealth.idle => 'В окне наблюдения нет учтённого трафика.',
      TrafficHealth.flowing => 'В окне наблюдения есть входящие данные.',
      TrafficHealth.outgoingWithoutReply =>
        'В окне наблюдения есть отправка без входящих данных.',
    };
    return 'Учтённые данные соединений: отправка ${observation.tx} Б, приём ${observation.rx} Б. '
        '$window Показатели могут включать фоновые приложения. Проверка интернета и DNS отдельно ещё недоступна.';
  }

  bool _closeToTray = false;
  bool get closeToTray => _closeToTray;
  bool desktopAvailable = false;
  bool desktopBusy = false;

  Future<void> initializeDesktop() async {
    if (_disposed || desktopBusy) return;
    desktopBusy = true;
    try {
      final status = await _desktop.configure(closeToTray);
      if (!_disposed) desktopAvailable = status.available;
    } catch (_) {
      if (!_disposed) desktopAvailable = false;
    } finally {
      desktopBusy = false;
      if (!_disposed) notifyListeners();
    }
  }

  Future<String> setCloseToTray(bool enabled) async {
    if (_disposed ||
        desktopBusy ||
        storageState == ProfileStorageState.loading) {
      return 'Настройки ещё загружаются. Повторите позже.';
    }
    desktopBusy = true;
    notifyListeners();
    try {
      final status = await _desktop.configure(enabled);
      if (_disposed) return 'Приложение закрыто.';
      desktopAvailable = status.available;
      if (enabled && (!status.available || !status.closeToTray)) {
        return 'Не удалось подтвердить включение трея Windows. Повторите проверку.';
      }
      _closeToTray = enabled;
      _profilesChanged();
      return enabled
          ? 'Закрытие окна сворачивает LiWeTun в трей. Выход — через меню значка.'
          : 'Закрытие окна завершает работу LiWeTun.';
    } catch (_) {
      return 'Не удалось изменить поведение окна. Повторите позже.';
    } finally {
      desktopBusy = false;
      if (!_disposed) notifyListeners();
    }
  }

  final DateTime Function() _clock;
  final SubscriptionTransport _subscriptionTransport;
  final int Function(int maximum) _jitter;
  final Map<String, DateTime> _refreshDue = {}, _lastRefreshAttempt = {};
  final Map<String, int> _refreshFailures = {};
  final Map<String, _RefreshOutcome> _refreshOutcomes = {};
  Timer? _refreshTimer;
  bool _autoRefresh = false;
  DateTime? _refreshNotBefore;
  String? _refreshingSource;
  bool get refreshingSubscription => _refreshingSource != null;
  bool get hasSubscriptions =>
      _connections.any((item) => item.link.kind == ImportKind.subscription);

  Map<String, SubscriptionStore> _subscriptions = {};
  List<LocalConnection> _derivedConnections = [];
  bool _applyingSubscription = false;
  Timer? _subscriptionExpiry;
  LocalConnection? _activeConnection;
  bool _subscriptionStopQueued = false;
  bool get applyingSubscription => _applyingSubscription;

  void enableAutomaticSubscriptionRefresh() {
    if (_disposed || _autoRefresh) return;
    _autoRefresh = true;
    _scheduleAutomaticRefresh();
  }

  Future<String> refreshSubscription([String? sourceId]) async {
    final sources = _connections
        .where((item) => item.link.kind == ImportKind.subscription)
        .toList();
    if (sourceId == null && sources.length > 1) {
      return 'Нажмите обновление у нужной подписки в списке.';
    }
    final id =
        sourceId ?? (sources.isEmpty ? null : sources.single.link.localId);
    if (id == null) {
      return const _RefreshOutcome.apply(SubscriptionApplyCode.missing).message;
    }
    return (await _refreshSubscription(id)).message;
  }

  Future<_RefreshOutcome> _refreshSubscription(String sourceId) async {
    if (_disposed) {
      return const _RefreshOutcome.apply(SubscriptionApplyCode.closed);
    }
    if (refreshingSubscription ||
        _applyingSubscription ||
        storageState == ProfileStorageState.loading) {
      return const _RefreshOutcome.apply(SubscriptionApplyCode.busy);
    }
    LocalConnection? source;
    for (final item in _connections) {
      if (item.link.kind == ImportKind.subscription &&
          item.link.localId == sourceId) {
        source = item;
      }
    }
    if (source == null) {
      return const _RefreshOutcome.apply(SubscriptionApplyCode.missing);
    }
    final now = _clock();
    final previous = _lastRefreshAttempt[sourceId];
    if (previous != null &&
        !now.isBefore(previous) &&
        now.difference(previous) < const Duration(seconds: 5)) {
      return const _RefreshOutcome.apply(SubscriptionApplyCode.busy);
    }
    _lastRefreshAttempt[sourceId] = now;
    _refreshTimer?.cancel();
    _refreshingSource = sourceId;
    journal.record(EventId.subscriptionRefreshStarted);
    notifyListeners();
    var outcome = const _RefreshOutcome.fetch(SubscriptionFetchCode.network);
    try {
      final reply = await _subscriptionTransport
          .fetch(source.link.secret)
          .timeout(const Duration(seconds: 17));
      if (_disposed) {
        return const _RefreshOutcome.apply(SubscriptionApplyCode.closed);
      }
      if (reply.code != SubscriptionFetchCode.ok) {
        outcome = _RefreshOutcome.fetch(reply.code);
      } else if (reply.payload == null) {
        outcome = const _RefreshOutcome.apply(SubscriptionApplyCode.rejected);
      } else {
        outcome = _RefreshOutcome.apply(
          await applySubscriptionSnapshot(sourceId, reply.payload!),
        );
      }
      return outcome;
    } on TimeoutException {
      outcome = const _RefreshOutcome.fetch(SubscriptionFetchCode.timeout);
      return outcome;
    } catch (_) {
      outcome = const _RefreshOutcome.fetch(SubscriptionFetchCode.network);
      return outcome;
    } finally {
      _refreshingSource = null;
      if (!_disposed) {
        _refreshOutcomes[sourceId] = outcome;
        if (!outcome.applied) {
          journal.record(
            EventId.subscriptionRefreshFailed,
            reason: _refreshReason(outcome),
          );
        }
        final failures = outcome.applied || outcome.unchanged
            ? 0
            : ((_refreshFailures[sourceId] ?? 0) + 1).clamp(1, 6);
        _refreshFailures[sourceId] = failures;
        DateTime? deadline;
        final time = _clock();
        for (final profile
            in _subscriptions[sourceId]?.profiles.values ?? <CachedProfile>[]) {
          if (!profile.canUse(time)) continue;
          final expires = profile.validUntil.isBefore(profile.accessExpiresAt)
              ? profile.validUntil
              : profile.accessExpiresAt;
          if (deadline == null || expires.isBefore(deadline)) {
            deadline = expires;
          }
        }
        _refreshDue[sourceId] = time.add(
          subscriptionRefreshDelay(
            now: time,
            failures: failures,
            jitterSeconds: _jitter(121),
            earliestDeadline: deadline,
          ),
        );
        _refreshNotBefore = time.add(const Duration(seconds: 1));
        _scheduleAutomaticRefresh();
        notifyListeners();
      }
    }
  }

  ReasonCode _refreshReason(_RefreshOutcome outcome) {
    if (outcome.fetchCode != null) {
      return switch (outcome.fetchCode!) {
        SubscriptionFetchCode.dns => ReasonCode.dnsFailure,
        SubscriptionFetchCode.tls => ReasonCode.tlsFailure,
        SubscriptionFetchCode.timeout => ReasonCode.timeout,
        SubscriptionFetchCode.privateAddress => ReasonCode.privateAddress,
        SubscriptionFetchCode.unsupportedProxy => ReasonCode.unsupported,
        SubscriptionFetchCode.httpStatus => ReasonCode.httpStatus,
        SubscriptionFetchCode.tooLarge => ReasonCode.tooLong,
        SubscriptionFetchCode.contentType => ReasonCode.unsupported,
        SubscriptionFetchCode.malformedBody ||
        SubscriptionFetchCode.malformedSource => ReasonCode.malformed,
        SubscriptionFetchCode.cancelled => ReasonCode.none,
        _ => ReasonCode.networkFailure,
      };
    }
    return switch (outcome.applyCode) {
      SubscriptionApplyCode.busy => ReasonCode.operationBusy,
      SubscriptionApplyCode.replay => ReasonCode.replay,
      SubscriptionApplyCode.stale => ReasonCode.stale,
      SubscriptionApplyCode.capacity => ReasonCode.tooLong,
      SubscriptionApplyCode.unsupported => ReasonCode.unsupported,
      SubscriptionApplyCode.unavailable => ReasonCode.ioFailure,
      _ => ReasonCode.malformed,
    };
  }

  void _scheduleAutomaticRefresh() {
    _refreshTimer?.cancel();
    if (!_autoRefresh ||
        _disposed ||
        refreshingSubscription ||
        _applyingSubscription) {
      return;
    }
    final now = _clock();
    DateTime? next;
    for (final source in _connections.where(
      (item) => item.link.kind == ImportKind.subscription,
    )) {
      final due = _refreshDue.putIfAbsent(source.link.localId, () => now);
      if (next == null || due.isBefore(next)) next = due;
    }
    if (next == null) return;
    if (_refreshNotBefore != null && next.isBefore(_refreshNotBefore!)) {
      next = _refreshNotBefore;
    }
    final delay = next!.difference(now);
    _refreshTimer = Timer(
      delay.isNegative ? Duration.zero : delay,
      () => unawaited(_refreshDueSource()),
    );
  }

  Future<void> _refreshDueSource() async {
    if (_disposed || !_autoRefresh) return;
    if (refreshingSubscription || _applyingSubscription) {
      _scheduleAutomaticRefresh();
      return;
    }
    final now = _clock();
    final candidates =
        _connections
            .where(
              (item) =>
                  item.link.kind == ImportKind.subscription &&
                  !(_refreshDue[item.link.localId] ?? now).isAfter(now),
            )
            .toList()
          ..sort(
            (a, b) => (_refreshDue[a.link.localId] ?? now).compareTo(
              _refreshDue[b.link.localId] ?? now,
            ),
          );
    if (candidates.isEmpty) {
      _scheduleAutomaticRefresh();
      return;
    }
    final result = await _refreshSubscription(candidates.first.link.localId);
    if (!_disposed && result.applyCode == SubscriptionApplyCode.busy) {
      _refreshDue[candidates.first.link.localId] = _clock().add(
        const Duration(seconds: 5),
      );
      _scheduleAutomaticRefresh();
    }
  }

  bool eligible(LocalConnection connection) =>
      connection.cachedProfile?.canUse(_clock()) ?? true;

  String subscriptionNotice(LocalConnection source) {
    final id = source.link.localId;
    final store = _subscriptions[id];
    final status = _refreshingSource == id
        ? 'Обновляем список…'
        : _refreshOutcomes[id] != null && !_refreshOutcomes[id]!.applied
        ? _refreshOutcomes[id]!.message
        : null;
    if (store == null || store.revision < 0) {
      return status ?? 'Обновлений ещё не было.';
    }
    final usable = store.profiles.values
        .where((profile) => profile.canUse(_clock()))
        .length;
    final state = switch (store.access) {
      Access.revoked => 'Доступ отозван.',
      Access.expired => 'Срок доступа завершён.',
      Access.active =>
        'Серверов: ${store.profiles.length} · актуальных: $usable',
    };
    final applied = store.lastAppliedAt?.toLocal();
    final updated = applied == null
        ? 'Время обновления неизвестно'
        : 'Обновлено ${applied.day.toString().padLeft(2, '0')}.${applied.month.toString().padLeft(2, '0')}.'
              '${applied.year} ${applied.hour.toString().padLeft(2, '0')}:${applied.minute.toString().padLeft(2, '0')}';
    return '${status == null ? '' : '$status\n'}$state · $updated';
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
  Future<SubscriptionApplyCode> applySubscriptionSnapshot(
    String sourceId,
    String text,
  ) async {
    if (_disposed) return SubscriptionApplyCode.closed;
    if (_applyingSubscription || storageState == ProfileStorageState.loading) {
      return SubscriptionApplyCode.busy;
    }
    if (!_connections.any(
      (item) =>
          item.link.localId == sourceId &&
          item.link.kind == ImportKind.subscription,
    )) {
      return SubscriptionApplyCode.missing;
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
      if (_disposed) return SubscriptionApplyCode.closed;
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
        closeToTray: closeToTray,
      ).encode();
      _subscriptions = stores;
      _derivedConnections = derived;
      _selectedId = selection;
      _profilesChanged();
      journal.record(EventId.subscriptionApplied);
      _scheduleSubscriptionExpiry();
      _enforceSubscriptionAccess();
      notifyListeners();
      return SubscriptionApplyCode.applied;
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
      return switch (error.reason) {
        SnapshotFailure.replay => SubscriptionApplyCode.replay,
        SnapshotFailure.stale => SubscriptionApplyCode.stale,
        SnapshotFailure.unsupported => SubscriptionApplyCode.unsupported,
        _ => SubscriptionApplyCode.rejected,
      };
    } on CacheException {
      if (!_disposed) {
        journal.record(
          EventId.subscriptionRejected,
          reason: ReasonCode.tooLong,
        );
      }
      return SubscriptionApplyCode.capacity;
    } catch (_) {
      if (!_disposed) {
        journal.record(
          EventId.subscriptionRejected,
          reason: ReasonCode.ioFailure,
        );
      }
      return SubscriptionApplyCode.unavailable;
    } finally {
      _applyingSubscription = false;
      _scheduleAutomaticRefresh();
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
        _closeToTray = cache.closeToTray;
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
      _scheduleAutomaticRefresh();
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
          closeToTray: closeToTray,
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
      if (link.kind == ImportKind.subscription) {
        _refreshDue[link.localId] = _clock();
        _scheduleAutomaticRefresh();
      }
      if (link.kind == ImportKind.profile) _selectedId ??= link.localId;
      journal.record(EventId.importAccepted, protocol: link.protocol);
      _profilesChanged();
      notifyListeners();
      return link.kind == ImportKind.subscription
          ? 'Подписка добавлена. Список можно обновить в разделе подключений.'
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
    journal.invalidateTraffic();
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
              response.code != ServiceCode.coreFailure &&
              !response.code.isAdapterRefusal);
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
          (response.code.isAdapterRefusal &&
              response.state != ServiceState.disconnected) ||
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
        } else if (response.code == ServiceCode.coreFailure ||
            response.code.isAdapterRefusal) {
          journal.record(
            EventId.serviceRequestRejected,
            reason: _serviceReason(response.code),
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
          response.code == ServiceCode.coreFailure ||
          response.code.isAdapterRefusal) {
        _failedPolls = 0;
        if (response.state != serviceStatus.state) {
          journal.record(EventId.serviceStateObserved);
        }
        if (response.code.isAdapterRefusal &&
            response.code != serviceStatus.code) {
          journal.record(
            EventId.serviceRequestRejected,
            reason: _serviceReason(response.code),
          );
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
      if (response.code == ServiceCode.ok &&
          response.state == ServiceState.tunnelReady) {
        TrafficObservation observation;
        try {
          observation = await _traffic.read().timeout(
            const Duration(seconds: 4),
          );
        } catch (_) {
          observation = const TrafficObservation(code: ServiceCode.timeout);
        }
        if (_disposed || epoch != _serviceEpoch) return;
        journal.observeTraffic(observation);
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

  ReasonCode _serviceReason(ServiceCode code) {
    if (code.isAdapterRefusal) return ReasonCode.values.byName(code.name);
    return switch (code) {
      ServiceCode.denied ||
      ServiceCode.untrustedInstallation => ReasonCode.serviceDenied,
      ServiceCode.profileRejected ||
      ServiceCode.malformed => ReasonCode.malformed,
      ServiceCode.coreFailure => ReasonCode.coreFailure,
      _ => ReasonCode.serviceUnavailable,
    };
  }

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
    _ when code.isAdapterRefusal =>
      'Запуск отклонён проверкой сетевых адаптеров. Ядро не запускалось. Экспортируйте отчёт для диагностики.',
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
    _refreshTimer?.cancel();
    _subscriptionTransport.close();
    journal.onPersistenceChanged = null;
    journal.disposePersistence();
    super.dispose();
  }
}
