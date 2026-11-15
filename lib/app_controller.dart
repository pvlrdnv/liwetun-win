import 'package:flutter/foundation.dart';

import 'diagnostics/journal.dart';
import 'domain/import_link.dart';
import 'native/trusttunnel.dart';

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
  AppController({Journal? journal, TrustTunnelInspector? inspector})
    : journal = journal ?? Journal(),
      _inspector = inspector ?? const WindowsTrustTunnel() {
    this.journal.record(EventId.appStarted);
  }

  final Journal journal;
  final TrustTunnelInspector _inspector;
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
      return 'Формат TrustTunnel проверен нативным модулем. Подключение службы ещё недоступно.';
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

  void clearJournal() {
    journal.clear();
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}
