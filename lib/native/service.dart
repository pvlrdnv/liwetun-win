import 'package:flutter/services.dart';

import '../domain/import_link.dart';

enum ServiceCode {
  ok,
  malformed,
  denied,
  busy,
  runtimeUnavailable,
  profileRejected,
  coreFailure,
  serviceUnavailable,
  timeout,
  untrustedInstallation,
}

enum ServiceState { disconnected, connecting, tunnelReady, recovering, error }

final class ServiceStatus {
  const ServiceStatus({
    this.code = ServiceCode.serviceUnavailable,
    this.state = ServiceState.disconnected,
    this.runtimeReady = false,
    this.coreState,
  });
  final ServiceCode code;
  final ServiceState state;
  final bool runtimeReady;
  final int? coreState;
  bool get active =>
      state == ServiceState.connecting ||
      state == ServiceState.tunnelReady ||
      state == ServiceState.recovering;
}

abstract interface class ServiceGateway {
  Future<ServiceStatus> query();
  Future<ServiceStatus> start(SecretLink link);
  Future<ServiceStatus> stop();
}

final class WindowsService implements ServiceGateway {
  const WindowsService();
  static const channel = MethodChannel('top.likeweb.liwetun/service');
  @override
  Future<ServiceStatus> query() => _call('query');
  @override
  Future<ServiceStatus> start(SecretLink link) =>
      _call('start', {'uri': link.value});
  @override
  Future<ServiceStatus> stop() => _call('stop');

  Future<ServiceStatus> _call(
    String command, [
    Map<String, Object>? args,
  ]) async {
    try {
      final value = await channel
          .invokeMapMethod<String, dynamic>(command, args)
          .timeout(const Duration(seconds: 15));
      if (value == null ||
          value.length != 4 ||
          !{
            'code',
            'state',
            'runtimeReady',
            'coreState',
          }.every(value.containsKey) ||
          value['runtimeReady'] is! bool) {
        return const ServiceStatus(
          code: ServiceCode.timeout,
          state: ServiceState.error,
        );
      }
      final codes = {for (final code in ServiceCode.values) code.name: code};
      final states = {
        for (final state in ServiceState.values) state.name: state,
      };
      final code = codes[value['code']];
      final state = states[value['state']];
      final core = value['coreState'];
      if (code == null ||
          state == null ||
          (core != null && (core is! int || core < 0 || core > 5))) {
        return const ServiceStatus(
          code: ServiceCode.timeout,
          state: ServiceState.error,
        );
      }
      return ServiceStatus(
        code: code,
        state: state,
        runtimeReady: value['runtimeReady'] as bool,
        coreState: core as int?,
      );
    } on MissingPluginException {
      return const ServiceStatus();
    } catch (_) {
      // In particular, never include PlatformException.message/details in logs.
      return const ServiceStatus(
        code: ServiceCode.timeout,
        state: ServiceState.error,
      );
    }
  }
}
