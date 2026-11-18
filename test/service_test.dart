import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/diagnostics/journal.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/native/service.dart';

import 'fixtures.dart';

final class Gateway implements ServiceGateway {
  int starts = 0, stops = 0, queries = 0;
  Future<ServiceStatus>? pending;
  Future<ServiceStatus>? pendingQuery;
  ServiceStatus stopping = const ServiceStatus(code: ServiceCode.ok);
  ServiceStatus starting = const ServiceStatus(
    code: ServiceCode.ok,
    state: ServiceState.connecting,
    runtimeReady: true,
  );
  ServiceStatus status = const ServiceStatus(
    code: ServiceCode.ok,
    state: ServiceState.disconnected,
    runtimeReady: true,
  );
  @override
  Future<ServiceStatus> start(SecretLink link) {
    starts++;
    return pending ?? Future.value(starting);
  }

  @override
  Future<ServiceStatus> query() {
    queries++;
    return pendingQuery ?? Future.value(status);
  }

  @override
  Future<ServiceStatus> stop() async {
    stops++;
    return stopping;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(
    () => messenger.setMockMethodCallHandler(WindowsService.channel, null),
  );

  test(
    'native gateway only sends profile for start and preserves unknown state',
    () async {
      final calls = <MethodCall>[];
      messenger.setMockMethodCallHandler(WindowsService.channel, (call) async {
        calls.add(call);
        return {
          'code': 'ok',
          'state': 'connecting',
          'runtimeReady': true,
          'coreState': null,
        };
      });
      final gateway = WindowsService();
      expect((await gateway.start(const SecretLink(tt))).coreState, isNull);
      await gateway.query();
      await gateway.stop();
      expect(calls.map((call) => call.method), ['start', 'query', 'stop']);
      expect(calls.first.arguments, {'uri': tt});
      expect(calls[1].arguments, isNull);
      expect(calls[2].arguments, isNull);
    },
  );

  test('unrecognized native results are uncertain and never echoed', () async {
    const canary = 'NATIVE_SERVICE_ERROR_SECRET_261115';
    for (final result in [
      null,
      {'code': canary},
      {
        'code': 'ok',
        'state': 'connected',
        'runtimeReady': true,
        'coreState': 0,
      },
      {
        'code': 'ok',
        'state': 'connecting',
        'runtimeReady': true,
        'coreState': 1.0,
      },
    ]) {
      messenger.setMockMethodCallHandler(
        WindowsService.channel,
        (_) async => result,
      );
      final status = await const WindowsService().query();
      expect(status.code, ServiceCode.timeout);
      expect(status.toString(), isNot(contains(canary)));
    }
    messenger.setMockMethodCallHandler(
      WindowsService.channel,
      (_) async => throw PlatformException(
        code: canary,
        message: canary,
        details: canary,
      ),
    );
    expect((await const WindowsService().query()).code, ServiceCode.timeout);
  });

  testWidgets(
    'start timeout reconciles and next click stops instead of starting twice',
    (tester) async {
      final gateway = Gateway()
        ..starting = const ServiceStatus(
          code: ServiceCode.timeout,
          state: ServiceState.error,
        );
      final controller = AppController(service: gateway)..import(tt);
      try {
        await controller.toggleConnection();
        expect(controller.stopPossible, true);
        expect(
          controller.journal.events.last.event,
          EventId.serviceRequestUncertain,
        );
        await controller.toggleConnection();
        expect(gateway.starts, 1);
        expect(gateway.stops, 1);
        await tester.pump(const Duration(seconds: 1));
        expect(controller.stopPossible, false);
      } finally {
        controller.dispose();
      }
    },
  );

  test(
    'adapter preflight refusal stays idle with a distinct closed report code',
    () async {
      final gateway = Gateway()
        ..starting = const ServiceStatus(
          code: ServiceCode.adapterPreflightRejected,
          runtimeReady: true,
        );
      final controller = AppController(service: gateway)..import(tt);
      addTearDown(controller.dispose);
      final message = await controller.toggleConnection();
      expect(message, contains('Ядро не запускалось'));
      expect(controller.stopPossible, false);
      expect(controller.serviceStatus.state, ServiceState.disconnected);
      expect(
        controller.journal.events.last.reason,
        ReasonCode.adapterPreflightRejected,
      );
      expect(gateway.starts, 1);
      expect(gateway.stops, 0);
    },
  );

  testWidgets('duplicate concurrent click does not repeat start', (
    tester,
  ) async {
    final pending = Completer<ServiceStatus>();
    final gateway = Gateway()..pending = pending.future;
    final controller = AppController(service: gateway)..import(tt);
    try {
      final operation = controller.toggleConnection();
      await controller.toggleConnection();
      expect(gateway.starts, 1);
      pending.complete(
        const ServiceStatus(
          code: ServiceCode.ok,
          state: ServiceState.connecting,
        ),
      );
      await operation;
    } finally {
      controller.dispose();
    }
  });

  testWidgets(
    'lost observations never fabricate disconnection or automatic restart',
    (tester) async {
      final gateway = Gateway()
        ..status = const ServiceStatus(
          code: ServiceCode.timeout,
          state: ServiceState.error,
        );
      final controller = AppController(service: gateway)..import(tt);
      try {
        await controller.toggleConnection();
        for (var i = 0; i < 6; ++i) {
          await tester.pump(const Duration(seconds: 1));
        }
        expect(gateway.starts, 1);
        expect(gateway.queries, 6);
        expect(controller.serviceStatus.state, ServiceState.error);
        expect(controller.stopPossible, true);
        expect(
          controller.journal.events.last.event,
          EventId.serviceObservationLost,
        );
      } finally {
        controller.dispose();
      }
    },
  );

  testWidgets('tunnel-ready state is visibly distinct from working internet', (
    tester,
  ) async {
    final gateway = Gateway()
      ..starting = const ServiceStatus(
        code: ServiceCode.ok,
        state: ServiceState.tunnelReady,
        runtimeReady: true,
        coreState: 2,
      );
    final controller = AppController(service: gateway)..import(tt);
    try {
      await controller.toggleConnection();
      await tester.pumpWidget(LiWeTunApp(controller: controller));
      expect(find.text('ТУННЕЛЬ ЗАПУЩЕН'), findsOneWidget);
      expect(
        find.text('Работа интернета через туннель ещё не проверена.'),
        findsOneWidget,
      );
      expect(find.text('ПОДКЛЮЧЕНО'), findsNothing);
    } finally {
      controller.dispose();
    }
  });

  testWidgets('late completion after disposal schedules no observation timer', (
    tester,
  ) async {
    final pending = Completer<ServiceStatus>();
    final gateway = Gateway()..pending = pending.future;
    final controller = AppController(service: gateway)..import(tt);
    final operation = controller.toggleConnection();
    controller.dispose();
    pending.complete(
      const ServiceStatus(
        code: ServiceCode.ok,
        state: ServiceState.tunnelReady,
      ),
    );
    await operation;
    await tester.pump(const Duration(seconds: 2));
    expect(gateway.queries, 0);
  });

  testWidgets('unavailable stop retains uncertain state', (tester) async {
    final gateway = Gateway()
      ..stopping = const ServiceStatus(code: ServiceCode.serviceUnavailable);
    final controller = AppController(service: gateway)..import(tt);
    try {
      await controller.toggleConnection();
      await controller.toggleConnection();
      expect(controller.serviceStatus.state, ServiceState.error);
      expect(controller.stopPossible, true);
      expect(
        controller.journal.events.last.event,
        EventId.serviceRequestUncertain,
      );
    } finally {
      controller.dispose();
    }
  });

  testWidgets('old observation cannot resurrect a stopped tunnel', (
    tester,
  ) async {
    final oldQuery = Completer<ServiceStatus>();
    final gateway = Gateway()..pendingQuery = oldQuery.future;
    final controller = AppController(service: gateway)..import(tt);
    try {
      await controller.toggleConnection();
      await tester.pump(const Duration(seconds: 1));
      expect(gateway.queries, 1);
      await controller.toggleConnection();
      oldQuery.complete(
        const ServiceStatus(
          code: ServiceCode.ok,
          state: ServiceState.tunnelReady,
        ),
      );
      await tester.pump();
      expect(controller.serviceStatus.state, ServiceState.disconnected);
      gateway.pendingQuery = null;
      await tester.pump(const Duration(seconds: 1));
      expect(controller.stopPossible, false);
    } finally {
      controller.dispose();
    }
  });

  testWidgets('unexpected gateway exception is sanitized and uncertain', (
    tester,
  ) async {
    const canary = 'SERVICE_GATEWAY_SECRET_261115';
    final pending = Completer<ServiceStatus>();
    final gateway = Gateway()..pending = pending.future;
    final controller = AppController(service: gateway)..import(tt);
    try {
      final operation = controller.toggleConnection();
      pending.completeError(StateError(canary));
      final message = await operation;
      expect(message, isNot(contains(canary)));
      expect(controller.serviceStatus.code, ServiceCode.timeout);
      expect(controller.stopPossible, true);
    } finally {
      controller.dispose();
    }
  });
}
