import 'dart:convert';

import 'package:archive/archive.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/diagnostics/journal.dart';
import 'package:liwetun/native/environment.dart';
import 'package:liwetun/native/service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(
    () => messenger.setMockMethodCallHandler(WindowsEnvironment.channel, null),
  );

  test(
    'environment query returns only bounded OS numbers and app architecture',
    () async {
      messenger.setMockMethodCallHandler(WindowsEnvironment.channel, (
        call,
      ) async {
        expect(call.method, 'environment');
        expect(call.arguments, isNull);
        return {'major': 10, 'minor': 0, 'build': 19045, 'architecture': 'x64'};
      });
      final value = await const WindowsEnvironment().read();
      expect(value.build, 19045);
      expect(value.appArchitecture, AppArchitecture.x64);
    },
  );

  test(
    'unknown or private platform data becomes unknown without raw errors',
    () async {
      for (final value in [
        null,
        {
          'major': 10,
          'minor': 0,
          'build': 'PRIVATE_CANARY',
          'architecture': 'x64',
        },
        {'major': 10, 'minor': 0, 'build': -1, 'architecture': 'x64'},
        {'major': 10, 'minor': 0, 'build': 19045.0, 'architecture': 'x64'},
        {
          'major': 10,
          'minor': 0,
          'build': 19045,
          'architecture': 'PRIVATE_CANARY',
        },
        {
          'major': 10,
          'minor': 0,
          'build': 19045,
          'architecture': 'x64',
          'hostname': 'PRIVATE_CANARY',
        },
      ]) {
        messenger.setMockMethodCallHandler(
          WindowsEnvironment.channel,
          (_) async => value,
        );
        expect((await const WindowsEnvironment().read()).build, isNull);
      }
      messenger.setMockMethodCallHandler(WindowsEnvironment.channel, (_) async {
        throw PlatformException(
          code: 'PRIVATE_CANARY',
          message: 'PRIVATE_CANARY',
        );
      });
      expect(
        jsonEncode((await const WindowsEnvironment().read()).toJson()),
        isNot(contains('PRIVATE_CANARY')),
      );
    },
  );

  test(
    'support summary records timestamps and unknown service state truthfully',
    () {
      final at = DateTime.utc(2026, 11, 15);
      final journal = Journal(clock: () => at);
      journal.environment = const ClientEnvironment(
        major: 10,
        minor: 0,
        build: 19045,
        appArchitecture: AppArchitecture.x64,
      );
      Map<String, dynamic> summary() {
        final archive = ZipDecoder().decodeBytes(journal.exportZip());
        return jsonDecode(
              utf8.decode(
                archive.files
                        .singleWhere((file) => file.name == 'summary.json')
                        .content
                    as List<int>,
              ),
            )
            as Map<String, dynamic>;
      }

      expect(summary()['service_observation']['code'], isNull);
      journal.observeService(const ServiceStatus(code: ServiceCode.denied));
      var report = summary();
      expect(report['schema_version'], 2);
      expect(report['environment']['windows_api_build'], 19045);
      expect(report['service_observation']['code'], 'denied');
      expect(report['service_observation']['state'], isNull);
      expect(report['service_observation']['runtime_ready'], isNull);
      journal.observeService(
        const ServiceStatus(
          code: ServiceCode.ok,
          state: ServiceState.tunnelReady,
          runtimeReady: true,
        ),
      );
      report = summary();
      expect(report['service_observation']['state'], 'tunnelReady');
      expect(
        report['service_observation']['observed_at'],
        at.toIso8601String(),
      );
      expect(report['traffic_metrics'], 'unknown');
    },
  );
}
