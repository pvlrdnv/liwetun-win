import 'dart:async';
import 'dart:convert';
import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/diagnostics/journal.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/domain/traffic_health.dart';
import 'package:liwetun/native/service.dart';
import 'package:liwetun/native/traffic.dart';
import 'fixtures.dart';

Map<String, dynamic> sample({
  int ms = 0,
  int tx = 0,
  int rx = 0,
  int instance = 1,
  int epoch = 1,
}) => {
  'code': 'ok',
  'supported': true,
  'valid': true,
  'flags': 3,
  'instance': instance,
  'epoch': epoch,
  'atMs': ms,
  'tx': tx,
  'rx': rx,
  'lastTxMs': tx > 0 ? ms : null,
  'lastRxMs': rx > 0 ? ms : null,
  'coreState': 2,
};
TrafficObservation observation({
  int ms = 0,
  int tx = 0,
  int rx = 0,
  int instance = 1,
  int epoch = 1,
}) => TrafficObservation.decode(
  sample(ms: ms, tx: tx, rx: rx, instance: instance, epoch: epoch),
);
const ready = ServiceStatus(
  code: ServiceCode.ok,
  state: ServiceState.tunnelReady,
  runtimeReady: true,
  coreState: 2,
);

final class _Service implements ServiceGateway {
  ServiceStatus current = ready;
  @override
  Future<ServiceStatus> query() async => current;
  @override
  Future<ServiceStatus> start(SecretLink link) async => current = ready;
  @override
  Future<ServiceStatus> stop() async =>
      current = const ServiceStatus(code: ServiceCode.ok);
}

final class _Traffic implements TrafficGateway {
  late Future<TrafficObservation> Function() answer;
  @override
  Future<TrafficObservation> read() => answer();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('zero is observed only for a complete valid native snapshot', () {
    final data = observation();
    expect(data.usable, true);
    expect(data.tx, 0);
    expect(data.lastRxMs, isNull);
    expect(const TrafficObservation().tx, isNull);
    for (final mutate in <void Function(Map<String, dynamic>)>[
      (m) => m['extra'] = 'SYNTHETIC_PRIVATE',
      (m) => m['flags'] = 7,
      (m) => m['supported'] = false,
      (m) => m['valid'] = false,
      (m) => m['instance'] = 0,
      (m) => m['epoch'] = null,
      (m) => m['atMs'] = -1,
      (m) => m['rx'] = null,
      (m) => m['tx'] = 1,
      (m) => m['lastRxMs'] = 0,
      (m) => m['coreState'] = 3,
      (m) => m['code'] = 'denied',
    ]) {
      final changed = sample();
      mutate(changed);
      final rejected = TrafficObservation.decode(changed);
      expect(rejected.code, ServiceCode.malformed);
      expect(rejected.tx, isNull);
      expect(
        jsonEncode(rejected.toJson()),
        isNot(contains('SYNTHETIC_PRIVATE')),
      );
    }
  });
  test(
    'capability without an active instance and invalid observations retain unknown counters',
    () {
      final data = sample()
        ..addAll({
          'valid': false,
          'flags': 1,
          'instance': null,
          'epoch': null,
          'atMs': null,
          'tx': null,
          'rx': null,
          'coreState': null,
        });
      final unavailable = TrafficObservation.decode(data);
      expect(unavailable.supported, true);
      expect(unavailable.usable, false);
      expect(unavailable.tx, isNull);
      data.addAll({
        'flags': 9,
        'instance': 2,
        'epoch': 3,
        'atMs': 40,
        'coreState': 2,
      });
      expect(TrafficObservation.decode(data).supported, true);
      expect(TrafficObservation.decode(data).usable, false);
    },
  );
  test(
    'rolling window distinguishes idle, one-sided sends and receive growth',
    () {
      for (final expected in [
        TrafficHealth.idle,
        TrafficHealth.outgoingWithoutReply,
        TrafficHealth.flowing,
      ]) {
        final window = TrafficWindow();
        TrafficHealth state = TrafficHealth.unknown;
        for (var i = 0; i <= 20; i++) {
          state = window.observe(
            observation(
              ms: i * 1000,
              tx: expected == TrafficHealth.idle ? 0 : i,
              rx: expected == TrafficHealth.flowing ? i : 0,
            ),
          );
          if (i < 20) expect(state, TrafficHealth.unknown);
        }
        expect(state, expected);
      }
    },
  );
  test(
    'instance, epoch, clock, counter reset and missed sampling invalidate the window',
    () {
      for (final next in [
        observation(ms: 21000, instance: 2),
        observation(ms: 21000, epoch: 2),
        observation(ms: 19000),
        observation(ms: 26000),
        observation(ms: 21000),
        const TrafficObservation(),
      ]) {
        final window = TrafficWindow();
        for (var i = 0; i <= 20; i++) {
          window.observe(observation(ms: i * 1000, tx: 10));
        }
        expect(window.observe(next), TrafficHealth.unknown);
      }
    },
  );
  test(
    'report distinguishes counter facts from unimplemented DNS/Internet proof and expires them',
    () {
      var wall = now;
      final journal = Journal(clock: () => wall)..observeService(ready);
      Map<String, dynamic> report() {
        final zip = ZipDecoder().decodeBytes(journal.exportZip());
        return jsonDecode(
              utf8.decode(
                zip.files.singleWhere((f) => f.name == 'summary.json').content
                    as List<int>,
              ),
            )
            as Map<String, dynamic>;
      }

      expect(report()['traffic_metrics'], 'unknown');
      journal.observeTraffic(observation(tx: 3));
      var result = report();
      expect(result['schema_version'], 3);
      expect(result['traffic_metrics'], 'endpoint_client_payload');
      expect(result['traffic_observation']['tx_bytes'], 3);
      expect(result['traffic_observation']['rx_bytes'], 0);
      expect(result['traffic_observation']['proves_internet'], false);
      expect(result['traffic_observation']['proves_dns'], false);
      wall = wall.add(const Duration(seconds: 6));
      result = report();
      expect(result['traffic_metrics'], 'unknown');
      expect(result['traffic_observation']['tx_bytes'], isNull);
      journal.observeService(const ServiceStatus(code: ServiceCode.ok));
      journal.observeTraffic(observation(tx: 4));
      expect(report()['traffic_metrics'], 'unknown');
    },
  );
  testWidgets(
    'controller polls native facts and drops a late snapshot after Stop',
    (tester) async {
      final service = _Service();
      final traffic = _Traffic();
      final pending = Completer<TrafficObservation>();
      traffic.answer = () => pending.future;
      final controller = AppController(service: service, traffic: traffic);
      try {
        controller.import(tt);
        await controller.toggleConnection();
        await tester.pump(const Duration(seconds: 1));
        await controller.toggleConnection();
        pending.complete(observation(tx: 100));
        await tester.pump();
        expect(controller.journal.trafficObservation.usable, false);
        expect(controller.trafficNotice, contains('недоступны'));
      } finally {
        controller.dispose();
      }
    },
  );
  testWidgets(
    'read failures never expose exception text or turn unknown metrics into zero',
    (tester) async {
      final service = _Service();
      final traffic = _Traffic();
      traffic.answer = () async =>
          throw StateError('SYNTHETIC_PRIVATE_TRAFFIC_ERROR');
      final controller = AppController(service: service, traffic: traffic);
      try {
        controller.import(tt);
        await controller.toggleConnection();
        await tester.pump(const Duration(seconds: 1));
        await tester.pump();
        expect(controller.journal.trafficObservation.tx, isNull);
        expect(
          controller.trafficNotice,
          isNot(contains('SYNTHETIC_PRIVATE_TRAFFIC_ERROR')),
        );
        expect(
          jsonEncode(controller.journal.events.map((e) => e.toJson()).toList()),
          isNot(contains('SYNTHETIC_PRIVATE_TRAFFIC_ERROR')),
        );
      } finally {
        controller.dispose();
      }
    },
  );
}
