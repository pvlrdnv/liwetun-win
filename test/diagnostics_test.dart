import 'dart:convert';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/diagnostics/journal.dart';
import 'package:liwetun/domain/traffic_health.dart';

void main() {
  test('secret canaries never enter events, ZIP or printed exceptions', () {
    const token = 'UNIQUE_SYNTHETIC_SECRET_261115_DO_NOT_LOG';
    final controller = AppController();
    for (final input in [
      'https://feed.example.invalid/sub/$token',
      'hy2://$token@node.example.invalid:443',
      'http://feed.example.invalid/$token',
      'tt://?$token',
      'vless://$token@node.example.invalid:443?security=tls',
      'malformed/$token%',
    ]) {
      final result = controller.import(input);
      expect(result, isNot(contains(token)));
    }
    controller.connectionUnavailable();
    final log = jsonEncode(
      controller.journal.events.map((event) => event.toJson()).toList(),
    );
    expect(log, isNot(contains(token)));
    final archive = ZipDecoder().decodeBytes(controller.journal.exportZip());
    expect(archive.files.map((file) => file.name).toSet(), {
      'summary.json',
      'events.jsonl',
    });
    for (final file in archive.files) {
      final text = utf8.decode(file.content as List<int>);
      expect(text, isNot(contains(token)));
      expect(text, isNot(contains('example.invalid')));
      expect(text, isNot(contains('https://')));
    }
    controller.dispose();
  });

  test('bounded in-memory journal drops oldest and clears completely', () {
    final journal = Journal(maxEvents: 2);
    journal.record(EventId.appStarted);
    journal.record(EventId.importAccepted);
    journal.record(EventId.importRejected);
    expect(journal.events.map((event) => event.event), [
      EventId.importAccepted,
      EventId.importRejected,
    ]);
    journal.clear();
    expect(journal.events, isEmpty);
    expect(journal.preview.start, isNull);
    expect(journal.exportZip(), isNotEmpty);
  });

  test('missing, reset, too-short or invalid counters are unknown', () {
    const first = TrafficSample(Duration.zero, tx: 10, rx: 20);
    for (final sample in [
      const TrafficSample(Duration(seconds: 30), tx: 30),
      const TrafficSample(Duration(seconds: 30), tx: 0, rx: 0),
      const TrafficSample(Duration(seconds: 1), tx: 30, rx: 30),
      const TrafficSample(Duration(seconds: -1), tx: 30, rx: 30),
    ]) {
      expect(classifyTraffic(first, sample), TrafficHealth.unknown);
    }
  });

  test('idle is distinct from TX-without-RX and actual RX growth', () {
    const first = TrafficSample(Duration.zero, tx: 10, rx: 20);
    expect(
      classifyTraffic(
        first,
        const TrafficSample(Duration(seconds: 30), tx: 10, rx: 20),
      ),
      TrafficHealth.idle,
    );
    expect(
      classifyTraffic(
        first,
        const TrafficSample(Duration(seconds: 30), tx: 30, rx: 20),
      ),
      TrafficHealth.outgoingWithoutReply,
    );
    expect(
      classifyTraffic(
        first,
        const TrafficSample(Duration(seconds: 30), tx: 30, rx: 30),
      ),
      TrafficHealth.flowing,
    );
  });
}
