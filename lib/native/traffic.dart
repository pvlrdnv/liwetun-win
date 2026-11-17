import 'dart:collection';
import 'package:flutter/services.dart';
import '../domain/traffic_health.dart';
import 'service.dart';

/// Aggregate endpoint-routed client payload only; it cannot prove DNS/Internet.
final class TrafficObservation {
  const TrafficObservation({
    this.code = ServiceCode.serviceUnavailable,
    this.supported = false,
    this.valid = false,
    this.flags = 0,
    this.instance,
    this.epoch,
    this.atMs,
    this.tx,
    this.rx,
    this.lastTxMs,
    this.lastRxMs,
    this.coreState,
  });
  final ServiceCode code;
  final bool supported, valid;
  final int flags;
  final int? instance, epoch, atMs, tx, rx, lastTxMs, lastRxMs, coreState;
  bool get usable => code == ServiceCode.ok && supported && valid;

  static TrafficObservation decode(Map<String, dynamic>? data) {
    const rejected = TrafficObservation(code: ServiceCode.malformed);
    const keys = {
      'code',
      'supported',
      'valid',
      'flags',
      'instance',
      'epoch',
      'atMs',
      'tx',
      'rx',
      'lastTxMs',
      'lastRxMs',
      'coreState',
    };
    if (data == null ||
        data.length != keys.length ||
        !keys.every(data.containsKey) ||
        data['supported'] is! bool ||
        data['valid'] is! bool ||
        data['flags'] is! int) {
      return rejected;
    }
    final code = {
      for (final value in ServiceCode.values) value.name: value,
    }[data['code']];
    if (code == null) return rejected;
    final flags = data['flags'] as int;
    if (flags < 0 || flags > 63) return rejected;
    for (final key in [
      'instance',
      'epoch',
      'atMs',
      'tx',
      'rx',
      'lastTxMs',
      'lastRxMs',
      'coreState',
    ]) {
      final value = data[key];
      if (value != null && (value is! int || value < 0)) return rejected;
    }
    final supported = data['supported'] as bool;
    final valid = data['valid'] as bool;
    if (supported != (flags & 1 != 0) || valid != (flags & 2 != 0)) {
      return rejected;
    }
    final instance = data['instance'] as int?;
    final epoch = data['epoch'] as int?;
    final at = data['atMs'] as int?;
    final tx = data['tx'] as int?;
    final rx = data['rx'] as int?;
    final lastTx = data['lastTxMs'] as int?;
    final lastRx = data['lastRxMs'] as int?;
    final state = data['coreState'] as int?;
    if ((instance != null && instance == 0) ||
        (epoch != null && epoch == 0) ||
        (state != null && state > 5)) {
      return rejected;
    }
    if (!supported &&
        (flags != 0 ||
            instance != null ||
            epoch != null ||
            at != null ||
            tx != null ||
            rx != null ||
            lastTx != null ||
            lastRx != null ||
            state != null)) {
      return rejected;
    }
    if (valid) {
      if (code != ServiceCode.ok ||
          flags != 3 ||
          instance == null ||
          epoch == null ||
          at == null ||
          tx == null ||
          rx == null ||
          state != 2 ||
          (tx == 0) != (lastTx == null) ||
          (rx == 0) != (lastRx == null) ||
          (lastTx != null && lastTx > at) ||
          (lastRx != null && lastRx > at)) {
        return rejected;
      }
    } else if (tx != null || rx != null || lastTx != null || lastRx != null) {
      return rejected;
    }
    return TrafficObservation(
      code: code,
      supported: supported,
      valid: valid,
      flags: flags,
      instance: instance,
      epoch: epoch,
      atMs: at,
      tx: tx,
      rx: rx,
      lastTxMs: lastTx,
      lastRxMs: lastRx,
      coreState: state,
    );
  }

  Map<String, Object?> toJson() => {
    'code': code.name,
    'supported': supported,
    'valid': usable,
    'flags': flags,
    'instance': instance,
    'epoch': epoch,
    'sample_at_ms': atMs,
    'tx_bytes': usable ? tx : null,
    'rx_bytes': usable ? rx : null,
    'last_tx_ms': usable ? lastTxMs : null,
    'last_rx_ms': usable ? lastRxMs : null,
    'core_state': coreState,
  };
}

abstract interface class TrafficGateway {
  Future<TrafficObservation> read();
}

final class WindowsTraffic implements TrafficGateway {
  const WindowsTraffic();
  @override
  Future<TrafficObservation> read() async {
    try {
      final data = await WindowsService.channel
          .invokeMapMethod<String, dynamic>('traffic')
          .timeout(const Duration(seconds: 3));
      return TrafficObservation.decode(data);
    } on MissingPluginException {
      return const TrafficObservation();
    } catch (_) {
      return const TrafficObservation(code: ServiceCode.timeout);
    }
  }
}

/// A bounded rolling observation window; gaps and epoch changes discard history.
final class TrafficWindow {
  final Queue<TrafficObservation> _samples = Queue();
  void clear() => _samples.clear();
  TrafficHealth observe(TrafficObservation value) {
    if (!value.usable ||
        value.instance == null ||
        value.epoch == null ||
        value.atMs == null ||
        value.tx == null ||
        value.rx == null) {
      clear();
      return TrafficHealth.unknown;
    }
    if (_samples.isNotEmpty) {
      final last = _samples.last;
      if (value.instance != last.instance ||
          value.epoch != last.epoch ||
          value.atMs! <= last.atMs! ||
          value.atMs! - last.atMs! > 5000 ||
          value.tx! < last.tx! ||
          value.rx! < last.rx!) {
        clear();
      }
    }
    _samples.add(value);
    while (_samples.length > 64 || value.atMs! - _samples.first.atMs! > 30000) {
      _samples.removeFirst();
    }
    TrafficObservation? baseline;
    for (final sample in _samples) {
      if (value.atMs! - sample.atMs! >= 20000) baseline = sample;
    }
    if (baseline == null) return TrafficHealth.unknown;
    return classifyTraffic(
      TrafficSample(
        Duration(milliseconds: baseline.atMs!),
        tx: baseline.tx,
        rx: baseline.rx,
      ),
      TrafficSample(
        Duration(milliseconds: value.atMs!),
        tx: value.tx,
        rx: value.rx,
      ),
    );
  }
}
