enum TrafficHealth { unknown, idle, flowing, outgoingWithoutReply }

final class TrafficSample {
  const TrafficSample(this.at, {this.tx, this.rx});
  final Duration at;
  final int? tx;
  final int? rx;
}

/// Evidence about counters only; never labels a server down or proves DNS health.
TrafficHealth classifyTraffic(
  TrafficSample previous,
  TrafficSample current, {
  Duration minimumWindow = const Duration(seconds: 20),
}) {
  if (minimumWindow <= Duration.zero ||
      current.at - previous.at < minimumWindow ||
      previous.tx == null ||
      previous.rx == null ||
      current.tx == null ||
      current.rx == null ||
      previous.tx! < 0 ||
      previous.rx! < 0 ||
      current.tx! < previous.tx! ||
      current.rx! < previous.rx!) {
    return TrafficHealth.unknown;
  }
  final tx = current.tx! - previous.tx!;
  final rx = current.rx! - previous.rx!;
  if (tx == 0 && rx == 0) return TrafficHealth.idle;
  if (tx > 0 && rx == 0) return TrafficHealth.outgoingWithoutReply;
  return TrafficHealth.flowing;
}
