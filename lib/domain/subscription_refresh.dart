/// Timing policy only. It neither fetches data nor grants cached access.
Duration subscriptionRefreshDelay({
  required DateTime now,
  required int failures,
  required int jitterSeconds,
  DateTime? earliestDeadline,
}) {
  if (failures < 0 || jitterSeconds < 0 || jitterSeconds > 120) {
    throw ArgumentError('invalid_subscription_refresh_policy');
  }
  if (failures > 0) {
    const delays = [30, 60, 120, 240, 480, 900];
    return Duration(
      seconds: delays[(failures - 1).clamp(0, 5)] + jitterSeconds % 31,
    );
  }
  var seconds = 15 * 60 + jitterSeconds;
  if (earliestDeadline != null) {
    final refreshBefore = (earliestDeadline.difference(now).inSeconds - 30)
        .clamp(30, seconds);
    seconds = refreshBefore;
  }
  return Duration(seconds: seconds);
}
