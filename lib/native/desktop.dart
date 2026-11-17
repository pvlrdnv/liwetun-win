import 'package:flutter/services.dart';

final class DesktopStatus {
  const DesktopStatus({
    this.available = false,
    this.closeToTray = false,
    this.visible,
  });
  final bool available;
  final bool closeToTray;
  final bool? visible;
}

abstract interface class DesktopGateway {
  Future<DesktopStatus> configure(bool closeToTray);
}

final class WindowsDesktop implements DesktopGateway {
  const WindowsDesktop();
  static const channel = MethodChannel('top.likeweb.liwetun/desktop');
  @override
  Future<DesktopStatus> configure(bool closeToTray) async {
    try {
      final data = await channel
          .invokeMapMethod<String, dynamic>('configure', {
            'closeToTray': closeToTray,
          })
          .timeout(const Duration(seconds: 3));
      if (data == null ||
          data.length != 3 ||
          data['available'] is! bool ||
          data['closeToTray'] is! bool ||
          data['visible'] is! bool ||
          (data['closeToTray'] == true && data['available'] != true)) {
        return const DesktopStatus();
      }
      return DesktopStatus(
        available: data['available'] as bool,
        closeToTray: data['closeToTray'] as bool,
        visible: data['visible'] as bool,
      );
    } catch (_) {
      return const DesktopStatus();
    }
  }
}
