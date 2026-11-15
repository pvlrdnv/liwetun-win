import 'package:flutter/services.dart';

enum AppArchitecture { x64 }

/// Reported API version, not a compatibility/feature decision or machine ID.
final class ClientEnvironment {
  const ClientEnvironment({
    this.major,
    this.minor,
    this.build,
    this.appArchitecture,
  });
  final int? major, minor, build;
  final AppArchitecture? appArchitecture;
  Map<String, Object?> toJson() => {
    'windows_api_major': major,
    'windows_api_minor': minor,
    'windows_api_build': build,
    'app_architecture': appArchitecture?.name,
  };
}

final class WindowsEnvironment {
  const WindowsEnvironment();
  static const channel = MethodChannel('top.likeweb.liwetun/service');
  Future<ClientEnvironment> read() async {
    try {
      final data = await channel
          .invokeMapMethod<String, dynamic>('environment')
          .timeout(const Duration(seconds: 3));
      if (data == null ||
          data.length != 4 ||
          !{
            'major',
            'minor',
            'build',
            'architecture',
          }.every(data.containsKey)) {
        return const ClientEnvironment();
      }
      for (final field in ['major', 'minor', 'build']) {
        final value = data[field];
        if (value is! int || value < 0 || value > 10000000) {
          return const ClientEnvironment();
        }
      }
      if (data['architecture'] != 'x64') return const ClientEnvironment();
      return ClientEnvironment(
        major: data['major'] as int,
        minor: data['minor'] as int,
        build: data['build'] as int,
        appArchitecture: AppArchitecture.x64,
      );
    } catch (_) {
      return const ClientEnvironment();
    }
  }
}
