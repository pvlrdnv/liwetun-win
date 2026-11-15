import 'package:flutter/services.dart';

import '../domain/import_link.dart';

enum NativeImportStatus {
  accepted,
  malformed,
  insecure,
  unsupported,
  unavailable,
}

final class NativeInspection {
  const NativeInspection(
    this.status, {
    this.transport,
    this.customCertificate,
    this.hasIpv6,
  });
  final NativeImportStatus status;
  final int? transport;
  final bool? customCertificate;
  final bool? hasIpv6;
}

abstract interface class TrustTunnelInspector {
  Future<NativeInspection> inspect(SecretLink link);
}

final class WindowsTrustTunnel implements TrustTunnelInspector {
  const WindowsTrustTunnel();
  static const channel = MethodChannel('top.likeweb.liwetun/trusttunnel');

  @override
  Future<NativeInspection> inspect(SecretLink link) async {
    try {
      final response = await channel
          .invokeMapMethod<String, dynamic>('inspectTrustTunnel', {
            'uri': link.value,
          })
          .timeout(const Duration(seconds: 3));
      final status = switch (response?['status']) {
        'accepted' => NativeImportStatus.accepted,
        'malformed' => NativeImportStatus.malformed,
        'insecure' => NativeImportStatus.insecure,
        'unsupported' => NativeImportStatus.unsupported,
        _ => NativeImportStatus.unavailable,
      };
      if (status != NativeImportStatus.accepted) {
        return NativeInspection(status);
      }
      final transport = response?['transport'];
      if (![2, 3].contains(transport) ||
          response?['customCertificate'] is! bool ||
          response?['hasIpv6'] is! bool) {
        return const NativeInspection(NativeImportStatus.unavailable);
      }
      return NativeInspection(
        status,
        transport: transport as int,
        customCertificate: response!['customCertificate'] as bool,
        hasIpv6: response['hasIpv6'] as bool,
      );
    } catch (_) {
      // Native errors may carry private details. Do not retain/print them.
      return const NativeInspection(NativeImportStatus.unavailable);
    }
  }
}
