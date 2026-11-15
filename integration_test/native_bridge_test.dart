import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:liwetun/app.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/native/trusttunnel.dart';
import 'package:liwetun/native/service.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('actual Windows C++ channel and official decoder, no network', (
    tester,
  ) async {
    final controller = AppController();
    addTearDown(controller.dispose);
    await tester.pumpWidget(LiWeTunApp(controller: controller));
    final capabilities = await WindowsTrustTunnel.channel
        .invokeMapMethod<String, dynamic>('capabilities');
    expect(capabilities?['canInspect'], true);
    expect(capabilities?['canConnect'], false);
    expect(capabilities?['abiVersion'], 1);
    expect(
      capabilities?['decoderRevision'],
      '48f424c0874eb6f6374ee84492c5cd55aa04dca9',
    );
    for (final (uri, transport) in [
      (const String.fromEnvironment('SYNTHETIC_TT_HTTP2'), 2),
      (const String.fromEnvironment('SYNTHETIC_TT_HTTP3'), 3),
    ]) {
      expect(
        uri.isNotEmpty,
        true,
        reason: 'Generate synthetic fixture defines first',
      );
      final inspection = await const WindowsTrustTunnel().inspect(
        SecretLink(uri),
      );
      expect(inspection.status, NativeImportStatus.accepted);
      expect(inspection.transport, transport);
      await controller.importValidated(uri);
    }
    const insecure = String.fromEnvironment('SYNTHETIC_TT_INSECURE');
    expect(insecure.isNotEmpty, true);
    expect(
      (await const WindowsTrustTunnel().inspect(
        const SecretLink(insecure),
      )).status,
      NativeImportStatus.insecure,
    );
    expect(
      (await const WindowsTrustTunnel().inspect(
        const SecretLink('tt://?SYNTHETIC_NATIVE_PRIVATE_CANARY'),
      )).status,
      NativeImportStatus.malformed,
    );
    await tester.pumpAndSettle();
    expect(find.text('НЕ ПОДКЛЮЧЕНО'), findsOneWidget);
    expect(controller.connections.length, 2);
    // This unsigned workspace build must fail before SCM/pipe side effects.
    // Exercise the actual worker and platform-thread result delivery.
    const service = WindowsService();
    for (final request in [service.query, service.stop]) {
      final status = await request();
      expect(status.code, ServiceCode.untrustedInstallation);
      expect(status.runtimeReady, false);
      expect(status.coreState, isNull);
    }
    final start = await service.start(
      const SecretLink(String.fromEnvironment('SYNTHETIC_TT_HTTP2')),
    );
    expect(start.code, ServiceCode.untrustedInstallation);
    await expectLater(
      WindowsTrustTunnel.channel.invokeMethod<void>(
        'arbitraryPrivilegedCommand',
      ),
      throwsA(isA<MissingPluginException>()),
    );
  });
}
