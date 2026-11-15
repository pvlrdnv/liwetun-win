import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/native/trusttunnel.dart';

import 'fixtures.dart';

final class _Inspector implements TrustTunnelInspector {
  _Inspector(this.answer);
  final Future<NativeInspection> answer;
  @override
  Future<NativeInspection> inspect(SecretLink link) => answer;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(
    () => messenger.setMockMethodCallHandler(WindowsTrustTunnel.channel, null),
  );

  test('channel request is narrow and accepted metadata is typed', () async {
    messenger.setMockMethodCallHandler(WindowsTrustTunnel.channel, (
      call,
    ) async {
      expect(call.method, 'inspectTrustTunnel');
      expect(call.arguments, {'uri': tt});
      return {
        'status': 'accepted',
        'transport': 3,
        'customCertificate': true,
        'hasIpv6': false,
      };
    });
    final result = await const WindowsTrustTunnel().inspect(
      const SecretLink(tt),
    );
    expect(result.status, NativeImportStatus.accepted);
    expect(result.transport, 3);
    expect(result.customCertificate, true);
    expect(result.hasIpv6, false);
  });

  test(
    'raw platform exceptions and unknown responses never leak private data',
    () async {
      const canary = 'UNIQUE_NATIVE_PRIVATE_CANARY_261115';
      for (final response in [
        null,
        {'status': canary},
        {'status': 'accepted'},
        {'status': 'accepted', 'transport': 9},
        {
          'status': 'accepted',
          'transport': 2.0,
          'customCertificate': false,
          'hasIpv6': true,
        },
      ]) {
        messenger.setMockMethodCallHandler(
          WindowsTrustTunnel.channel,
          (_) async => response,
        );
        final result = await const WindowsTrustTunnel().inspect(
          const SecretLink(canary),
        );
        expect(result.status, NativeImportStatus.unavailable);
        expect(result.toString(), isNot(contains(canary)));
      }
      messenger.setMockMethodCallHandler(WindowsTrustTunnel.channel, (_) async {
        throw PlatformException(code: canary, message: canary, details: canary);
      });
      expect(
        (await const WindowsTrustTunnel().inspect(
          const SecretLink(canary),
        )).status,
        NativeImportStatus.unavailable,
      );
    },
  );

  for (final status in [
    NativeImportStatus.malformed,
    NativeImportStatus.insecure,
    NativeImportStatus.unsupported,
  ]) {
    test('native ${status.name} rejection never adds a profile', () async {
      final controller = AppController(
        inspector: _Inspector(Future.value(NativeInspection(status))),
      );
      addTearDown(controller.dispose);
      final message = await controller.importValidated(tt);
      expect(controller.connections, isEmpty);
      expect(message, isNot(contains(ttPayload)));
    });
  }

  test('accepted metadata is retained without implying live traffic', () async {
    final controller = AppController(
      inspector: _Inspector(
        Future.value(
          const NativeInspection(
            NativeImportStatus.accepted,
            transport: 2,
            customCertificate: false,
            hasIpv6: true,
          ),
        ),
      ),
    );
    addTearDown(controller.dispose);
    final message = await controller.importValidated(tt);
    expect(controller.connections.single.inspection!.transport, 2);
    expect(message, contains('Подключение службы ещё недоступно'));
  });

  test(
    'missing native plugin retains explicitly unvalidated profile',
    () async {
      final controller = AppController(
        inspector: _Inspector(
          Future.value(const NativeInspection(NativeImportStatus.unavailable)),
        ),
      );
      addTearDown(controller.dispose);
      await controller.importValidated(tt);
      expect(controller.connections.single.inspection, isNull);
    },
  );

  test('late native completion after controller disposal is ignored', () async {
    final pending = Completer<NativeInspection>();
    final controller = AppController(inspector: _Inspector(pending.future));
    final operation = controller.importValidated(tt);
    controller.dispose();
    pending.complete(const NativeInspection(NativeImportStatus.accepted));
    await operation;
    expect(controller.connections, isEmpty);
  });
}
