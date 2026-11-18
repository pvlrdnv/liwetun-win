import 'dart:async';
import 'dart:convert';
import 'package:archive/archive.dart';
import 'package:liwetun/app.dart';

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

  testWidgets('private embedded title and endpoint reach UI but never report', (
    tester,
  ) async {
    const name = 'Тестовый сервер PRIVATE_TITLE';
    const hostname = 'private-host.example.invalid';
    const addresses = '192.0.2.27:443, [2001:db8::27]:8443';
    messenger.setMockMethodCallHandler(
      WindowsTrustTunnel.channel,
      (_) async => {
        'status': 'accepted',
        'transport': 2,
        'customCertificate': false,
        'hasIpv6': true,
        'name': name,
        'hostname': hostname,
        'addresses': addresses,
      },
    );
    final controller = AppController(inspector: const WindowsTrustTunnel());
    addTearDown(controller.dispose);
    await controller.importValidated(tt);
    expect(controller.connections.single.title, name);
    await tester.pumpWidget(LiWeTunApp(controller: controller));
    await tester.tap(find.text('Серверы'));
    await tester.pumpAndSettle();
    expect(find.text(name), findsWidgets);
    await tester.ensureVisible(find.text('Технические детали'));
    await tester.tap(find.text('Технические детали'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Сервер: $hostname'), findsOneWidget);
    expect(find.textContaining('Адреса: $addresses'), findsOneWidget);
    // Metadata remains in memory; the diagnostic ZIP contains only closed fields.
    final archive = ZipDecoder().decodeBytes(controller.journal.exportZip());
    for (final entry in archive) {
      final body = utf8.decode(entry.content as List<int>);
      for (final private in [name, hostname, addresses, tt]) {
        expect(body, isNot(contains(private)));
      }
    }
  });

  test(
    'untrusted presentation controls are rejected without echoing them',
    () async {
      for (final value in ['fake\nserver', 'fake\u202eserver', 123]) {
        messenger.setMockMethodCallHandler(
          WindowsTrustTunnel.channel,
          (_) async => {
            'status': 'accepted',
            'transport': 2,
            'customCertificate': false,
            'hasIpv6': false,
            'name': value,
          },
        );
        final result = await const WindowsTrustTunnel().inspect(
          const SecretLink(tt),
        );
        expect(result.status, NativeImportStatus.unavailable);
        expect(result.name, isNull);
      }
    },
  );

  test('empty embedded name keeps numbered fallback', () {
    final link = parseLink(tt);
    expect(
      LocalConnection(
        1,
        link,
        inspection: const NativeInspection(
          NativeImportStatus.accepted,
          name: '',
        ),
      ).title,
      'Подключение 1',
    );
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
    expect(message, equals('Формат TrustTunnel проверен нативным модулем.'));
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
