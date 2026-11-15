import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/native/trusttunnel.dart';

import 'fixtures.dart';

final class _UnavailableInspector implements TrustTunnelInspector {
  @override
  Future<NativeInspection> inspect(SecretLink link) async =>
      const NativeInspection(NativeImportStatus.unavailable);
}

void main() {
  for (final size in [const Size(1280, 800), const Size(480, 800)]) {
    testWidgets('empty shell, navigation and unavailable connection at $size', (
      tester,
    ) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final controller = AppController();
      addTearDown(controller.dispose);
      await tester.pumpWidget(LiWeTunApp(controller: controller));
      expect(find.text('НЕ ПОДКЛЮЧЕНО'), findsOneWidget);
      expect(find.text('Начните с персональной ссылки'), findsOneWidget);
      await tester.tap(find.byIcon(Icons.power_settings_new));
      await tester.pumpAndSettle();
      expect(
        find.textContaining('Для подключения нужен модуль Windows.'),
        findsOneWidget,
      );
      await tester.tap(find.text('Серверы').last);
      await tester.pumpAndSettle();
      expect(find.textContaining('Пока ничего нет.'), findsOneWidget);
      await tester.tap(find.text('Поддержка').last);
      await tester.pumpAndSettle();
      expect(find.text('Сохранить отчёт для поддержки'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('import obscures input and never reports a live connection', (
    tester,
  ) async {
    final controller = AppController(inspector: _UnavailableInspector());
    addTearDown(controller.dispose);
    await tester.pumpWidget(LiWeTunApp(controller: controller));
    await tester.ensureVisible(find.text('Добавить подключение'));
    await tester.tap(find.text('Добавить подключение'));
    await tester.pumpAndSettle();
    final field = tester.widget<TextField>(find.byType(TextField));
    expect(field.obscureText, isTrue);
    await tester.enterText(find.byType(TextField), tt);
    await tester.tap(find.text('Добавить').last);
    await tester.pumpAndSettle();
    await tester.pump(const Duration(milliseconds: 400));
    await tester.pumpAndSettle();
    expect(controller.connections, hasLength(1));
    expect(find.text('НЕ ПОДКЛЮЧЕНО'), findsOneWidget);
    expect(find.text(tt), findsNothing);
    expect(tester.takeException(), isNull);
  });

  test(
    'duplicate QR/direct imports collapse and source is not selectable server',
    () {
      final controller = AppController();
      addTearDown(controller.dispose);
      controller.import(tt);
      controller.import('https://trusttunnel.org/#tt=$ttPayload');
      controller.import('https://feed.example.invalid/sub/synthetic');
      expect(controller.connections, hasLength(2));
      final selected = controller.selectedId;
      controller.select(controller.connections.last);
      expect(controller.selectedId, selected);
    },
  );
}
