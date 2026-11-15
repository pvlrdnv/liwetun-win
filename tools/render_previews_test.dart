// Artifact generator, run explicitly; these images are not native Windows proof.
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/app.dart';
import 'package:liwetun/app_controller.dart';

void main() {
  testWidgets('render actual Flutter screens for review', (tester) async {
    final fontPath = const String.fromEnvironment('PREVIEW_FONT');
    if (fontPath.isNotEmpty) {
      final loader = FontLoader('Roboto')
        ..addFont(
          Future.value(ByteData.sublistView(File(fontPath).readAsBytesSync())),
        );
      await loader.load();
      final icons = FontLoader('MaterialIcons')
        ..addFont(
          Future.value(
            ByteData.sublistView(
              File(
                '${File(fontPath).parent.path}/MaterialIcons-Regular.otf',
              ).readAsBytesSync(),
            ),
          ),
        );
      await icons.load();
    }
    tester.view.physicalSize = const Size(1280, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final controller = AppController();
    addTearDown(controller.dispose);
    final boundary = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(
        key: boundary,
        child: LiWeTunApp(controller: controller),
      ),
    );
    await tester.pumpAndSettle();
    final directory = Directory('build/previews')..createSync(recursive: true);
    for (final (screen, label) in [
      ('home', 'Главная'),
      ('servers', 'Серверы'),
      ('support', 'Поддержка'),
    ]) {
      await tester.tap(find.text(label).last);
      await tester.pumpAndSettle();
      final render =
          boundary.currentContext!.findRenderObject()! as RenderRepaintBoundary;
      await tester.runAsync(() async {
        final image = await render.toImage();
        final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
        File(
          '${directory.path}/$screen.png',
        ).writeAsBytesSync(bytes!.buffer.asUint8List());
        image.dispose();
      });
    }
  });
}
