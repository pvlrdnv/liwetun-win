import 'package:flutter/material.dart';
import 'dart:async';

import 'app.dart';
import 'app_controller.dart';
import 'native/environment.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = AppController();
  unawaited(controller.initializeJournal());
  unawaited(controller.initializeStorage());
  unawaited(
    const WindowsEnvironment().read().then((value) {
      controller.journal.environment = value;
    }),
  );
  runApp(LiWeTunApp(controller: controller));
}
