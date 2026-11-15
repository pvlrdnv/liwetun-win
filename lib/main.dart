import 'package:flutter/material.dart';
import 'dart:async';

import 'app.dart';
import 'app_controller.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = AppController();
  unawaited(controller.initializeStorage());
  runApp(LiWeTunApp(controller: controller));
}
