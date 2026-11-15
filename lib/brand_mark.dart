import 'package:flutter/material.dart';

/// Code-native counterpart of assets/brand/liwetun.svg.
class BrandMark extends StatelessWidget {
  const BrandMark({super.key, this.size = 32});
  final double size;
  @override
  Widget build(BuildContext context) => SizedBox.square(
    dimension: size,
    child: CustomPaint(painter: _MarkPainter()),
  );
}

class _MarkPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.scale(size.width / 64, size.height / 64);
    canvas.drawRRect(
      RRect.fromRectAndRadius(
        const Rect.fromLTWH(0, 0, 64, 64),
        const Radius.circular(16),
      ),
      Paint()..color = const Color(0xFF112B27),
    );
    final stroke = Paint()
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round
      ..strokeWidth = 6
      ..color = const Color(0xFF84D5B5);
    canvas.drawPath(
      Path()
        ..moveTo(18, 46)
        ..lineTo(18, 30)
        ..arcToPoint(const Offset(46, 30), radius: const Radius.circular(14))
        ..lineTo(46, 46),
      stroke,
    );
    stroke
      ..strokeWidth = 5
      ..color = const Color(0xFFF4F6F1);
    canvas.drawPath(
      Path()
        ..moveTo(30, 30)
        ..lineTo(30, 46)
        ..lineTo(37, 46),
      stroke,
    );
    canvas.restore();
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
