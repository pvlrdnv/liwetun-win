import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/domain/import_link.dart';

import 'fixtures.dart';

void main() {
  test('TT QR is normalized locally, no HTTP client involved', () {
    final direct = parseLink(tt);
    final qr = parseLink('https://trusttunnel.org/#tt=$ttPayload');
    expect(qr.localId, direct.localId);
    expect(qr.secret.value, tt);
    expect(qr.protocol, Protocol.trusttunnel);
  });

  test('TT payload is kept opaque, not claimed to be decoded', () {
    expect(parseLink(tt).secret.value, tt);
    expect(parseLink(tt).secret.toString(), isNot(contains(ttPayload)));
  });

  test('classifies personal HTTPS source separately', () {
    final imported = parseLink(
      'https://feed.example.invalid/sub/synthetic-token',
    );
    expect(imported.kind, ImportKind.subscription);
    expect(imported.protocol, isNull);
  });

  test('supported HY2 and TLS/REALITY VLESS subset', () {
    expect(parseLink(hy2).protocol, Protocol.hysteria2);
    expect(parseLink(vless).protocol, Protocol.vless);
    expect(
      parseLink(hy2.replaceFirst('hy2:', 'hysteria2:')).protocol,
      Protocol.hysteria2,
    );
  });

  for (final bad in [
    '',
    'http://feed.example.invalid/secret',
    'https://user:password@feed.example.invalid/sub',
    'https://feed.example.invalid/#secret',
    'https://trusttunnel.org/#tt=short',
    'https://trusttunnel.org/other#tt=$ttPayload',
    'tt://?bad+payload',
    '$hy2&insecure=1',
    '$hy2&allowInsecure=true',
    '$hy2&skip_cert_verify=yes',
    '$hy2&sni=duplicate',
    'hy2://password@node.example.invalid:0',
    'hy2://password@node.example.invalid:99999',
    'hy2://password@node.example.invalid',
    'vless://invalid-uuid@node.example.invalid:443?security=tls',
    vless.replaceFirst('security=reality', 'security=none'),
    'file:///etc/passwd',
    'tt://?$ttPayload\nsecret',
    'x' * 8193,
  ]) {
    test(
      'rejects malformed/unsafe input case ${bad.length}:${bad.hashCode}',
      () {
        expect(() => parseLink(bad), throwsA(isA<LinkException>()));
        try {
          parseLink(bad);
        } on LinkException catch (error) {
          expect(error.toString(), isNot(contains('password')));
          expect(error.toString(), isNot(contains(ttPayload)));
        }
      },
    );
  }
}
