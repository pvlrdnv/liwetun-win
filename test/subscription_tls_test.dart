import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/network/subscription_transport.dart';

final class _RealHttp extends HttpOverrides {}

void main() {
  final fixture = Platform.environment['LIWETUN_SUBSCRIPTION_TLS_FIXTURE'];
  group(
    'synthetic loopback HTTPS (no OS trust changes)',
    () {
      late HttpServer server;
      late SecurityContext trusted;
      late HttpSubscriptionTransport transport;
      late int requests;
      late void Function(HttpRequest) handler;
      setUp(() async {
        final root = Directory(fixture!);
        final certificate = '${root.path}/cert.pem';
        final context = SecurityContext(withTrustedRoots: false)
          ..useCertificateChain(certificate)
          ..usePrivateKey('${root.path}/key.pem');
        trusted = SecurityContext(withTrustedRoots: false)
          ..setTrustedCertificates(certificate);
        requests = 0;
        handler = (request) {
          request.response.headers.contentType = ContentType.json;
          request.response.write('{}');
        };
        server = await HttpServer.bindSecure(
          InternetAddress.loopbackIPv4,
          0,
          context,
        );
        server.listen((request) async {
          requests++;
          try {
            handler(request);
            await request.response.close();
          } catch (_) {
            // Expected when a bounded test client closes an oversized response.
          }
        }, onError: (_) {});
        transport = HttpSubscriptionTransport(
          resolver: (_) async => [InternetAddress('8.8.8.8')],
          proxyResolver: (_) => 'DIRECT',
          clientFactory: () => _RealHttp().createHttpClient(null),
          connector: (address, port, hostname) {
            expect(address.address, '8.8.8.8');
            expect(port, 443);
            return openSubscriptionTls(
              InternetAddress.loopbackIPv4,
              server.port,
              hostname,
              context: trusted,
            );
          },
        );
      });
      tearDown(() async {
        transport.close();
        await server.close(force: true);
      });

      test(
        'real TLS and HTTP preserve Host without cookies or authorization',
        () async {
          String? host, cookie, authorization;
          handler = (request) {
            host = request.headers.value(HttpHeaders.hostHeader);
            cookie = request.headers.value(HttpHeaders.cookieHeader);
            authorization = request.headers.value(
              HttpHeaders.authorizationHeader,
            );
            request.response.headers.contentType = ContentType.json;
            request.response.write(jsonEncode({'synthetic': true}));
          };
          final reply = await transport.fetch(
            const SecretLink(
              'https://subscription.example.invalid/SYNTHETIC_PRIVATE',
            ),
          );
          expect(reply.code, SubscriptionFetchCode.ok);
          expect(jsonDecode(reply.payload!)['synthetic'], true);
          expect(host, 'subscription.example.invalid');
          expect(cookie, isNull);
          expect(authorization, isNull);
          expect(requests, 1);
        },
      );

      test('correct CA never permits a mismatched TLS hostname', () async {
        final task = await openSubscriptionTls(
          InternetAddress.loopbackIPv4,
          server.port,
          'wrong.example.invalid',
          context: trusted,
        );
        await expectLater(task.socket, throwsA(isA<TlsException>()));
        task.cancel();
        expect(requests, 0);
      });

      test('default trust rejects a synthetic untrusted certificate', () async {
        final task = await openSubscriptionTls(
          InternetAddress.loopbackIPv4,
          server.port,
          'subscription.example.invalid',
        );
        await expectLater(task.socket, throwsA(isA<TlsException>()));
        task.cancel();
        expect(requests, 0);
      });

      test('real redirect response never opens its Location', () async {
        handler = (request) {
          request.response.statusCode = HttpStatus.found;
          request.response.headers.set(
            HttpHeaders.locationHeader,
            'https://127.0.0.1/REDIRECT_PRIVATE',
          );
        };
        final reply = await transport.fetch(
          const SecretLink(
            'https://subscription.example.invalid/SYNTHETIC_PRIVATE',
          ),
        );
        expect(reply.code, SubscriptionFetchCode.httpStatus);
        expect(reply.payload, isNull);
        expect(requests, 1);
      });

      test(
        'pinned HTTP parser bounds response headers as well as body',
        () async {
          handler = (request) {
            request.response.headers.set(
              'x-synthetic',
              'A' * (1024 * 1024 + 1),
            );
            request.response.headers.contentType = ContentType.json;
            request.response.write('{}');
          };
          final reply = await transport.fetch(
            const SecretLink(
              'https://subscription.example.invalid/SYNTHETIC_PRIVATE',
            ),
          );
          expect(reply.code, SubscriptionFetchCode.network);
          expect(reply.payload, isNull);
          expect(requests, 1);
        },
      );

      test('real chunked oversized response is bounded', () async {
        handler = (request) {
          request.response.headers.contentType = ContentType.json;
          request.response.add(
            List<int>.filled(HttpSubscriptionTransport.maxBytes + 1, 65),
          );
        };
        final reply = await transport.fetch(
          const SecretLink(
            'https://subscription.example.invalid/SYNTHETIC_PRIVATE',
          ),
        );
        expect(reply.code, SubscriptionFetchCode.tooLarge);
        expect(reply.payload, isNull);
        expect(requests, 1);
      });
    },
    skip: fixture == null
        ? 'Generate isolated synthetic TLS fixture first'
        : false,
  );
}
