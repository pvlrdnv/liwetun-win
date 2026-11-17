import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/network/subscription_transport.dart';

const secretSource = SecretLink(
  'https://subscription.example.invalid/PRIVATE_CANARY',
);

final class _Headers extends Fake implements HttpHeaders {
  final values = <String, String>{};
  @override
  ContentType? get contentType => values[HttpHeaders.contentTypeHeader] == null
      ? null
      : ContentType.parse(values[HttpHeaders.contentTypeHeader]!);
  @override
  String? value(String name) => values[name];
  @override
  void set(String name, Object value, {bool preserveHeaderCase = false}) {
    values[name] = value.toString();
  }
}

final class _Response extends Fake implements HttpClientResponse {
  _Response({String body = '{}', Stream<List<int>>? stream})
    : stream = stream ?? Stream.value(utf8.encode(body)) {
    headers.values[HttpHeaders.contentTypeHeader] = 'application/json';
  }
  final Stream<List<int>> stream;
  @override
  final _Headers headers = _Headers();
  @override
  int statusCode = 200;
  @override
  int contentLength = -1;
  @override
  StreamSubscription<List<int>> listen(
    void Function(List<int>)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => stream.listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );
}

final class _Request extends Fake implements HttpClientRequest {
  _Request(this.response);
  final _Response response;
  int closes = 0;
  @override
  final _Headers headers = _Headers();
  @override
  bool followRedirects = true;
  @override
  int maxRedirects = 5;
  @override
  bool persistentConnection = true;
  @override
  Future<HttpClientResponse> close() async {
    closes++;
    return response;
  }
}

final class _SecureSocket extends Fake implements SecureSocket {
  bool destroyed = false;
  @override
  void destroy() {
    destroyed = true;
  }
}

final class _PlainSocket extends Fake implements Socket {
  bool destroyed = false;
  @override
  void destroy() {
    destroyed = true;
  }
}

final class _Client extends Fake implements HttpClient {
  _Client(this.request);
  final _Request request;
  bool closed = false;
  int gets = 0;
  Future<ConnectionTask<Socket>> Function(Uri, String?, int?)? connect;
  @override
  set connectionFactory(
    Future<ConnectionTask<Socket>> Function(Uri, String?, int?)? value,
  ) {
    connect = value;
  }

  @override
  Future<HttpClientRequest> getUrl(Uri uri) async {
    gets++;
    final task = await connect!(uri, null, null);
    await task.socket;
    return request;
  }

  @override
  void close({bool force = false}) {
    closed = true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) {
    if (invocation.isSetter) return null;
    return super.noSuchMethod(invocation);
  }
}

void main() {
  late _Response response;
  late _Request request;
  late _Client client;
  late HttpSubscriptionTransport transport;
  late int lookups, connects;
  late List<InternetAddress> addresses;
  late List<(String, String)> dialed;
  setUp(() {
    response = _Response();
    request = _Request(response);
    client = _Client(request);
    lookups = connects = 0;
    dialed = [];
    addresses = [InternetAddress('8.8.8.8')];
    transport = HttpSubscriptionTransport(
      resolver: (_) async {
        lookups++;
        return addresses;
      },
      connector: (address, port, hostname) async {
        connects++;
        dialed.add((address.address, hostname));
        return ConnectionTask.fromSocket(
          Future<Socket>.value(_SecureSocket()),
          () {},
        );
      },
      clientFactory: () => client,
      proxyResolver: (_) => 'DIRECT',
    );
  });
  tearDown(() => transport.close());

  test(
    'numeric destination is pinned while TLS retains original hostname',
    () async {
      final reply = await transport.fetch(secretSource);
      expect(reply.code, SubscriptionFetchCode.ok);
      expect(reply.payload, '{}');
      expect(lookups, 1);
      expect(dialed, [('8.8.8.8', 'subscription.example.invalid')]);
      expect(request.followRedirects, isFalse);
      expect(request.maxRedirects, 0);
      expect(request.persistentConnection, isFalse);
      expect(request.headers.values, {
        'accept': 'application/json',
        'accept-encoding': 'identity',
      });
      expect(client.closed, isTrue);
      expect(reply.toString(), isNot(contains('PRIVATE_CANARY')));
    },
  );

  test(
    'mixed public/private DNS reply is rejected before any connection',
    () async {
      addresses.add(InternetAddress('127.0.0.1'));
      expect(
        (await transport.fetch(secretSource)).code,
        SubscriptionFetchCode.privateAddress,
      );
      expect(connects, 0);
      expect(client.gets, 0);
    },
  );

  test('TT wrapper and insecure inputs are never fetched', () async {
    for (final value in [
      'http://subscription.example.invalid/PRIVATE_CANARY',
      'https://trusttunnel.org/#tt=SYNTHETIC_PRIVATE_CANARY',
      'https://user:PRIVATE_CANARY@subscription.example.invalid/',
    ]) {
      final reply = await transport.fetch(SecretLink(value));
      expect(reply.code, SubscriptionFetchCode.malformedSource);
      expect(reply.toString(), isNot(contains('PRIVATE_CANARY')));
    }
    expect(lookups, 0);
    expect(connects, 0);
  });

  test('configured proxy is never silently bypassed', () async {
    final proxied = HttpSubscriptionTransport(
      proxyResolver: (_) => 'PROXY 127.0.0.1:3128',
      resolver: (_) async {
        fail('Proxy configuration bypassed');
      },
    );
    addTearDown(proxied.close);
    expect(
      (await proxied.fetch(secretSource)).code,
      SubscriptionFetchCode.unsupportedProxy,
    );
  });

  for (final status in [301, 302, 307, 308, 401, 403, 500]) {
    test(
      'HTTP $status has no body or redirect/revocation interpretation',
      () async {
        response.statusCode = status;
        response.headers.set('location', 'https://127.0.0.1/PRIVATE_CANARY');
        final reply = await transport.fetch(secretSource);
        expect(reply.code, SubscriptionFetchCode.httpStatus);
        expect(reply.payload, isNull);
        expect(connects, 1);
        expect(client.closed, isTrue);
      },
    );
  }

  test('compressed or non-JSON content is rejected', () async {
    response.headers.set('content-encoding', 'gzip');
    expect(
      (await transport.fetch(secretSource)).code,
      SubscriptionFetchCode.contentType,
    );
  });

  test('declared body limit is enforced before reading body', () async {
    response.contentLength = HttpSubscriptionTransport.maxBytes + 1;
    expect(
      (await transport.fetch(secretSource)).code,
      SubscriptionFetchCode.tooLarge,
    );
  });

  test('streaming size and invalid UTF8 return closed failures', () async {
    for (final (chunks, expected) in [
      (
        [List<int>.filled(HttpSubscriptionTransport.maxBytes + 1, 65)],
        SubscriptionFetchCode.tooLarge,
      ),
      (
        [
          [0xff],
        ],
        SubscriptionFetchCode.malformedBody,
      ),
    ]) {
      final replyClient = _Client(
        _Request(_Response(stream: Stream.fromIterable(chunks))),
      );
      final candidate = HttpSubscriptionTransport(
        resolver: (_) async => addresses,
        proxyResolver: (_) => 'DIRECT',
        clientFactory: () => replyClient,
        connector: (_, _, _) async => ConnectionTask.fromSocket(
          Future<Socket>.value(_SecureSocket()),
          () {},
        ),
      );
      addTearDown(candidate.close);
      final reply = await candidate.fetch(secretSource);
      expect(reply.code, expected);
      expect(reply.payload, isNull);
      expect(replyClient.closed, isTrue);
    }
  });

  test('plain socket from a connector is never treated as HTTPS', () async {
    final plain = _PlainSocket();
    final candidate = HttpSubscriptionTransport(
      resolver: (_) async => addresses,
      proxyResolver: (_) => 'DIRECT',
      clientFactory: () => client,
      connector: (_, _, _) async =>
          ConnectionTask.fromSocket(Future<Socket>.value(plain), () {}),
    );
    addTearDown(candidate.close);
    expect(
      (await candidate.fetch(secretSource)).code,
      SubscriptionFetchCode.tls,
    );
    expect(plain.destroyed, isTrue);
    expect(request.closes, 0);
  });

  test('close cancels pending DNS without a later connection', () async {
    final dns = Completer<List<InternetAddress>>();
    final candidate = HttpSubscriptionTransport(
      resolver: (_) => dns.future,
      proxyResolver: (_) => 'DIRECT',
      clientFactory: () => client,
    );
    final fetching = candidate.fetch(secretSource);
    candidate.close();
    expect((await fetching).code, SubscriptionFetchCode.cancelled);
    dns.complete(addresses);
    await Future<void>.delayed(Duration.zero);
    expect(client.gets, 0);
  });

  test('absolute response timeout cancels body observation', () async {
    final body = StreamController<List<int>>();
    var cancelled = false;
    body.onCancel = () {
      cancelled = true;
    };
    final replyClient = _Client(_Request(_Response(stream: body.stream)));
    final candidate = HttpSubscriptionTransport(
      timeout: const Duration(seconds: 1),
      resolver: (_) async => addresses,
      proxyResolver: (_) => 'DIRECT',
      clientFactory: () => replyClient,
      connector: (_, _, _) async => ConnectionTask.fromSocket(
        Future<Socket>.value(_SecureSocket()),
        () {},
      ),
    );
    addTearDown(candidate.close);
    addTearDown(body.close);
    expect(
      (await candidate.fetch(secretSource)).code,
      SubscriptionFetchCode.timeout,
    );
    expect(replyClient.closed, isTrue);
    expect(cancelled, isTrue);
  });

  test(
    'close cancels a hanging response without waiting for its timeout',
    () async {
      final body = StreamController<List<int>>();
      var cancelled = false;
      body.onCancel = () {
        cancelled = true;
      };
      final replyClient = _Client(_Request(_Response(stream: body.stream)));
      final candidate = HttpSubscriptionTransport(
        resolver: (_) async => addresses,
        proxyResolver: (_) => 'DIRECT',
        clientFactory: () => replyClient,
        connector: (_, _, _) async => ConnectionTask.fromSocket(
          Future<Socket>.value(_SecureSocket()),
          () {},
        ),
      );
      addTearDown(candidate.close);
      addTearDown(body.close);
      final fetching = candidate.fetch(secretSource);
      await Future<void>.delayed(Duration.zero);
      candidate.close();
      expect(
        (await fetching.timeout(const Duration(seconds: 1))).code,
        SubscriptionFetchCode.cancelled,
      );
      expect(cancelled, isTrue);
    },
  );

  test('late DNS completion after deadline never creates a client', () async {
    final dns = Completer<List<InternetAddress>>();
    final candidate = HttpSubscriptionTransport(
      timeout: const Duration(milliseconds: 20),
      resolver: (_) => dns.future,
      proxyResolver: (_) => 'DIRECT',
      clientFactory: () => client,
    );
    addTearDown(candidate.close);
    expect(
      (await candidate.fetch(secretSource)).code,
      SubscriptionFetchCode.timeout,
    );
    dns.complete(addresses);
    await Future<void>.delayed(Duration.zero);
    expect(client.gets, 0);
  });

  test(
    'TLS failure never tries a different address or reveals its exception',
    () async {
      var attempts = 0;
      final candidate = HttpSubscriptionTransport(
        resolver: (_) async => [
          InternetAddress('8.8.8.8'),
          InternetAddress('1.1.1.1'),
        ],
        proxyResolver: (_) => 'DIRECT',
        clientFactory: () => client,
        connector: (_, _, _) async {
          attempts++;
          throw const TlsException('PRIVATE_CANARY');
        },
      );
      addTearDown(candidate.close);
      final reply = await candidate.fetch(secretSource);
      expect(reply.code, SubscriptionFetchCode.tls);
      expect(reply.toString(), isNot(contains('PRIVATE_CANARY')));
      expect(attempts, 1);
      expect(request.closes, 0);
    },
  );

  test(
    'numeric connection fallback is bounded to four resolved addresses',
    () async {
      var attempts = 0;
      final candidate = HttpSubscriptionTransport(
        resolver: (_) async =>
            List.generate(8, (i) => InternetAddress('8.8.8.${i + 1}')),
        proxyResolver: (_) => 'DIRECT',
        clientFactory: () => client,
        connector: (_, _, _) async {
          attempts++;
          throw const SocketException('PRIVATE_CANARY');
        },
      );
      addTearDown(candidate.close);
      final reply = await candidate.fetch(secretSource);
      expect(reply.code, SubscriptionFetchCode.network);
      expect(reply.toString(), isNot(contains('PRIVATE_CANARY')));
      expect(attempts, 4);
      expect(request.closes, 0);
    },
  );

  test('HTML never reaches the subscription parser', () async {
    response.headers.set('content-type', 'text/html');
    final reply = await transport.fetch(secretSource);
    expect(reply.code, SubscriptionFetchCode.contentType);
    expect(reply.payload, isNull);
  });

  test(
    'DNS exceptions never disclose the private URL or exception text',
    () async {
      final candidate = HttpSubscriptionTransport(
        proxyResolver: (_) => 'DIRECT',
        resolver: (_) async => throw const SocketException('PRIVATE_CANARY'),
        clientFactory: () => client,
      );
      addTearDown(candidate.close);
      final reply = await candidate.fetch(secretSource);
      expect(reply.code, SubscriptionFetchCode.dns);
      expect(reply.toString(), isNot(contains('PRIVATE_CANARY')));
      expect(client.gets, 0);
    },
  );

  for (final address in [
    '0.0.0.0',
    '10.1.2.3',
    '100.64.0.1',
    '127.0.0.1',
    '169.254.169.254',
    '172.31.255.255',
    '192.168.1.1',
    '192.0.2.1',
    '198.18.0.1',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:8.8.8.8',
    '64:ff9b::a00:1',
    'fc00::1',
    'fe80::1',
    '2001::1',
    '2001:db8::1',
    '2002:7f00:1::',
    '3fff::1',
    'ff02::1',
  ]) {
    test('non-public/transition fixture $address is rejected', () {
      expect(subscriptionAddressAllowed(InternetAddress(address)), isFalse);
    });
  }
  test('ordinary public IPv4 and global IPv6 are accepted without network', () {
    for (final address in [
      '1.1.1.1',
      '8.8.8.8',
      '2001:4860:4860::8888',
      '2606:4700:4700::1111',
    ]) {
      expect(subscriptionAddressAllowed(InternetAddress(address)), isTrue);
    }
  });
}
