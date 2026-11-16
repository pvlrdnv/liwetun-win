import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../domain/import_link.dart';

enum SubscriptionFetchCode {
  ok,
  malformedSource,
  privateAddress,
  unsupportedProxy,
  dns,
  network,
  tls,
  httpStatus,
  contentType,
  tooLarge,
  timeout,
  malformedBody,
  cancelled,
}

final class SubscriptionFetchReply {
  const SubscriptionFetchReply(this.code, {this.payload});
  final SubscriptionFetchCode code;
  final String? payload;
  @override
  String toString() => 'SubscriptionFetchReply(${code.name})';
}

abstract interface class SubscriptionTransport {
  Future<SubscriptionFetchReply> fetch(SecretLink source);
  void close();
}

final class _FetchFailure implements Exception {
  const _FetchFailure(this.code);
  final SubscriptionFetchCode code;
  @override
  String toString() => 'SubscriptionFetchFailure(${code.name})';
}

typedef SubscriptionResolver =
    Future<List<InternetAddress>> Function(String host);
typedef SubscriptionConnector =
    Future<ConnectionTask<Socket>> Function(
      InternetAddress address,
      int port,
      String hostname,
    );

// Conservative subscription-origin policy, reviewed against the IANA special
// registries on 2026-11-16. This is not a general Internet reachability oracle.
bool subscriptionAddressAllowed(InternetAddress address) {
  final bytes = address.rawAddress;
  if (address.type == InternetAddressType.IPv4) {
    final value = bytes.fold<int>(0, (value, byte) => (value << 8) | byte);
    for (final (network, bits) in <(int, int)>[
      (0x00000000, 8),
      (0x0a000000, 8),
      (0x64400000, 10),
      (0x7f000000, 8),
      (0xa9fe0000, 16),
      (0xac100000, 12),
      (0xc0000000, 24),
      (0xc0000200, 24),
      (0xc0586300, 24),
      (0xc0a80000, 16),
      (0xc6120000, 15),
      (0xc6336400, 24),
      (0xcb007100, 24),
      (0xe0000000, 4),
      (0xf0000000, 4),
    ]) {
      if ((value >> (32 - bits)) == (network >> (32 - bits))) return false;
    }
    return true;
  }
  if (address.type != InternetAddressType.IPv6 ||
      bytes.length != 16 ||
      (bytes[0] & 0xe0) != 0x20) {
    return false;
  }
  // Reject transition/special-purpose and documentation prefixes, including
  // IPv4-mapped/NAT64/ULA/link-local via the global-unicast requirement above.
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 2) return false;
  if (bytes[0] == 0x20 &&
      bytes[1] == 0x01 &&
      bytes[2] == 0x0d &&
      bytes[3] == 0xb8) {
    return false;
  }
  if (bytes[0] == 0x20 && bytes[1] == 0x02) return false;
  if (bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0) {
    return false;
  }
  return true;
}

/// Connect to a numeric address and verify TLS against the original hostname.
/// No second DNS lookup, certificate exception or global trust-store mutation.
/// An explicit context exists for isolated synthetic TLS fixtures only; the
/// production transport uses the default system-trusted context.
Future<ConnectionTask<Socket>> openSubscriptionTls(
  InternetAddress address,
  int port,
  String hostname, {
  SecurityContext? context,
}) async {
  final tcp = await Socket.startConnect(address, port);
  Socket? plain;
  SecureSocket? secure;
  var cancelled = false;
  void discard() {
    try {
      secure?.destroy();
    } catch (_) {}
    try {
      plain?.destroy();
    } catch (_) {}
  }

  Future<Socket> upgrade() async {
    try {
      plain = await tcp.socket.timeout(
        const Duration(seconds: 4),
        onTimeout: () {
          tcp.cancel();
          throw const SocketException('subscription_connect_timeout');
        },
      );
      if (cancelled) throw const _FetchFailure(SubscriptionFetchCode.cancelled);
      secure = await SecureSocket.secure(
        plain!,
        host: hostname,
        context: context,
        supportedProtocols: ['http/1.1'],
      );
      if (cancelled) throw const _FetchFailure(SubscriptionFetchCode.cancelled);
      return secure!;
    } catch (_) {
      tcp.cancel();
      discard();
      rethrow;
    }
  }

  final socket = upgrade();
  // Install an error observer before publishing the task; a failed connection
  // can complete before HttpClient attaches its own task.socket listener.
  socket.ignore();
  return ConnectionTask.fromSocket(socket, () {
    cancelled = true;
    tcp.cancel();
    discard();
  });
}

final class HttpSubscriptionTransport implements SubscriptionTransport {
  HttpSubscriptionTransport({
    SubscriptionResolver? resolver,
    SubscriptionConnector? connector,
    HttpClient Function()? clientFactory,
    String Function(Uri)? proxyResolver,
    this.timeout = const Duration(seconds: 15),
  }) : _resolver = resolver ?? InternetAddress.lookup,
       _connector = connector ?? openSubscriptionTls,
       _clientFactory = clientFactory ?? HttpClient.new,
       _proxyResolver = proxyResolver ?? HttpClient.findProxyFromEnvironment {
    if (timeout <= Duration.zero || timeout > const Duration(seconds: 30)) {
      throw ArgumentError('invalid_subscription_timeout');
    }
  }

  static const maxBytes = 1024 * 1024;
  final SubscriptionResolver _resolver;
  final SubscriptionConnector _connector;
  final HttpClient Function() _clientFactory;
  final String Function(Uri) _proxyResolver;
  final Duration timeout;
  final Set<HttpClient> _clients = {};
  bool _closed = false;
  final Set<Completer<Never>> _requests = {};

  @override
  void close() {
    if (_closed) return;
    _closed = true;
    for (final pending in _requests.toList()) {
      if (!pending.isCompleted) {
        pending.completeError(
          const _FetchFailure(SubscriptionFetchCode.cancelled),
        );
      }
    }
    for (final client in _clients.toList()) {
      try {
        client.close(force: true);
      } catch (_) {}
    }
  }

  @override
  Future<SubscriptionFetchReply> fetch(SecretLink source) async {
    if (_closed) {
      return const SubscriptionFetchReply(SubscriptionFetchCode.cancelled);
    }
    final watch = Stopwatch()..start();
    final cancelled = Completer<Never>();
    cancelled.future.ignore();
    _requests.add(cancelled);
    HttpClient? client;
    StreamIterator<List<int>>? iterator;
    var finished = false;
    Duration remaining() {
      final value = timeout - watch.elapsed;
      if (value <= Duration.zero) {
        throw const _FetchFailure(SubscriptionFetchCode.timeout);
      }
      if (_closed || finished) {
        throw const _FetchFailure(SubscriptionFetchCode.cancelled);
      }
      return value;
    }

    Future<T> bounded<T>(Future<T> value) =>
        Future.any<T>([value, cancelled.future]).timeout(remaining());
    try {
      final link = parseLink(source.value);
      if (link.kind != ImportKind.subscription) {
        return const SubscriptionFetchReply(
          SubscriptionFetchCode.malformedSource,
        );
      }
      final uri = Uri.parse(link.secret.value);
      if (uri.port < 1 || uri.port > 65535 || uri.host.contains('%')) {
        return const SubscriptionFetchReply(
          SubscriptionFetchCode.malformedSource,
        );
      }
      // Never silently bypass an existing proxy configuration. A proxy-aware
      // pinned-origin implementation is a separate capability.
      if (_proxyResolver(uri) != 'DIRECT') {
        return const SubscriptionFetchReply(
          SubscriptionFetchCode.unsupportedProxy,
        );
      }
      List<InternetAddress> resolved;
      try {
        resolved = await bounded(
          Future<List<InternetAddress>>.sync(() => _resolver(uri.host)),
        );
      } on SocketException {
        return const SubscriptionFetchReply(SubscriptionFetchCode.dns);
      }
      remaining();
      if (resolved.isEmpty || resolved.length > 32) {
        return const SubscriptionFetchReply(SubscriptionFetchCode.dns);
      }
      if (resolved.any((address) => !subscriptionAddressAllowed(address))) {
        return const SubscriptionFetchReply(
          SubscriptionFetchCode.privateAddress,
        );
      }
      final unique = <String, InternetAddress>{
        for (final address in resolved) address.address: address,
      };
      final addresses = unique.values.take(4).toList();
      final active = _clientFactory();
      client = active;
      _clients.add(active);
      active.autoUncompress = false;
      active.connectionTimeout = remaining();
      active.maxConnectionsPerHost = 1;
      active.userAgent = 'LiWeTun';
      active.badCertificateCallback = null;
      active.keyLog = null;
      active.authenticate = null;
      active.authenticateProxy = null;
      active.findProxy = (_) => 'DIRECT';
      active.connectionFactory = (requested, proxyHost, proxyPort) async {
        remaining();
        if (proxyHost != null || proxyPort != null) {
          throw const _FetchFailure(SubscriptionFetchCode.unsupportedProxy);
        }
        if (requested.scheme != 'https' ||
            requested.host != uri.host ||
            requested.port != uri.port) {
          throw const _FetchFailure(SubscriptionFetchCode.malformedSource);
        }
        ConnectionTask<Socket>? current;
        var cancelled = false;
        Future<Socket> connect() async {
          for (final address in addresses) {
            remaining();
            if (cancelled) {
              throw const _FetchFailure(SubscriptionFetchCode.cancelled);
            }
            try {
              current = await _connector(address, uri.port, uri.host);
              if (cancelled || _closed || finished) {
                current!.cancel();
                throw const _FetchFailure(SubscriptionFetchCode.cancelled);
              }
              final socket = await current!.socket;
              if (socket is! SecureSocket) {
                socket.destroy();
                throw const _FetchFailure(SubscriptionFetchCode.tls);
              }
              return socket;
            } on SocketException {
              current?.cancel();
            }
          }
          throw const _FetchFailure(SubscriptionFetchCode.network);
        }

        final socket = connect();
        socket.ignore();
        return ConnectionTask.fromSocket(socket, () {
          cancelled = true;
          current?.cancel();
        });
      };
      // Debug HTTP profiling retains full credential-bearing URLs. Keep it off
      // before the request is created; product builds also remove that profiler.
      HttpClient.enableTimelineLogging = false;
      final request = await bounded(active.getUrl(uri));
      request.followRedirects = false;
      request.maxRedirects = 0;
      request.persistentConnection = false;
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      request.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
      final response = await bounded(request.close());
      if (response.statusCode != HttpStatus.ok) {
        return const SubscriptionFetchReply(SubscriptionFetchCode.httpStatus);
      }
      final type = response.headers.contentType;
      final charset = type?.charset?.toLowerCase();
      final encoding = response.headers
          .value(HttpHeaders.contentEncodingHeader)
          ?.trim()
          .toLowerCase();
      if (type?.mimeType != 'application/json' ||
          (charset != null && charset.isNotEmpty && charset != 'utf-8') ||
          (encoding != null && encoding != 'identity')) {
        return const SubscriptionFetchReply(SubscriptionFetchCode.contentType);
      }
      if (response.contentLength > maxBytes) {
        return const SubscriptionFetchReply(SubscriptionFetchCode.tooLarge);
      }
      final reader = StreamIterator<List<int>>(response);
      iterator = reader;
      Future<String> body() async {
        final buffer = BytesBuilder(copy: false);
        var size = 0;
        while (await reader.moveNext()) {
          final chunk = reader.current;
          remaining();
          size += chunk.length;
          if (size > maxBytes) {
            throw const _FetchFailure(SubscriptionFetchCode.tooLarge);
          }
          buffer.add(chunk);
        }
        remaining();
        return utf8.decode(buffer.takeBytes(), allowMalformed: false);
      }

      final payload = await bounded(body());
      remaining();
      return SubscriptionFetchReply(SubscriptionFetchCode.ok, payload: payload);
    } on LinkException {
      return const SubscriptionFetchReply(
        SubscriptionFetchCode.malformedSource,
      );
    } on _FetchFailure catch (error) {
      return SubscriptionFetchReply(
        _closed ? SubscriptionFetchCode.cancelled : error.code,
      );
    } on TimeoutException {
      return const SubscriptionFetchReply(SubscriptionFetchCode.timeout);
    } on TlsException {
      return const SubscriptionFetchReply(SubscriptionFetchCode.tls);
    } on FormatException {
      return const SubscriptionFetchReply(SubscriptionFetchCode.malformedBody);
    } catch (_) {
      return SubscriptionFetchReply(
        _closed
            ? SubscriptionFetchCode.cancelled
            : SubscriptionFetchCode.network,
      );
    } finally {
      finished = true;
      _requests.remove(cancelled);
      if (iterator != null) unawaited(iterator.cancel().catchError((_) {}));
      try {
        client?.close(force: true);
      } catch (_) {}
      _clients.remove(client);
    }
  }
}
