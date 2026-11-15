import 'dart:convert';

import 'package:crypto/crypto.dart';

enum Protocol { trusttunnel, hysteria2, vless }

enum ImportKind { profile, subscription }

/// Never interpolate this object in UI, exceptions or diagnostic events.
final class SecretLink {
  const SecretLink(this.value);
  final String value;

  @override
  String toString() => '[private link]';
}

enum ImportFailure { malformed, unsupported, insecure, tooLong }

final class LinkException implements Exception {
  const LinkException(this.reason);
  final ImportFailure reason;

  @override
  String toString() => 'LinkException(${reason.name})';
}

final class ImportedLink {
  const ImportedLink({
    required this.kind,
    required this.secret,
    required this.localId,
    this.protocol,
  });

  final ImportKind kind;
  final SecretLink secret;
  final Protocol? protocol;
  // Local-only deduplication digest. Never written to diagnostic output.
  final String localId;
}

ImportedLink parseLink(String input) {
  final value = input.trim();
  if (value.length > 8192) {
    throw const LinkException(ImportFailure.tooLong);
  }
  if (value.isEmpty || RegExp(r'[\x00-\x20\x7f]').hasMatch(value)) {
    throw const LinkException(ImportFailure.malformed);
  }
  try {
    return _parse(value);
  } on LinkException {
    rethrow;
  } catch (_) {
    // Uri/decoder exceptions may contain the original credentials.
    throw const LinkException(ImportFailure.malformed);
  }
}

ImportedLink _parse(String value) {
  final uri = Uri.parse(value);
  if (uri.scheme == 'http') {
    throw const LinkException(ImportFailure.insecure);
  }
  if (uri.scheme == 'https' && uri.host == 'trusttunnel.org') {
    if (uri.userInfo.isNotEmpty ||
        uri.port != 443 ||
        (uri.path.isNotEmpty && uri.path != '/') ||
        uri.hasQuery ||
        !uri.fragment.startsWith('tt=')) {
      throw const LinkException(ImportFailure.malformed);
    }
    return _trust('tt://?${uri.fragment.substring(3)}');
  }
  if (uri.scheme == 'tt') return _trust(value);
  if (uri.scheme == 'https') {
    if (uri.host.isEmpty || uri.userInfo.isNotEmpty || uri.hasFragment) {
      throw const LinkException(ImportFailure.malformed);
    }
    return _result(value, ImportKind.subscription);
  }
  final protocol = switch (uri.scheme) {
    'vless' => Protocol.vless,
    'hy2' || 'hysteria2' => Protocol.hysteria2,
    _ => throw const LinkException(ImportFailure.unsupported),
  };
  if (uri.host.isEmpty ||
      uri.userInfo.isEmpty ||
      !uri.hasPort ||
      uri.port < 1 ||
      uri.port > 65535 ||
      (uri.path.isNotEmpty && uri.path != '/')) {
    throw const LinkException(ImportFailure.malformed);
  }
  // Duplicate parameters can cause different interpretations by UI/core.
  if (uri.queryParametersAll.values.any((values) => values.length != 1)) {
    throw const LinkException(ImportFailure.malformed);
  }
  final query = uri.queryParameters;
  for (final name in ['insecure', 'allowInsecure', 'skip_cert_verify']) {
    if (query.containsKey(name) &&
        !['0', 'false'].contains(query[name]!.toLowerCase())) {
      throw const LinkException(ImportFailure.insecure);
    }
  }
  if (protocol == Protocol.vless) {
    if (!RegExp(
      r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
    ).hasMatch(uri.userInfo)) {
      throw const LinkException(ImportFailure.malformed);
    }
    if (!['tls', 'reality'].contains(query['security'])) {
      throw const LinkException(ImportFailure.insecure);
    }
  }
  return _result(value, ImportKind.profile, protocol);
}

ImportedLink _trust(String value) {
  // TT is an opaque SDK binary format, not base64 JSON. Structural validation
  // does not claim SDK compatibility or TLS/certificate validation.
  if (!value.startsWith('tt://?') ||
      !RegExp(r'^[A-Za-z0-9_-]{20,8186}$').hasMatch(value.substring(6))) {
    throw const LinkException(ImportFailure.malformed);
  }
  return _result(value, ImportKind.profile, Protocol.trusttunnel);
}

ImportedLink _result(String value, ImportKind kind, [Protocol? protocol]) =>
    ImportedLink(
      kind: kind,
      secret: SecretLink(value),
      protocol: protocol,
      localId: sha256.convert(utf8.encode(value)).toString(),
    );
