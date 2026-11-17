"""Disposable Windows TLS/HTTP control; private fixture keys never become evidence."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
HOST = 'health.liwetun.invalid'
HEADERS = (b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nContent-Type: application/octet-stream\r\n'
           b'Cache-Control: no-store\r\nConnection: close\r\n\r\n')


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def generate(directory):
    directory.mkdir(parents=True, exist_ok=False)
    basic = directory / 'req.cnf'
    basic.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
    for name, host in [('valid', HOST), ('wrong-name', 'other.liwetun.invalid'), ('untrusted', HOST)]:
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '2',
                '-config', basic, '-keyout', directory / (name + '.key'), '-out', directory / (name + '.pem'),
                '-subj', '/CN=' + host, '-addext', 'subjectAltName=DNS:' + host,
                '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'extendedKeyUsage=serverAuth',
                '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign')
    # A genuine old validity interval, not a client clock/validation override.
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', basic,
            '-keyout', directory / 'expired.key', '-out', directory / 'expired.csr', '-subj', '/CN=' + HOST)
    (directory / 'index').write_text('')
    (directory / 'serial').write_text('1000\n')
    (directory / 'newcerts').mkdir()
    config = directory / 'ca.cnf'
    base = directory.resolve().as_posix()
    if any(c in base for c in ['$', '"', '\n', '\r']):
        raise RuntimeError('unsupported_fixture_path')
    config.write_text(f'''[ca]
default_ca=local
[local]
dir="{base}"
database=$dir/index
serial=$dir/serial
new_certs_dir=$dir/newcerts
certificate=$dir/valid.pem
private_key=$dir/expired.key
default_md=sha256
policy=names
x509_extensions=server
[names]
commonName=supplied
[server]
basicConstraints=critical,CA:TRUE
subjectAltName=DNS:{HOST}
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign
''')
    openssl('ca', '-batch', '-selfsign', '-config', config, '-in', directory / 'expired.csr',
            '-keyfile', directory / 'expired.key', '-startdate', '20000101000000Z',
            '-enddate', '20000102000000Z', '-out', directory / 'expired.pem', '-notext')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', basic,
            '-keyout', directory / 'missing-crl.key', '-out', directory / 'missing-crl.csr', '-subj', '/CN=' + HOST)
    leaf = directory / 'leaf.cnf'
    leaf.write_text(f'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{HOST}\n'
                    'extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n')
    openssl('x509', '-req', '-in', directory / 'missing-crl.csr', '-CA', directory / 'valid.pem',
            '-CAkey', directory / 'valid.key', '-set_serial', '17', '-days', '2', '-sha256',
            '-extfile', leaf, '-out', directory / 'missing-crl.pem')
    openssl('verify', '-purpose', 'sslserver', '-CAfile', directory / 'valid.pem', directory / 'missing-crl.pem')
    # A separate CA makes cached-revocation success/refusal independent from the
    # missing-information control above. No URL is embedded or contacted.
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '2',
            '-config', basic, '-keyout', directory / 'crl-ca.key', '-out', directory / 'crl-ca.pem',
            '-subj', '/CN=LiWeTun disposable revocation CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    (directory / 'crl-index').write_text('')
    (directory / 'crl-serial').write_text('2000\n')
    (directory / 'crl-number').write_text('1000\n')
    crl_config = directory / 'crl-ca.cnf'
    crl_config.write_text(f'''[ca]
default_ca=local
[local]
dir="{base}"
database=$dir/crl-index
serial=$dir/crl-serial
crlnumber=$dir/crl-number
new_certs_dir=$dir/newcerts
certificate=$dir/crl-ca.pem
private_key=$dir/crl-ca.key
default_md=sha256
default_days=2
default_crl_days=2
unique_subject=no
policy=names
x509_extensions=server
crl_extensions=crl
[names]
commonName=supplied
[server]
basicConstraints=critical,CA:FALSE
subjectAltName=DNS:{HOST}
authorityKeyIdentifier=keyid:always
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature,keyEncipherment
[crl]
authorityKeyIdentifier=keyid:always
''')
    for name in ['crl-good', 'crl-revoked']:
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', basic,
                '-keyout', directory / (name + '.key'), '-out', directory / (name + '.csr'), '-subj', '/CN=' + HOST)
        openssl('ca', '-batch', '-config', crl_config, '-in', directory / (name + '.csr'),
                '-out', directory / (name + '.pem'), '-notext')
    openssl('ca', '-config', crl_config, '-revoke', directory / 'crl-revoked.pem', '-crl_reason', 'keyCompromise')
    openssl('ca', '-config', crl_config, '-gencrl', '-out', directory / 'fixture.crl.pem')
    openssl('crl', '-in', directory / 'fixture.crl.pem', '-outform', 'DER', '-out', directory / 'fixture.crl.der')
    openssl('verify', '-purpose', 'sslserver', '-crl_check', '-CAfile', directory / 'crl-ca.pem',
            '-CRLfile', directory / 'fixture.crl.pem', directory / 'crl-good.pem')
    for name in ['valid', 'wrong-name', 'untrusted', 'expired', 'crl-ca']:
        openssl('x509', '-in', directory / (name + '.pem'), '-outform', 'DER', '-out', directory / (name + '.der'))


class FixtureRoots:
    """Own only newly added fixture contexts, with exact-hash absence check."""
    def __init__(self):
        if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise RuntimeError('disposable_windows_required')
        self.api = ctypes.WinDLL('crypt32', use_last_error=True)
        self.api.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.api.CertOpenStore.restype = ctypes.c_void_p
        self.api.CertAddEncodedCertificateToStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                                            wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        self.api.CertAddEncodedCertificateToStore.restype = wintypes.BOOL
        self.api.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
        self.api.CertDeleteCertificateFromStore.restype = wintypes.BOOL
        self.api.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
        self.api.CertFreeCertificateContext.restype = wintypes.BOOL
        self.api.CertFindCertificateInStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                      wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
        self.api.CertFindCertificateInStore.restype = ctypes.c_void_p
        self.api.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self.api.CertCloseStore.restype = wintypes.BOOL
        self.contexts = []
        self.hashes = []
        self.crl_context = None
        name = ctypes.c_wchar_p('ROOT')
        self.store = self.api.CertOpenStore(ctypes.c_void_p(10), 0, None, 0x00020000 | 0x00004000, name)
        if not self.store:
            raise RuntimeError('fixture_root_store_unavailable')
        self.api.CertAddEncodedCRLToStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                                   wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        self.api.CertAddEncodedCRLToStore.restype = wintypes.BOOL
        self.api.CertDeleteCRLFromStore.argtypes = [ctypes.c_void_p]
        self.api.CertDeleteCRLFromStore.restype = wintypes.BOOL
        self.ca_store = None

    def contains(self, digest):
        class Blob(ctypes.Structure):
            _fields_ = [('size', wintypes.DWORD), ('data', ctypes.c_void_p)]
        data = ctypes.create_string_buffer(digest)
        blob = Blob(len(digest), ctypes.cast(data, ctypes.c_void_p))
        found = self.api.CertFindCertificateInStore(self.store, 1, 0, 0x00010000, ctypes.byref(blob), None)
        if found:
            self.api.CertFreeCertificateContext(found)
        return bool(found)

    def add(self, path):
        data = path.read_bytes()
        digest = hashlib.sha1(data).digest() # Windows store locator only, not a signature/trust algorithm.
        if self.contains(digest):
            raise RuntimeError('preexisting_fixture_root')
        encoded = ctypes.create_string_buffer(data)
        context = ctypes.c_void_p()
        if not self.api.CertAddEncodedCertificateToStore(self.store, 1, encoded, len(data), 1, ctypes.byref(context)):
            raise RuntimeError('fixture_root_add_failed')
        self.contexts.append(context)
        self.hashes.append(digest)

    def add_crl(self, path):
        name = ctypes.c_wchar_p('CA')
        self.ca_store = self.api.CertOpenStore(ctypes.c_void_p(10), 0, None, 0x00020000 | 0x00004000, name)
        if not self.ca_store:
            raise RuntimeError('fixture_crl_store_unavailable')
        data = path.read_bytes()
        encoded = ctypes.create_string_buffer(data)
        context = ctypes.c_void_p()
        if not self.api.CertAddEncodedCRLToStore(self.ca_store, 1, encoded, len(data), 1, ctypes.byref(context)):
            raise RuntimeError('fixture_crl_add_failed')
        self.crl_context = context

    def close(self):
        passed = True
        if self.crl_context is not None:
            passed = bool(self.api.CertDeleteCRLFromStore(self.crl_context)) and passed
            self.crl_context = None
        if self.ca_store is not None:
            passed = bool(self.api.CertCloseStore(self.ca_store, 0)) and passed
            self.ca_store = None
        for context in reversed(self.contexts):
            passed = bool(self.api.CertDeleteCertificateFromStore(context)) and passed
        self.contexts.clear()
        for digest in self.hashes:
            passed = not self.contains(digest) and passed
        passed = bool(self.api.CertCloseStore(self.store, 0)) and passed
        self.store = None
        return passed


class Server:
    def __init__(self, directory, certificate, mode):
        self.mode = mode
        self.stop = threading.Event()
        self.counts = dict(handshake_complete=0, handshake_failed=0, requests=0, body_bytes=0,
                           replies=0, client_certificate_seen=False, peer_closed=False)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(directory / (certificate + '.pem'), directory / (certificate + '.key'))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(1)
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        raw = None
        try:
            while not self.stop.is_set():
                try:
                    raw, _ = self.socket.accept()
                    break
                except socket.timeout:
                    continue
            if raw is None:
                return
            raw.settimeout(5)
            with self.context.wrap_socket(raw, server_side=True) as client:
                self.counts['handshake_complete'] = 1
                self.counts['client_certificate_seen'] = bool(client.getpeercert())
                client.settimeout(.2)
                packet = b''
                deadline = time.monotonic() + 6
                while not self.stop.is_set() and time.monotonic() < deadline:
                    try:
                        part = client.recv(1024 - len(packet))
                    except socket.timeout:
                        continue
                    if not part:
                        self.counts['peer_closed'] = True
                        return
                    packet += part
                    boundary = packet.find(b'\r\n\r\n')
                    if boundary >= 0 and len(packet) >= boundary + 12:
                        break
                    if len(packet) == 1024:
                        return
                boundary = packet.find(b'\r\n\r\n')
                expected = (b'POST /liwetun/health/v1 HTTP/1.1\r\nHost: health.liwetun.invalid\r\n'
                            b'Content-Type: application/octet-stream\r\nContent-Length: 8\r\n'
                            b'Cache-Control: no-store\r\nConnection: close\r\n\r\n')
                if boundary < 0 or packet[:boundary + 4] != expected or len(packet) != boundary + 12:
                    return
                nonce = packet[boundary + 4:]
                if nonce == bytes(8):
                    return
                self.counts['requests'] = 1
                self.counts['body_bytes'] = 8
                if self.mode == 'stall':
                    while not self.stop.wait(.1) and time.monotonic() < deadline:
                        pass
                    return
                reply = HEADERS + nonce
                if self.mode == 'wrong-nonce':
                    reply = HEADERS + bytes(8)
                elif self.mode == 'redirect':
                    reply = HEADERS.replace(b'200 OK', b'302 Found') + nonce
                elif self.mode == 'oversized':
                    reply = b'HTTP/1.1 200 OK\r\nX: ' + b'a' * 5000 + b'\r\n\r\n'
                if self.mode == 'fragmented':
                    for byte in reply:
                        client.sendall(bytes([byte]))
                else:
                    client.sendall(reply)
                self.counts['replies'] = 1
                while not self.stop.is_set() and time.monotonic() < deadline:
                    try:
                        if not client.recv(1):
                            self.counts['peer_closed'] = True
                            break
                    except socket.timeout:
                        continue
        except (OSError, ssl.SSLError):
            if not self.counts['handshake_complete']:
                self.counts['handshake_failed'] = 1
        finally:
            if raw is not None:
                raw.close()

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=6)
        return not self.thread.is_alive()


def validate_client(value):
    expected = {'tls_result', 'http_result', 'handshake_verified', 'request_sent', 'response_verified',
                'synthetic_nonce', 'sdk_path_qualified', 'release_ready'}
    if not isinstance(value, dict) or set(value) != expected:
        raise RuntimeError('invalid_tls_client_report')
    if type(value['tls_result']) is not int or not 0 <= value['tls_result'] <= 15:
        raise RuntimeError('invalid_tls_client_report')
    if value['http_result'] is not None and (type(value['http_result']) is not int or not 0 <= value['http_result'] <= 7):
        raise RuntimeError('invalid_tls_client_report')
    for key in expected - {'tls_result', 'http_result'}:
        if type(value[key]) is not bool:
            raise RuntimeError('invalid_tls_client_report')
    if not value['synthetic_nonce'] or value['sdk_path_qualified'] or value['release_ready']:
        raise RuntimeError('invalid_tls_client_report')
    if value['response_verified'] and not (value['tls_result'] == 0 and value['http_result'] == 1
                                          and value['handshake_verified'] and value['request_sent']):
        raise RuntimeError('invalid_tls_client_report')
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('disposable_windows_required')
    client = args.client.resolve()
    if client != (ROOT / 'build/health-tls-probe.exe').resolve():
        raise RuntimeError('unexpected_fixture_client')
    directory = ROOT / 'build/health-tls-fixture'
    output = ROOT / 'build/health-tls-evidence/qualification.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(schema_version=1, passed=False, cases=[], fixture_roots_removed=False,
                  scope='windows_ci_loopback_schannel_tls12_no_sdk_no_tun',
                  sdk_path_qualified=False, dns_health_qualified=False, release_ready=False)
    roots = None
    stage = 'generate_certificates'
    try:
        generate(directory)
        stage = 'fixture_roots'
        roots = FixtureRoots()
        for certificate in ['valid', 'wrong-name', 'expired', 'crl-ca']:
            roots.add(directory / (certificate + '.der'))
        roots.add_crl(directory / 'fixture.crl.der')
        cases = [('valid', 'valid', 'echo', None), ('fragmented', 'valid', 'fragmented', None),
                 ('wrong_nonce', 'valid', 'wrong-nonce', None), ('redirect', 'valid', 'redirect', None),
                 ('oversized', 'valid', 'oversized', None), ('wrong_name', 'wrong-name', 'echo', None),
                 ('untrusted', 'untrusted', 'echo', None), ('expired', 'expired', 'echo', None),
                 ('missing_revocation', 'missing-crl', 'echo', None),
                 ('cached_revocation_good', 'crl-good', 'echo', None),
                 ('revoked', 'crl-revoked', 'echo', None),
                 ('deadline', 'valid', 'stall', None), ('cancel', 'valid', 'stall', 'cancel-read')]
        for name, certificate, mode, extra in cases:
            stage = name
            server = Server(directory, certificate, mode)
            try:
                command = [str(client), str(server.port)] + ([extra] if extra else [])
                started = time.monotonic()
                process = subprocess.run(command, capture_output=True, timeout=15, text=True)
                elapsed = int((time.monotonic() - started) * 1000)
                if process.returncode or len(process.stdout) > 2048:
                    raise RuntimeError('tls_client_failed')
                value = validate_client(json.loads(process.stdout))
            finally:
                ended = server.close()
            counts = dict(server.counts)
            case = dict(case=name, client=value, receiver=counts, elapsed_ms=elapsed, receiver_stopped=ended)
            report['cases'].append(case)
            if not ended or counts['client_certificate_seen']:
                raise RuntimeError('tls_fixture_not_clean')
            if name in ['valid', 'fragmented', 'cached_revocation_good']:
                passed = value['response_verified'] and counts['requests'] == 1 and counts['replies'] == 1
            elif name in ['wrong_nonce', 'redirect', 'oversized']:
                expected = {'wrong_nonce': 2, 'redirect': 3, 'oversized': 6}[name]
                passed = (value['tls_result'] == 0 and value['handshake_verified'] and value['request_sent']
                          and value['http_result'] == expected and not value['response_verified'] and counts['requests'] == 1)
            elif name in ['deadline', 'cancel']:
                expected = 2 if name == 'deadline' else 1
                passed = (value['tls_result'] == expected and value['request_sent'] and not value['response_verified']
                          and counts['requests'] == 1 and counts['replies'] == 0 and elapsed < 6500)
            else:
                expected = {'wrong_name': 7, 'untrusted': 8, 'expired': 9, 'missing_revocation': 10, 'revoked': 10}[name]
                passed = (value['tls_result'] == expected and not value['handshake_verified']
                          and value['http_result'] is None and not value['request_sent']
                          and not value['response_verified'] and counts['requests'] == counts['body_bytes'] == 0)
            case['passed'] = passed
            if not passed:
                raise RuntimeError('tls_case_not_qualified')
        report['passed'] = True
    except Exception as error:
        report['failed_stage'] = stage
        allowed = {'tls_client_failed', 'tls_fixture_not_clean', 'tls_case_not_qualified', 'invalid_tls_client_report',
                   'fixture_root_store_unavailable', 'preexisting_fixture_root', 'fixture_root_add_failed',
                   'fixture_crl_store_unavailable', 'fixture_crl_add_failed', 'unsupported_fixture_path'}
        reason = error.args[0] if error.args else None
        report['failure_reason'] = reason if isinstance(reason, str) and reason in allowed else 'fixture_failure'
    finally:
        report['fixture_roots_removed'] = roots.close() if roots is not None else False
        report['passed'] = report['passed'] and report['fixture_roots_removed']
        output.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['passed'] else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit('health_tls_fixture_failed') from None
