"""Fixed synthetic HTTPS receiver and closed service-result validation for CI."""
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/fixtures'))
from health_tls import HEADERS
from owned_probe_fixture import validate_report

MODES = ('https', 'https-wrong-nonce', 'https-untrusted', 'https-deadline', 'https-cancel',
         'https-migration', 'https-epoch-change')
REQUEST_HEADERS = (b'POST /liwetun/health/v1 HTTP/1.1\r\nHost: health.liwetun.invalid\r\n'
                   b'Content-Type: application/octet-stream\r\nContent-Length: 8\r\n'
                   b'Cache-Control: no-store\r\nConnection: close\r\n\r\n')


class OwnedHttpsSink:
    def __init__(self, directory, mode, port=38556):
        if mode not in MODES:
            raise ValueError('invalid_owned_https_mode')
        self.mode = mode
        certificate = 'untrusted' if mode == 'https-untrusted' else 'crl-good'
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(directory / (certificate + '.pem'), directory / (certificate + '.key'))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', port))
        self.socket.listen(4)
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = dict(accepted=0, empty_controls=0, handshake_complete=0, handshake_failed=0,
                           valid_requests=0, request_bytes=0, replies_sent=0, reply_bytes=0,
                           rejected_frames=0, waiting_for_owner_close=0, owner_closed=0,
                           owner_reset=0, invalid_replies=0, client_certificate_seen=False)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def count(self, key, value=1):
        with self.lock:
            self.counts[key] += value

    def stats(self):
        with self.lock:
            return dict(self.counts)

    def serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.count('accepted')
            with raw:
                raw.settimeout(2)
                try:
                    if not raw.recv(1, socket.MSG_PEEK):
                        self.count('empty_controls')
                        continue
                    try:
                        client = self.context.wrap_socket(raw, server_side=True)
                    except (ssl.SSLError, OSError):
                        self.count('handshake_failed')
                        continue
                    with client:
                        self.count('handshake_complete')
                        if client.getpeercert():
                            with self.lock:
                                self.counts['client_certificate_seen'] = True
                        client.settimeout(.1)
                        packet = b''
                        deadline = time.monotonic() + 6
                        while len(packet) < len(REQUEST_HEADERS) + 8 and not self.stop.is_set() and time.monotonic() < deadline:
                            try:
                                part = client.recv(len(REQUEST_HEADERS) + 8 - len(packet))
                            except socket.timeout:
                                continue
                            if not part:
                                break
                            packet += part
                        self.count('request_bytes', len(packet))
                        if (len(packet) != len(REQUEST_HEADERS) + 8 or not packet.startswith(REQUEST_HEADERS)
                                or packet[-8:] == bytes(8)):
                            self.count('rejected_frames')
                            continue
                        self.count('valid_requests')
                        if self.mode not in ['https-deadline', 'https-cancel', 'https-epoch-change']:
                            nonce = packet[-8:]
                            if self.mode == 'https-wrong-nonce':
                                nonce = bytes(8)
                                self.count('invalid_replies')
                            response = HEADERS + nonce
                            client.sendall(response)
                            self.count('replies_sent')
                            self.count('reply_bytes', len(response))
                        self.count('waiting_for_owner_close')
                        try:
                            while not self.stop.is_set() and time.monotonic() < deadline:
                                try:
                                    extra = client.recv(1)
                                except socket.timeout:
                                    continue
                                if not extra:
                                    self.count('owner_closed')
                                else:
                                    self.count('rejected_frames')
                                break
                        finally:
                            self.count('waiting_for_owner_close', -1)
                except ConnectionResetError:
                    self.count('owner_reset')
                except (ssl.SSLError, OSError):
                    pass

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=3)
        return not self.thread.is_alive()


def read_receipt(path):
    with path.open('rb') as source:
        raw = source.read(4097)
    if len(raw) > 4096:
        raise ValueError('invalid_owned_https_report')
    if not raw.endswith(b'\n'):
        return None  # CREATE_NEW publication may still be writing; retry boundedly.
    return json.loads(raw)


def validate_https_report(value, path):
    validate_report(path)
    booleans = {'handshake_verified', 'request_sent', 'response_verified', 'qualified',
                'proves_dns', 'proves_internet', 'release_ready'}
    if not isinstance(value, dict) or set(value) != booleans | {'schema_version', 'tls_result', 'http_result', 'wire_tx', 'wire_rx'}:
        raise ValueError('invalid_owned_https_report')
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['tls_result']) is not int or not 0 <= value['tls_result'] <= 15
            or any(type(value[k]) is not bool for k in booleans)
            or any(type(value[k]) is not int or not 0 <= value[k] <= 262144 for k in ['wire_tx', 'wire_rx'])
            or (value['http_result'] is not None and (type(value['http_result']) is not int or not 0 <= value['http_result'] <= 7))
            or any(value[k] for k in ['proves_dns', 'proves_internet', 'release_ready'])):
        raise ValueError('invalid_owned_https_report')
    if value['response_verified'] != path['echo_verified'] or value['qualified'] != path['qualified']:
        raise ValueError('invalid_owned_https_report')
    if value['response_verified'] and not (value['handshake_verified'] and value['request_sent']
                                          and value['tls_result'] == 0 and value['http_result'] == 1):
        raise ValueError('invalid_owned_https_report')
    if value['qualified'] and not (value['response_verified'] and value['wire_tx'] > 0 and value['wire_rx'] > 0
                                    and path['tx_bytes'] >= value['wire_tx'] and path['rx_bytes'] >= value['wire_rx']):
        raise ValueError('invalid_owned_https_report')
    return value
