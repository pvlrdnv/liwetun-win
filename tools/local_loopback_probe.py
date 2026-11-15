"""Windows CLI -> local SOCKS -> loopback endpoint -> private local WSL origin.

Explicit developer test only: no real profiles, TUN, routes, DNS, driver/service
installation, system certificate store or external test destinations. Requires
WSL Windows interop, openssl and the two pinned upstream archives in /tmp.
Raw core output is discarded, never written to a file or support journal.
"""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
from pathlib import Path
import hashlib
import ipaddress
import json
import re
import socket
import shutil
import subprocess
import tempfile
import tarfile
import threading
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
BIN = Path('/tmp/liwetun-loopback-bin')
MARKER = b'LIWETUN_LOOPBACK_ORIGIN_261115'
PINNED = {
    '/tmp/liwetun-endpoint-v1.1.0.tar.gz': '91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7',
    '/tmp/liwetun-client-v1.1.12-windows.zip': '56fb620f4cd30abbc1b4586c6645b56d90c8c0e977ba53d95fb0f542acb7cb1f',
}


def winpath(path):
    return subprocess.check_output(['wslpath', '-w', str(path)], text=True).strip()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def traffic_totals(port):
    # Aggregate data-plane counters only; per-user metrics are disabled.
    for attempt in range(10):
        try:
            connection = HTTPConnection('127.0.0.1', port, timeout=2)
            try:
                connection.request('GET', '/metrics', headers={'Connection': 'keep-alive', 'Content-Length': '0'})
                response = connection.getresponse()
                if response.status != 200:
                    raise OSError('metrics_unavailable')
                text = response.read(262144).decode('ascii', errors='replace')
            finally:
                connection.close()
            break
        except OSError:
            if attempt == 9:
                raise
            time.sleep(.1)
    totals = {protocol: {'inbound': 0, 'outbound': 0} for protocol in ['http1', 'http2', 'http3']}
    for direction, label, count in re.findall(
        r'^(inbound|outbound)_traffic_bytes\{protocol_type="([A-Za-z0-9]+)"\} ([0-9]+)$', text, re.M,
    ):
        actual = {'HTTP1': 'http1', 'HTTP2': 'http2', 'HTTP3': 'http3', 'QUIC': 'http3'}.get(label.upper())
        if actual is not None:
            totals[actual][direction] += int(count)
    return totals


@contextmanager
def endpoint(directory, port, address):
    process = subprocess.Popen([
        str(BIN / 'endpoint/trusttunnel_endpoint'),
        str(directory / 'vpn.toml'), str(directory / 'hosts.toml'), '--jobs', '2',
    ], cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError('endpoint_exited')
            try:
                with socket.create_connection((address, port), timeout=.1):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('endpoint_not_ready')
        yield
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def windows_probe(port, origin_port, origin_host, timeout=7):
    return subprocess.run([
        'curl.exe', '--silent', '--max-time', str(timeout),
        '--noproxy', 'no-bypass.example.invalid',
        '--socks5-hostname', f'127.0.0.1:{port}',
        f'http://{origin_host}:{origin_port}/probe',
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout + 3,
       start_new_session=True)


def stop_owned_client(process, process_name):
    # Task-generated random image name, never generic core/process names.
    subprocess.run([
        'powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
        f'Get-Process -Name {process_name} -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue',
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
       start_new_session=True)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def verify_pinned_inputs():
    for path, digest in PINNED.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise RuntimeError('archive_digest_mismatch')
    with zipfile.ZipFile('/tmp/liwetun-client-v1.1.12-windows.zip') as archive:
        for name in ['trusttunnel_client.exe', 'wintun.dll']:
            if (BIN / 'client' / name).read_bytes() != archive.read(name):
                raise RuntimeError('extracted_windows_binary_mismatch')
    with tarfile.open('/tmp/liwetun-endpoint-v1.1.0.tar.gz') as archive:
        binary = archive.extractfile('trusttunnel-v1.1.0-linux-x86_64/trusttunnel_endpoint')
        if binary is None or binary.read() != (BIN / 'endpoint/trusttunnel_endpoint').read_bytes():
            raise RuntimeError('extracted_endpoint_binary_mismatch')


def main():
    verify_pinned_inputs()

    class Origin(BaseHTTPRequestHandler):
        hits = 0

        def do_GET(self):
            if self.path != '/probe':
                self.send_error(404)
                return
            type(self).hits += 1
            self.send_response(200)
            self.send_header('Content-Length', str(len(MARKER)))
            self.end_headers()
            self.wfile.write(MARKER)

        def log_message(self, *_args):
            pass

    # A loopback target is forcibly bypassed by the official core. Pick only an
    # already-existing private WSL interface; UDP connect performs a route lookup
    # without sending packets. No address or route is added/modified.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_lookup:
        route_lookup.connect(('192.0.2.1', 1))
        origin_host = route_lookup.getsockname()[0]
    address = ipaddress.ip_address(origin_host)
    if not address.is_private or address.is_loopback:
        raise RuntimeError('private_local_origin_required')
    origin = ThreadingHTTPServer((origin_host, 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix='liwetun-loopback-') as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            # Unique executable identity makes timeout cleanup unambiguous;
            # never touch a user's pre-existing trusttunnel_client process.
            process_name = 'liwetun_probe_' + uuid.uuid4().hex[:12]
            client_exe = directory / (process_name + '.exe')
            shutil.copyfile(BIN / 'client/trusttunnel_client.exe', client_exe)
            client_exe.chmod(0o700)
            shutil.copyfile(BIN / 'client/wintun.dll', directory / 'wintun.dll')
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                '-keyout', str(directory / 'key.pem'), '-out', str(directory / 'cert.pem'),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (directory / 'key.pem').chmod(0o600)
            certificate = (directory / 'cert.pem').read_text()
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                '-keyout', str(directory / 'wrong-key.pem'), '-out', str(directory / 'wrong-cert.pem'),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (directory / 'wrong-key.pem').chmod(0o600)
            wrong_certificate = (directory / 'wrong-cert.pem').read_text()
            port = free_port()
            metrics_port = free_port()
            (directory / 'credentials.toml').write_text('[[client]]\nusername="synthetic-user"\npassword="synthetic-password"\n')
            (directory / 'vpn.toml').write_text(
                f'listen_address="127.0.0.1:{port}"\ncredentials_file="credentials.toml"\n'
                'ipv6_available=false\nallow_private_network_connections=true\n'
                # Upstream metrics codec reads the HTTP/1 upload buffer settings.
                '[listen_protocols.http1]\n[listen_protocols.http2]\n[listen_protocols.quic]\n'
                f'[metrics]\naddress="127.0.0.1:{metrics_port}"\nper_client_metrics=false\n')
            (directory / 'hosts.toml').write_text(
                '[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            with endpoint(directory, port, '127.0.0.1'):
                for protocol, wrong_password, wrong_name in [
                    ('http2', False, False), ('http3', False, False),
                    ('http2', True, False), ('http2', False, True),
                ]:
                    proxy_port = free_port()
                    password = 'wrong-synthetic' if wrong_password else 'synthetic-password'
                    hostname = 'localhost'
                    trusted_certificate = wrong_certificate if wrong_name else certificate
                    config = directory / 'client.toml'
                    config.write_text(
                        'loglevel="error"\nvpn_mode="general"\nkillswitch_enabled=false\n'
                        f'[endpoint]\nhostname="{hostname}"\naddresses=["127.0.0.1:{port}"]\n'
                        f'username="synthetic-user"\npassword="{password}"\nhas_ipv6=false\n'
                        f'skip_verification=false\ncertificate="""{trusted_certificate}"""\n'
                        f'upstream_protocol="{protocol}"\ndns_upstreams=["127.0.0.1:9"]\n'
                        f'[listener.socks]\naddress="127.0.0.1:{proxy_port}"\n')
                    before = Origin.hits
                    traffic_before = traffic_totals(metrics_port)
                    process = subprocess.Popen([
                        str(client_exe), '--config', winpath(config),
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       start_new_session=True)
                    delivered = False
                    core_exit = None
                    try:
                        time.sleep(1)
                        core_exit = process.poll()
                        if core_exit is None:
                            probe = windows_probe(proxy_port, origin.server_port, origin_host)
                            delivered = probe.returncode == 0 and probe.stdout == MARKER
                    finally:
                        stop_owned_client(process, process_name)
                    negative = windows_probe(proxy_port, origin.server_port, origin_host, timeout=2)
                    traffic_after = traffic_totals(metrics_port)
                    all_deltas = {p: {key: traffic_after[p][key] - traffic_before[p][key]
                                      for key in traffic_before[p]} for p in traffic_before}
                    delta = all_deltas[protocol]
                    expected = not wrong_password and not wrong_name
                    case = {
                        'protocol': protocol,
                        'case': 'bad_auth' if wrong_password else 'bad_certificate' if wrong_name else 'valid',
                        'delivered': delivered, 'expected_delivery': expected,
                        'origin_hits_delta': Origin.hits - before,
                        'client_stopped': process.poll() is not None,
                        'closed_proxy_failed': negative.returncode != 0,
                        'core_exit': core_exit,
                        'endpoint_data_bytes_delta': delta,
                        'observed_transports': [p for p, counts in all_deltas.items() if any(counts.values())],
                    }
                    case['passed'] = (
                        delivered == expected and case['client_stopped']
                        and case['closed_proxy_failed']
                        and ((Origin.hits > before) if expected else (Origin.hits == before))
                        and (all(value > 0 for value in delta.values()) if expected else all(value == 0 for value in delta.values()))
                    )
                    if not expected:
                        case['passed'] = case['passed'] and any(
                            c['case'] == 'valid' and c['protocol'] == 'http2' and c['passed']
                            for c in results
                        )
                    case['qualification'] = (
                        'verified' if case['passed'] else
                        'fallback_only' if delivered and case['observed_transports'] else
                        'not_verified'
                    )
                    results.append(case)
                    print(json.dumps(case), flush=True)
                    if core_exit is not None and expected:
                        break
    finally:
        origin.shutdown()
        origin.server_close()
    evidence = {'endpoint': '1.1.0', 'windows_cli': '1.1.12', 'tun': False,
                'origin_scope': 'existing_private_wsl_interface',
                'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'archives': {Path(path).name: digest for path, digest in PINNED.items()},
                'service_installed': False, 'production_contacted': False, 'cases': results}
    target = ROOT / 'build/loopback-evidence.json'
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(evidence, indent=2) + '\n')
    if len(results) != 4 or not all(case['passed'] for case in results):
        raise SystemExit(2)  # Partial qualification is distinct from a harness exception.


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'failure_type': type(error).__name__, 'raw_details': 'suppressed'}))
        raise SystemExit(1) from None
