"""Disposable Windows CI only: real signed service -> Wintun -> real endpoint.

The endpoint runs in WSL1 on this runner. Bounded task-created host routes
prevent same-host endpoint egress looping. Every HTTPS/DNS probe
sets IP_UNICAST_IF to the TUN index; it cannot use ordinary direct routing.
The public HTTPS origin is example.com, with normal TLS verification. No owner
profiles, application health status or release package are produced here.
"""
from http.client import HTTPConnection
from pathlib import Path
import argparse
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
INIT_STAGE = 'arguments'
PROBE_ERROR = None
PHYSICAL_ROUTE = None


def ps(script):
    result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command',
                             "$ErrorActionPreference='Stop'; " + script],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('fixture_system_command_failed')
    return json.loads(result.stdout) if result.stdout.strip() else None


def snapshot():
    return ps("""
    $dns = @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily |
      Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    $routes = @(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop |
      Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
    @{dns=$dns;routes=$routes} | ConvertTo-Json -Depth 6 -Compress
    """)


def tun():
    return ps("""
    $adapter = @(Get-NetAdapter -IncludeHidden | Where-Object Name -eq 'LiWeTun')
    if ($adapter.Count -eq 0) { 'null'; exit }
    if ($adapter.Count -ne 1) { throw 'Ambiguous task adapter' }
    $index = $adapter[0].ifIndex
    $routes = @(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4 |
      Where-Object DestinationPrefix -eq '198.18.0.0/15')
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses
    $defaults = @(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4 |
      Where-Object DestinationPrefix -eq '0.0.0.0/0')
    @{index=$index;fixture_route=($routes.Count -eq 1);dns=@($dns);automatic_default=($defaults.Count -gt 0)} | ConvertTo-Json -Compress
    """)


def prepare_tun(info, origin):
    global PHYSICAL_ROUTE
    if not info['fixture_route'] or not info['dns']:
        raise RuntimeError('missing_tun_routes_or_dns')
    index = int(info['index'])
    # Windows can create an on-link default along with the adapter address.
    # Keep the fixture bounded even when that route is present.
    if info['automatic_default']:
        ps(f"Get-NetRoute -InterfaceIndex {index} -DestinationPrefix '0.0.0.0/0' | Remove-NetRoute -Confirm:$false | Out-Null")
    os.environ['LIWETUN_CI_ORIGIN'] = origin
    # Preserve ordinary endpoint egress. Create an exact task-owned physical
    # host route only when none exists; never alter/delete a pre-existing route.
    PHYSICAL_ROUTE = ps("""
    $prefix = $env:LIWETUN_CI_ORIGIN + '/32'
    $existing = @(Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue)
    if ($existing.Count) { @{created=$false} | ConvertTo-Json -Compress; exit }
    $physical = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 |
      Sort-Object RouteMetric | Select-Object -First 1
    if (!$physical) { throw 'Missing physical route' }
    New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $physical.InterfaceIndex -NextHop $physical.NextHop -RouteMetric 0 -PolicyStore ActiveStore | Out-Null
    @{created=$true;index=$physical.InterfaceIndex} | ConvertTo-Json -Compress
    """)
    ps(f"New-NetRoute -InterfaceIndex {index} -DestinationPrefix ($env:LIWETUN_CI_ORIGIN + '/32') -NextHop '0.0.0.0' -RouteMetric 5000 -PolicyStore ActiveStore | Out-Null")
    ps(f"if (@(Find-NetRoute -RemoteIPAddress $env:LIWETUN_CI_ORIGIN | Where-Object InterfaceIndex -eq {index}).Count) {{ throw 'Endpoint egress loop' }}")


def remove_physical_route():
    global PHYSICAL_ROUTE
    if PHYSICAL_ROUTE and PHYSICAL_ROUTE['created']:
        index = int(PHYSICAL_ROUTE['index'])
        ps(f"Remove-NetRoute -InterfaceIndex {index} -DestinationPrefix ($env:LIWETUN_CI_ORIGIN + '/32') -RouteMetric 0 -Confirm:$false | Out-Null")
    PHYSICAL_ROUTE = None


class Child:
    def __init__(self, args):
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, encoding='utf-8')
        self.lines = queue.Queue()
        def read():
            for line in self.process.stdout:
                self.lines.put(line.strip() if len(line) < 4096 else '')
            self.lines.put('')
        threading.Thread(target=read, daemon=True).start()

    def receive(self):
        try:
            value = self.lines.get(timeout=20)
        except queue.Empty:
            raise RuntimeError('fixture_child_timeout') from None
        if not value:
            raise RuntimeError('fixture_child_closed')
        return value

    def command(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        return json.loads(self.receive())

    def close(self, command=None):
        if self.process.poll() is None:
            if command:
                try:
                    self.process.stdin.write(command + '\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=8)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()


def totals():
    connection = HTTPConnection('127.0.0.1', 38444, timeout=3)
    try:
        connection.request('GET', '/metrics', headers={'Content-Length': '0'})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError('metrics_unavailable')
        data = response.read(262144).decode('ascii', errors='replace')
    finally:
        connection.close()
    result = {key: 0 for key in ['http1', 'http2', 'http3']}
    for protocol, value in re.findall(r'^(?:inbound|outbound)_traffic_bytes\{protocol_type="([A-Za-z0-9]+)"\} ([0-9]+)$', data, re.M):
        key = {'HTTP1': 'http1', 'HTTP2': 'http2', 'HTTP3': 'http3', 'QUIC': 'http3'}.get(protocol.upper())
        if key:
            result[key] += int(value)
    return result


def https_probe(index, origin):
    global PROBE_ERROR
    PROBE_ERROR = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(8)
            # Windows IP_UNICAST_IF expects the interface index in network order.
            raw.setsockopt(socket.IPPROTO_IP, 31, struct.pack('!I', index))
            raw.connect((origin, 443))
            with ssl.create_default_context().wrap_socket(raw, server_hostname='example.com') as secured:
                secured.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
                data = b''
                while len(data) < 65536:
                    chunk = secured.recv(8192)
                    if not chunk:
                        break
                    data += chunk
        return data.startswith(b'HTTP/1.1 200') and b'Example Domain' in data
    except (OSError, ValueError) as error:
        PROBE_ERROR = {'kind': type(error).__name__, 'os_code': getattr(error, 'winerror', None),
                       'tls_code': getattr(error, 'verify_code', None)}
        return False


def dns_probe(info):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.setsockopt(socket.IPPROTO_IP, 31, struct.pack('!I', int(info['index'])))
        question = b'\x07liwetun\x07invalid\x00\x00\x01\x00\x01'
        packet = b'\x37\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question
        sock.sendto(packet, (info['dns'][0], 53))
        answer = sock.recv(4096)
        return answer[:2] == packet[:2] and answer[6:8] == b'\x00\x01' and answer.endswith(b'\xc0\x00\x02\x7b')


def wait_clean(baseline):
    for _ in range(20):
        if tun() is None and snapshot() == baseline:
            return True
        time.sleep(.5)
    return False


def main():
    global INIT_STAGE
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('disposable_windows_runner_required')
    distro = os.environ['LIWETUN_CI_DISTRO']
    if not re.fullmatch(r'LiWeTunCI[0-9]+', distro):
        raise RuntimeError('invalid_task_distribution')
    directory = (ROOT / 'build/network-fixture').resolve()
    directory.mkdir(exist_ok=True, parents=True)
    wsl = ['wsl.exe', '-d', distro, '--']
    def linux(path):
        # Legacy WSL1 command dispatch passes through a shell. Forward slashes
        # prevent unquoted backslashes in drive paths from being consumed.
        return subprocess.check_output(wsl + ['wslpath', '-u', path.as_posix()],
                                       text=True, stderr=subprocess.DEVNULL, timeout=10).strip()
    INIT_STAGE = 'linux_paths'
    fixture = linux(ROOT / 'tools/service/endpoint_fixture.py')
    folder = linux(directory)
    endpoint_binary = linux(ROOT / 'build/endpoint/trusttunnel_endpoint')
    INIT_STAGE = 'synthetic_certificates'
    subprocess.run(wsl + ['python3', fixture, folder, endpoint_binary, 'prepare'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    INIT_STAGE = 'synthetic_profile_generator'
    subprocess.run(['cargo', 'run', '--manifest-path', str(ROOT / 'native/trusttunnel_bridge/Cargo.toml'),
                    '--locked', '--release', '--example', 'network_fixture', '--', str(directory)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    INIT_STAGE = 'public_origin_resolution'
    origin = socket.getaddrinfo('example.com', 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    if not ipaddress.ip_address(origin).is_global:
        raise RuntimeError('public_example_origin_required')
    INIT_STAGE = 'baseline_snapshot'
    baseline = snapshot()
    INIT_STAGE = 'preexisting_adapter_check'
    if tun() is not None:
        raise RuntimeError('preexisting_adapter')
    result = {'release_ready': False, 'mode': 'interface_bound_ipv4_bounded_host_route',
              'origin': 'example.com_https_normal_tls', 'cases': [], 'all_passed': False}
    endpoint = session = None
    stage = 'initialization'
    try:
        for name in ['http2', 'http3', 'wrong-auth', 'wrong-ca', 'ui-death', 'service-crash']:
            stage = name
            protocol = 'http3' if name == 'http3' else 'http2'
            endpoint = Child(wsl + ['python3', fixture, folder, endpoint_binary, protocol])
            if endpoint.receive() != 'ready':
                raise RuntimeError('endpoint_not_ready')
            before = totals()
            profile = name if name in ['http2', 'http3', 'wrong-auth', 'wrong-ca'] else 'http2'
            session = Child([str(args.client), '--network-session', str(directory / (profile + '.uri'))])
            started = json.loads(session.receive())
            if started['code'] not in [0, 6]:
                raise RuntimeError('service_start_rejected')
            info = None
            state = started
            for _ in range(30):
                state = session.command('query')
                info = tun()
                if info and info['fixture_route'] and (state['state'] == 2 or name.startswith('wrong-')):
                    break
                if state['state'] == 4:
                    break
                time.sleep(.2)
            delivered = dns = False
            probe_error = None
            dns_bytes = {key: 0 for key in before}
            idle_bytes = {key: 0 for key in before}
            startup_bytes = {key: 0 for key in before}
            index = int(info['index']) if info else 0
            if info and info['fixture_route']:
                prepare_tun(info, origin)
                idle_before = totals()
                time.sleep(1)
                idle_after = totals()
                idle_bytes = {key: idle_after[key] - idle_before[key] for key in before}
                startup_bytes = {key: idle_after[key] - before[key] for key in before}
                before = idle_after  # Measure the controlled probes separately.
                delivered = https_probe(index, origin)
                probe_error = PROBE_ERROR
                if not name.startswith('wrong-'):
                    dns_before = totals()
                    try:
                        dns = dns_probe(info)
                    except OSError:
                        dns = False
                    dns_after = totals()
                    dns_bytes = {key: dns_after[key] - dns_before[key] for key in dns_before}
            after = totals()
            dns_fixture_counts = endpoint.command('stats')
            delta = {key: after[key] - before[key] for key in before}
            if name == 'ui-death':
                session.close()  # Exact owned process; service must notice lease death.
            elif name == 'service-crash':
                # Validate SCM image against this installed client's directory.
                os.environ['LIWETUN_EXPECTED_SERVICE'] = str(args.client.parent / 'liwetun_service.exe')
                ps("""
                $service = Get-CimInstance Win32_Service -Filter "Name='LiWeTun'"
                $expected = '"' + $env:LIWETUN_EXPECTED_SERVICE + '" --service '
                if (!$service.ProcessId -or !$service.PathName.StartsWith($expected)) { throw 'Unexpected service identity' }
                Stop-Process -Id $service.ProcessId -Force
                """)
                session.close()
            else:
                session.close('stop')
            session = None
            remove_physical_route()
            cleaned = wait_clean(baseline)
            no_direct_fallback = not https_probe(index, origin) if index else not delivered
            positive = not name.startswith('wrong-')
            transport = delta[protocol] > 0 and all(delta[key] == 0 for key in delta if key != protocol)
            bounded_bytes = sum(idle_bytes.values()) < 16384 and sum(delta.values()) < 524288
            passed = cleaned and no_direct_fallback and (
                (delivered and dns and transport and dns_bytes[protocol] > 0 and bounded_bytes) if positive
                else (not delivered and sum(delta.values()) == 0))
            result['cases'].append({'case': name, 'tls_https_delivered': delivered, 'dns_fixture_answer': dns,
                                    'endpoint_bytes_by_transport': delta, 'routes_dns_adapter_restored': cleaned,
                                    'dns_endpoint_bytes_by_transport': dns_bytes, 'https_probe_error': probe_error,
                                    'idle_endpoint_bytes_by_transport': idle_bytes,
                                    'startup_endpoint_bytes_by_transport': startup_bytes,
                                    'dns_fixture_counts': dns_fixture_counts,
                                    'automatic_tun_default_removed': bool(info and info['automatic_default']),
                                    'bounded_bytes': bounded_bytes,
                                    'closed_interface_denies_delivery': no_direct_fallback, 'passed': passed})
            print('network_case:' + name + (':passed' if passed else ':failed'), flush=True)
            endpoint.close('quit')
            endpoint = None
            if not cleaned:
                raise RuntimeError('cleanup_failed')
            if name == 'service-crash':
                ps('Start-Service LiWeTun')
        result['all_passed'] = all(case['passed'] for case in result['cases'])
    except Exception as error:
        result['failed_stage'] = stage  # Closed enum; never a raw exception.
        result['error_type'] = type(error).__name__
    finally:
        if session:
            session.close('stop')
        if endpoint:
            endpoint.close('quit')
        remove_physical_route()
        result['final_network_restored'] = wait_clean(baseline)
        destination = ROOT / 'build/service-evidence/network.json'
        destination.parent.mkdir(exist_ok=True, parents=True)
        destination.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['all_passed'] and result['final_network_restored'] else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # The caller records the fixed failure; no traceback/profile/core output.
        result = {'all_passed': False, 'release_ready': False, 'failed_stage': INIT_STAGE,
                  'error_type': type(error).__name__,
                  'subprocess_exit': error.returncode if isinstance(error, subprocess.CalledProcessError) else None}
        destination = ROOT / 'build/service-evidence/network.json'
        destination.parent.mkdir(exist_ok=True, parents=True)
        destination.write_text(json.dumps(result, indent=2) + '\n')
        print('network_fixture_initialization_failed:' + INIT_STAGE)
        raise SystemExit(1)
