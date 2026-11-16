"""One ordinary unbound IPv4 HTTPS/DNS case on disposable Windows CI.

The official endpoint uses its SOCKS5 forwarder feature. Only its test exit
binds the physical interface; this harness adds no client/physical host routes.
This single positive case is not the complete crash/negative/desktop matrix.
"""
import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time

from network import Child, ROOT, ps, snapshot, totals, tun, wait_clean


def owned_wfp(client):
    process = subprocess.run([str(client), '--wfp-state'], capture_output=True,
                             text=True, timeout=15)
    if process.returncode or len(process.stdout) > 2048:
        raise RuntimeError('wfp_probe_failed')
    result = json.loads(process.stdout)
    if result.get('passed') is not True:
        raise RuntimeError('wfp_probe_failed')
    return result


def ordinary_https(origin, addresses):
    source_matches = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(8)
            raw.connect((origin, 443))  # Deliberately no bind or IP_UNICAST_IF.
            source_matches = raw.getsockname()[0] in addresses
            with ssl.create_default_context().wrap_socket(raw, server_hostname='example.com') as tls:
                tls.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
                answer = b''
                while len(answer) < 65536:
                    part = tls.recv(8192)
                    if not part:
                        break
                    answer += part
                return answer.startswith(b'HTTP/1.1 200') and b'Example Domain' in answer, source_matches
    except (OSError, ValueError):
        return False, source_matches


def ordinary_dns(target, addresses):
    source_matches = False
    observation = dict(reply_received=False, id_matches=False, one_answer=False, payload_matches=False)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as raw:
            raw.settimeout(5)
            raw.connect((target, 53))  # Ordinary Windows route/source selection.
            source_matches = raw.getsockname()[0] in addresses
            question = b'\x07liwetun\x07invalid\x00\x00\x01\x00\x01'
            packet = b'\x37\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question
            raw.send(packet)
            answer = raw.recv(4096)
            observation.update(reply_received=True, id_matches=answer[:2] == packet[:2],
                               one_answer=answer[6:8] == b'\x00\x01',
                               payload_matches=answer.endswith(b'\xc0\x00\x02\x7b'))
            return all(observation.values()), source_matches, observation
    except OSError as error:
        observation['os_code'] = error.errno
        return False, source_matches, observation


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', type=str, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('disposable_windows_required')
    run_id = os.environ['GITHUB_RUN_ID']
    distro = os.environ['LIWETUN_CI_DISTRO']
    if not re.fullmatch(r'[0-9]{1,20}', run_id) or distro != 'LiWeTunCI' + run_id:
        raise RuntimeError('invalid_task_identity')
    from pathlib import Path
    client = Path(args.client).resolve()
    expected = Path(os.environ['ProgramFiles']) / ('LiWeTun-CI-' + run_id) / 'liwetun.exe'
    if str(client).lower() != str(expected).lower():
        raise RuntimeError('unexpected_client_path')
    protocol = os.environ.get('LIWETUN_PRODUCTION_TRANSPORT', 'http2')
    if protocol not in ['http2', 'http3']:
        raise RuntimeError('invalid_fixture_protocol')
    termination = os.environ.get('LIWETUN_PRODUCTION_TERMINATION', 'stop')
    if termination not in ['stop', 'lease-death', 'service-crash']:
        raise RuntimeError('invalid_fixture_termination')
    report = ROOT / 'build/service-evidence/production-network.json'
    report.parent.mkdir(exist_ok=True, parents=True)
    result = {'passed': False, 'mode': 'single_production_unbound_ipv4', 'protocol': protocol,
              'termination': termination,
              'network_test_modes_enabled': False, 'client_host_routes_added': False,
              'server_https_egress_bound_physical': True,
              'endpoint_udp_relay': 'wsl_local',
              'endpoint_diagnostic_source_fix': bool(os.environ.get('LIWETUN_ENDPOINT_FIXTURE_RUN')),
              'full_matrix_qualified': False, 'release_ready': False}
    directory = ROOT / 'build/network-fixture'
    directory.mkdir(exist_ok=True, parents=True)
    baseline = snapshot()
    if tun() is not None:
        raise RuntimeError('preexisting_adapter')
    stage = 'fixture_preparation'
    endpoint = forwarder = session = watchdog = wfp_watch = None
    restored = False
    try:
        physical = ps("""
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 1
        $address = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 | Where-Object AddressState -eq 'Preferred' | Select-Object -First 1
        @{index=$route.InterfaceIndex;address=$address.IPAddress} | ConvertTo-Json -Compress
        """)
        dns_host = ipaddress.IPv4Address(physical['address'])
        if not dns_host.is_private or dns_host.is_loopback:
            raise RuntimeError('invalid_fixture_address')
        origin = socket.getaddrinfo('example.com', 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        if not ipaddress.ip_address(origin).is_global:
            raise RuntimeError('invalid_fixture_address')
        (directory / 'dns-host.txt').write_text(str(dns_host))
        (directory / 'forwarder-inputs.json').write_text(json.dumps({
            'origin': origin, 'dns_host': str(dns_host), 'physical_index': physical['index']}))
        wsl = ['wsl.exe', '-d', distro, '--']
        def linux(path):
            return subprocess.check_output(wsl + ['wslpath', '-u', path.as_posix()],
                                           text=True, stderr=subprocess.DEVNULL, timeout=10).strip()
        def udp_boundary():
            preflight = subprocess.run(wsl + ['python3', linux(ROOT / 'tools/service/udp_fixture_probe.py'),
                                              linux(directory)],
                                       capture_output=True, text=True, timeout=15)
            if len(preflight.stdout) > 2048:
                raise RuntimeError('udp_preflight_failed')
            observation = json.loads(preflight.stdout)
            if preflight.returncode not in [0, 2] or not isinstance(observation, dict):
                raise RuntimeError('udp_preflight_failed')
            return observation
        fixture = linux(ROOT / 'tools/service/endpoint_fixture.py')
        folder = linux(directory)
        binary = linux(ROOT / 'build/endpoint/trusttunnel_endpoint')
        subprocess.run(wsl + ['python3', fixture, folder, binary, 'prepare'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        subprocess.run(['cargo', 'run', '--manifest-path', str(ROOT / 'native/trusttunnel_bridge/Cargo.toml'),
                        '--locked', '--release', '--example', 'network_fixture', '--', str(directory)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        wfp_before = owned_wfp(client)
        if termination == 'service-crash':
            wfp_watch = Child([str(client), '--wfp-watch'])
            retained = json.loads(wfp_watch.receive())
            if (retained.get('passed') is not True or retained.get('retained_process_alive') is not True
                    or retained['sdk_sessions'] != wfp_before['sdk_sessions']
                    or retained['sdk_dynamic_sessions'] != wfp_before['sdk_dynamic_sessions']):
                raise RuntimeError('wfp_watch_not_ready')
        forwarder = Child([sys.executable, str(ROOT / 'tools/service/physical_forwarder.py'), str(directory)])
        if forwarder.receive() != 'ready':
            raise RuntimeError('forwarder_not_ready')
        endpoint = Child(wsl + ['python3', fixture, folder, binary, protocol])
        if endpoint.receive() != 'ready':
            raise RuntimeError('endpoint_not_ready')
        stage = 'wsl_udp_preflight'
        result['wsl_udp_preflight'] = udp_boundary()
        if result['wsl_udp_preflight'].get('passed') is not True:
            raise RuntimeError('udp_preflight_failed')
        stage = 'endpoint_udp_preflight'
        from endpoint_udp_probe import probe as endpoint_udp_probe
        result['endpoint_udp_preflight'] = endpoint_udp_probe(directory, sources=(40000, 40001))
        if result['endpoint_udp_preflight'].get('passed') is not True:
            result['dns_fixture_counts'] = endpoint.command('stats')
            raise RuntimeError('endpoint_udp_preflight_failed')
        stage = 'armed_deadline'
        watchdog = Child(['pwsh', '-NoProfile', '-NonInteractive', '-File',
                          str(ROOT / 'tools/service/general-watchdog.ps1'), '-DeadlineSeconds', '60'])
        if watchdog.receive() != 'ready':
            raise RuntimeError('watchdog_not_ready')
        before = totals()
        stage = 'production_session'
        session = Child([str(client), '--network-session', str(directory / (protocol + '.uri'))])
        if json.loads(session.receive())['code'] not in [0, 6]:
            raise RuntimeError('service_start_rejected')
        info = None
        selected = False
        os.environ['LIWETUN_CI_ORIGIN'] = origin
        for _ in range(20):
            state = session.command('query')
            info = tun()
            if info and info['dns']:
                selected = ps(f"@(Find-NetRoute -RemoteIPAddress $env:LIWETUN_CI_ORIGIN | Where-Object InterfaceIndex -eq {int(info['index'])}).Count -gt 0 | ConvertTo-Json -Compress")
                if selected and state['state'] == 2:
                    break
            if state['state'] == 4:
                break
            time.sleep(.1)
        result['ordinary_origin_route_is_tun'] = selected
        if not info or not selected:
            raise RuntimeError('production_route_not_selected')
        os.environ['LIWETUN_CI_DNS_HOST'] = str(dns_host)
        dns_physical = ps(f"@(Find-NetRoute -RemoteIPAddress $env:LIWETUN_CI_DNS_HOST | Where-Object InterfaceIndex -eq {int(physical['index'])}).Count -gt 0 | ConvertTo-Json -Compress")
        result['fixture_dns_private_route_is_physical'] = dns_physical
        if not dns_physical:
            raise RuntimeError('fixture_dns_route_not_physical')
        index = int(info['index'])
        addresses = ps(f"@(Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4).IPAddress | ConvertTo-Json -Compress")
        if isinstance(addresses, str):
            addresses = [addresses]
        stage = 'ordinary_https'
        delivered, source = ordinary_https(origin, addresses)
        result.update(tls_https_delivered=delivered, https_socket_source_is_tun=source)
        stage = 'wsl_udp_active_sdk'
        result['wsl_udp_active_sdk'] = udp_boundary()
        stage = 'ordinary_dns'
        marker_before = endpoint.command('stats')['local_forwarder_counts']
        dns_before = totals()
        dns, dns_source, dns_observation = ordinary_dns(info['dns'][0], addresses)
        dns_after = totals()
        for _ in range(10):
            if dns_after[protocol] > dns_before[protocol]:
                break
            time.sleep(.1)
            dns_after = totals()
        after = totals()
        delta = {key: after[key] - before[key] for key in before}
        dns_delta = {key: dns_after[key] - dns_before[key] for key in before}
        proxy = forwarder.command('stats')
        endpoint_observation = endpoint.command('stats')
        marker_after = endpoint_observation['local_forwarder_counts']
        marker_delta = {key: marker_after[key] - marker_before[key]
                        for key in ['synthetic_dns_requests', 'synthetic_dns_replies']}
        result.update(dns_fixture_answer=dns, dns_socket_source_is_tun=dns_source,
                      dns_observation=dns_observation,
                      synthetic_dns_forwarder_delta=marker_delta,
                      endpoint_bytes_by_transport=delta, dns_endpoint_bytes_by_transport=dns_delta,
                      forwarder_counts=proxy, dns_fixture_counts=endpoint_observation)
        if wfp_watch:
            active = wfp_watch.command('query')
            result['retained_sdk_dynamic_session_observed'] = (
                active.get('passed') is True and active.get('retained_process_alive') is True
                and active['sdk_dynamic_sessions'] > wfp_before['sdk_dynamic_sessions'])
            if not result['retained_sdk_dynamic_session_observed']:
                raise RuntimeError('active_wfp_session_not_observed')
        stage = 'terminate_and_restore'
        # No stdin EOF/graceful Stop in this fault case: Child.close without a
        # command kills exactly its owned process. The service must detect loss
        # of its authenticated lease and restore the network itself.
        if termination == 'lease-death':
            if session.process.poll() is not None:
                raise RuntimeError('lease_client_already_exited')
            session.close()
            result['lease_client_forced_exit'] = session.process.returncode != 0
            if not result['lease_client_forced_exit']:
                raise RuntimeError('lease_client_not_forced')
        elif termination == 'service-crash':
            os.environ['LIWETUN_EXPECTED_SERVICE'] = str(client.parent / 'liwetun_service.exe')
            killed = ps("""
            $configuration = Get-CimInstance Win32_Service -Filter "Name='LiWeTun'"
            $expected = '"' + $env:LIWETUN_EXPECTED_SERVICE + '" --service '
            if (!$configuration.ProcessId -or !$configuration.PathName.StartsWith($expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected service identity' }
            $target = Get-Process -Id $configuration.ProcessId
            try {
              $retained = $target.SafeHandle
              if (!$retained -or ![string]::Equals($target.Path,$env:LIWETUN_EXPECTED_SERVICE,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected service process image' }
              $target.Kill()
              if (!$target.WaitForExit(10000)) { throw 'Owned service did not exit' }
              $true | ConvertTo-Json -Compress
            } finally { $target.Dispose() }
            """)
            result['owned_service_force_terminated'] = killed is True
            if not result['owned_service_force_terminated']:
                raise RuntimeError('service_crash_not_observed')
            session.close()
        else:
            session.close('stop')
        session = None
        restored = wait_clean(baseline)
        wfp_after = wfp_watch.command('query') if wfp_watch else owned_wfp(client)
        wfp_restored = (wfp_after['sdk_sessions'] == wfp_before['sdk_sessions'] and
                        wfp_after['sdk_dynamic_sessions'] == wfp_before['sdk_dynamic_sessions'])
        if wfp_watch:
            result['retained_service_process_ended'] = wfp_after.get('retained_process_alive') is False
            wfp_restored = (wfp_restored and wfp_after.get('passed') is True
                            and result['retained_service_process_ended'])
        result['sdk_wfp_sessions_restored'] = wfp_restored
        result['passed'] = (delivered and source and dns and dns_source and restored and wfp_restored
                            and delta[protocol] > 0 and dns_delta[protocol] >= 82
                            and all(value > 0 for value in marker_delta.values())
                            and all(delta[key] == 0 for key in delta if key != protocol)
                            and proxy['tcp_connected'] > 0
                            and endpoint_observation['local_forwarder_counts']['udp_replies'] > 0)
    except Exception as error:
        result['failed_stage'] = stage
        result['error_type'] = type(error).__name__
    finally:
        if session:
            session.close('stop')
        restored = wait_clean(baseline)
        if watchdog:
            if restored and watchdog.process.poll() is None:
                ps("""
                $event = [Threading.EventWaitHandle]::OpenExisting('Local\\LiWeTun.CI.GeneralDone.' + $env:GITHUB_RUN_ID)
                try { [void]$event.Set() } finally { $event.Dispose() }
                """)
            try:
                watchdog.process.wait(timeout=85)
                guard = json.loads((report.parent / 'general-watchdog.json').read_text(encoding='utf-8-sig'))
                result['deadline_triggered'] = guard['triggered']
                result['passed'] = result['passed'] and not guard['triggered'] and guard['action_completed']
            except Exception:
                result['passed'] = False
                result['deadline_result_unavailable'] = True
            watchdog.close()
        if endpoint:
            endpoint.close('quit')
        if forwarder:
            forwarder.close('quit')
        if wfp_watch:
            wfp_watch.close('quit')
        result['routes_dns_adapter_restored'] = wait_clean(baseline)
        result['passed'] = result['passed'] and result['routes_dns_adapter_restored']
        report.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        # No traceback/raw endpoint/core output, including early fixture errors.
        destination = ROOT / 'build/service-evidence/production-network.json'
        destination.parent.mkdir(exist_ok=True, parents=True)
        destination.write_text(json.dumps({'passed': False, 'failed_stage': 'fixture_initialization',
                                           'release_ready': False}) + '\n')
        raise SystemExit(2) from None
