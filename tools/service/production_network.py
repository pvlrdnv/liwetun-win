"""One ordinary unbound traffic/refusal/fault case on disposable Windows CI.

The official endpoint uses its SOCKS5 forwarder feature. Only its test exit
binds the physical interface; this harness adds no client/physical host routes.
Optional IPv6 TCP/UDP uses a fixed synthetic NAT64 exit, not native IPv6 Internet.
Each invocation is one case, not complete recovery/desktop qualification.
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
from physical_forwarder import SYNTHETIC_IPV6, SYNTHETIC_IPV6_PAYLOAD, SYNTHETIC_IPV6_UDP_PORT


def owned_wfp(client):
    process = subprocess.run([str(client), '--wfp-state'], capture_output=True,
                             text=True, timeout=15)
    if len(process.stdout) > 2048:
        raise RuntimeError('wfp_probe_failed')
    result = json.loads(process.stdout)
    if process.returncode or result.get('passed') is not True:
        error = RuntimeError('wfp_probe_failed')
        stages = {'disposable_ci', 'authenticated_service_query', 'owned_service_pid',
                  'retain_trusted_service', 'read_wfp_sessions'}
        error.wfp_stage = result.get('stage') if result.get('stage') in stages else 'unknown'
        code = result.get('query_code')
        error.wfp_query_code = code if type(code) is int and 0 <= code <= 9 else None
        raise error
    return result


def source_is_tun(stream, addresses):
    source = ipaddress.ip_address(stream.getsockname()[0].split('%')[0])
    return any(source == ipaddress.ip_address(address.split('%')[0]) for address in addresses)


def ordinary_https(origin, addresses, family=socket.AF_INET):
    source_matches = False
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(8)
            raw.connect((origin, 443))  # Deliberately no bind or IP_UNICAST_IF.
            source_matches = source_is_tun(raw, addresses)
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


def ordinary_dns(target, addresses, aaaa=False):
    source_matches = False
    observation = dict(reply_received=False, id_matches=False, one_answer=False, payload_matches=False)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as raw:
            raw.settimeout(5)
            raw.connect((target, 53))  # Ordinary Windows route/source selection.
            source_matches = source_is_tun(raw, addresses)
            question = b'\x07liwetun\x07invalid\x00' + (b'\x00\x1c' if aaaa else b'\x00\x01') + b'\x00\x01'
            packet = b'\x37\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question
            raw.send(packet)
            answer = raw.recv(4096)
            observation.update(reply_received=True, id_matches=answer[:2] == packet[:2],
                               one_answer=answer[6:8] == b'\x00\x01',
                               payload_matches=answer.endswith(ipaddress.IPv6Address(SYNTHETIC_IPV6).packed
                                                               if aaaa else b'\xc0\x00\x02\x7b'))
            return all(observation.values()), source_matches, observation
    except OSError as error:
        observation['os_code'] = error.errno
        return False, source_matches, observation


def ordinary_ipv6_echo(addresses):
    source_matches = False
    observation = dict(reply_received=False, payload_matches=False)
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as raw:
            raw.settimeout(5)
            raw.connect((SYNTHETIC_IPV6, SYNTHETIC_IPV6_UDP_PORT))
            source_matches = source_is_tun(raw, addresses)
            raw.send(SYNTHETIC_IPV6_PAYLOAD)
            answer = raw.recv(4096)
            observation.update(reply_received=True, payload_matches=answer == SYNTHETIC_IPV6_PAYLOAD)
            return all(observation.values()), source_matches, observation
    except OSError as error:
        observation.update(os_code=error.errno, timed_out=isinstance(error, TimeoutError))
        return False, source_matches, observation


def recovery_evidence_valid(protocol, state, https_ok, https_tun, dns_ok, dns_tun,
                            growth, dns_growth, dns_transport_growth):
    """A recovered process/ready flag or direct traffic cannot satisfy this oracle."""
    return (state == 2 and https_ok and https_tun and dns_ok and dns_tun
            and growth[protocol] > 0
            and all(growth[key] == 0 for key in growth if key != protocol)
            and all(value > 0 for value in dns_growth.values())
            and dns_transport_growth[protocol] >= 82
            and all(value == 0 for key, value in dns_transport_growth.items()
                    if key != protocol))


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
    if termination not in ['stop', 'lease-death', 'service-crash', 'endpoint-restart']:
        raise RuntimeError('invalid_fixture_termination')
    profile = os.environ.get('LIWETUN_PRODUCTION_PROFILE', 'valid')
    if profile not in ['valid', 'wrong-auth', 'wrong-ca'] or (
            profile != 'valid' and (protocol != 'http2' or termination != 'stop')):
        raise RuntimeError('invalid_fixture_profile')
    family = os.environ.get('LIWETUN_PRODUCTION_FAMILY', 'ipv4')
    if family not in ['ipv4', 'synthetic-ipv6'] or (family != 'ipv4' and profile != 'valid'):
        raise RuntimeError('invalid_fixture_family')
    if termination == 'endpoint-restart' and (profile != 'valid' or family != 'ipv4'):
        raise RuntimeError('invalid_recovery_case')
    synthetic_ipv6 = family == 'synthetic-ipv6'
    report = ROOT / 'build/service-evidence/production-network.json'
    report.parent.mkdir(exist_ok=True, parents=True)
    result = {'passed': False, 'mode': 'single_production_unbound_ipv4', 'protocol': protocol,
              'termination': termination,
              'profile': profile,
              'client_family': family,
              'network_test_modes_enabled': False, 'client_host_routes_added': False,
              'server_https_egress_bound_physical': True,
              'endpoint_udp_relay': 'wsl_local',
              'endpoint_diagnostic_source_fix': bool(os.environ.get('LIWETUN_ENDPOINT_FIXTURE_RUN')),
              'full_matrix_qualified': False, 'release_ready': False}
    if synthetic_ipv6:
        result.update(mode='single_production_synthetic_ipv6_nat64',
                      ipv6_fixture_exit_translates_to_ipv4=True,
                      ipv6_native_egress_qualified=False, dns_probe_family='ipv4')
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
            'origin': origin, 'dns_host': str(dns_host), 'physical_index': physical['index'],
            'synthetic_ipv6': synthetic_ipv6}))
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
                          str(ROOT / 'tools/service/general-watchdog.ps1'), '-DeadlineSeconds',
                          '120' if termination == 'endpoint-restart' else '60'])
        if watchdog.receive() != 'ready':
            raise RuntimeError('watchdog_not_ready')
        before = totals()
        stage = 'production_session'
        profile_file = protocol if profile == 'valid' else profile
        session = Child([str(client), '--network-session', str(directory / (profile_file + '.uri'))])
        if json.loads(session.receive())['code'] not in [0, 6]:
            raise RuntimeError('service_start_rejected')
        info = None
        selected = False
        os.environ['LIWETUN_CI_ORIGIN'] = SYNTHETIC_IPV6 if synthetic_ipv6 else origin
        for _ in range(20):
            state = session.command('query')
            info = tun()
            if info and info['dns']:
                selected = ps(f"@(Find-NetRoute -RemoteIPAddress $env:LIWETUN_CI_ORIGIN | Where-Object InterfaceIndex -eq {int(info['index'])}).Count -gt 0 | ConvertTo-Json -Compress")
                if selected and state['state'] == 2 and profile == 'valid':
                    break
            if state['state'] == 4:
                break
            time.sleep(.1)
        result['ordinary_origin_route_is_tun'] = selected
        if profile == 'valid':
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
            https_addresses = addresses
            if synthetic_ipv6:
                stage = 'ipv6_tun_addresses'
                https_addresses = ps(f"@(Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv6).IPAddress | ConvertTo-Json -Compress")
                if isinstance(https_addresses, str):
                    https_addresses = [https_addresses]
                if not isinstance(https_addresses, list) or not https_addresses:
                    raise RuntimeError('ipv6_tun_address_missing')
            stage = 'ordinary_https'
            delivered, source = ordinary_https(SYNTHETIC_IPV6 if synthetic_ipv6 else origin,
                                               https_addresses,
                                               socket.AF_INET6 if synthetic_ipv6 else socket.AF_INET)
            result.update(tls_https_delivered=delivered, https_socket_source_is_tun=source)
            stage = 'wsl_udp_active_sdk'
            result['wsl_udp_active_sdk'] = udp_boundary()
            ipv6_ok = True
            if synthetic_ipv6:
                stage = 'ordinary_ipv6_udp'
                echo_before = endpoint.command('stats')['local_forwarder_counts']
                echo_transport_before = totals()
                echo, echo_source, echo_observation = ordinary_ipv6_echo(https_addresses)
                echo_transport_after = totals()
                for _ in range(10):
                    if echo_transport_after[protocol] - echo_transport_before[protocol] >= 2 * len(SYNTHETIC_IPV6_PAYLOAD):
                        break
                    time.sleep(.1)
                    echo_transport_after = totals()
                echo_after = endpoint.command('stats')['local_forwarder_counts']
                echo_delta = {key: echo_after[key] - echo_before[key]
                              for key in ['synthetic_ipv6_echo_requests', 'synthetic_ipv6_echo_replies']}
                echo_transport = {key: echo_transport_after[key] - echo_transport_before[key]
                                  for key in echo_transport_before}
                ipv6_ok = (echo and echo_source and all(value > 0 for value in echo_delta.values())
                           and echo_transport[protocol] >= 2 * len(SYNTHETIC_IPV6_PAYLOAD)
                           and all(value == 0 for key, value in echo_transport.items() if key != protocol))
                result.update(ipv6_udp_echo_delivered=echo, ipv6_udp_source_is_tun=echo_source,
                              ipv6_udp_observation=echo_observation, ipv6_echo_forwarder_delta=echo_delta,
                              ipv6_echo_transport_bytes=echo_transport)
                stage = 'ordinary_aaaa_dns'
                aaaa_marker_before = endpoint.command('stats')['local_forwarder_counts']
                aaaa_before = totals()
                aaaa, aaaa_source, aaaa_observation = ordinary_dns(info['dns'][0], addresses, aaaa=True)
                aaaa_after = totals()
                for _ in range(10):
                    if aaaa_after[protocol] - aaaa_before[protocol] >= 94:
                        break
                    time.sleep(.1)
                    aaaa_after = totals()
                aaaa_marker_after = endpoint.command('stats')['local_forwarder_counts']
                aaaa_delta = {key: aaaa_marker_after[key] - aaaa_marker_before[key]
                              for key in ['synthetic_aaaa_requests', 'synthetic_aaaa_replies']}
                aaaa_transport = {key: aaaa_after[key] - aaaa_before[key] for key in aaaa_before}
                ipv6_ok = (ipv6_ok and aaaa and aaaa_source and all(value > 0 for value in aaaa_delta.values())
                           and aaaa_transport[protocol] >= 94
                           and all(value == 0 for key, value in aaaa_transport.items() if key != protocol))
                result.update(ipv6_aaaa_answer_delivered=aaaa, aaaa_dns_socket_source_is_tun=aaaa_source,
                              aaaa_dns_observation=aaaa_observation, aaaa_forwarder_delta=aaaa_delta,
                              aaaa_transport_bytes=aaaa_transport)
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
            traffic_ok = (delivered and source and dns and dns_source and ipv6_ok
                          and delta[protocol] > 0 and dns_delta[protocol] >= 82
                          and all(value > 0 for value in marker_delta.values())
                          and all(delta[key] == 0 for key in delta if key != protocol)
                          and proxy['tcp_connected'] > 0
                          and endpoint_observation['local_forwarder_counts']['udp_replies'] > 0)
        else:
            stage = 'profile_refusal'
            after_refusal = totals()
            refusal_delta = {key: after_refusal[key] - before[key] for key in before}
            refusal_stats = endpoint.command('stats')['local_forwarder_counts']
            terminal_error = state['code'] == 6 and state['state'] == 4
            traffic_ok = (terminal_error and sum(refusal_delta.values()) == 0
                          and refusal_stats['tcp_connected'] == 0)
            result.update(profile_refusal_observed=terminal_error,
                          ordinary_https_probe_attempted=False,
                          adapter_absent_at_refusal=info is None,
                          endpoint_bytes_by_transport=refusal_delta,
                          endpoint_tcp_connections=refusal_stats['tcp_connected'])
        if termination == 'endpoint-restart':
            if not traffic_ok:
                raise RuntimeError('pre_recovery_traffic_failed')
            stage = 'owned_endpoint_restart'
            restarted = endpoint.command('restart')
            result['endpoint_restart'] = restarted
            if restarted != {'restarted': True, 'outage_seconds': 2}:
                raise RuntimeError('endpoint_restart_failed')
            # Existing authenticated GUI lease and SDK instance remain alive.
            # Re-read TUN addresses on every observation; no Start/reconnect RPC.
            attempts = []
            recovered = False
            for _ in range(3):
                stage = 'observe_endpoint_recovery'
                current = tun()
                if not current:
                    attempts.append({'adapter_present': False})
                    break
                current_addresses = ps(f"@(Get-NetIPAddress -InterfaceIndex {int(current['index'])} -AddressFamily IPv4).IPAddress | ConvertTo-Json -Compress")
                if isinstance(current_addresses, str):
                    current_addresses = [current_addresses]
                current_state = session.command('query')
                counters_before = totals()
                markers_before = endpoint.command('stats')['local_forwarder_counts']
                https_ok, https_tun = ordinary_https(origin, current_addresses)
                dns_before_recovery = totals()
                dns_ok, dns_tun, _ = ordinary_dns(current['dns'][0], current_addresses)
                counters_after = totals()
                for _ in range(10):
                    if counters_after[protocol] - dns_before_recovery[protocol] >= 82:
                        break
                    time.sleep(.1)
                    counters_after = totals()
                dns_transport_growth = {key: counters_after[key] - dns_before_recovery[key]
                                        for key in counters_before}
                markers_after = endpoint.command('stats')['local_forwarder_counts']
                growth = {key: counters_after[key] - counters_before[key] for key in counters_before}
                dns_growth = {key: markers_after[key] - markers_before[key]
                              for key in ['synthetic_dns_requests', 'synthetic_dns_replies']}
                # Require the selected transport and the exact synthetic DNS exchange.
                # Endpoint uptime/process state alone can never qualify recovery.
                recovered = recovery_evidence_valid(
                    protocol, current_state['state'], https_ok, https_tun, dns_ok, dns_tun,
                    growth, dns_growth, dns_transport_growth)
                attempts.append({'adapter_present': True,
                                 'state': current_state['state'], 'https_delivered': https_ok,
                                 'https_source_is_tun': https_tun, 'dns_delivered': dns_ok,
                                 'dns_source_is_tun': dns_tun, 'transport_bytes': growth,
                                 'dns_marker_delta': dns_growth, 'dns_transport_bytes': dns_transport_growth,
                                 'recovered': recovered})
                if recovered:
                    break
                time.sleep(.5)
            result.update(recovery_attempts=attempts, recovered_without_new_start=recovered,
                          desktop_sleep_or_network_change_qualified=False)
            traffic_ok = traffic_ok and recovered
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
        stage = 'observe_routes_dns_adapter_restore'
        result['restoration_observation'] = {}
        restored = wait_clean(baseline, result['restoration_observation'])
        stage = 'observe_wfp_restore'
        wfp_after = wfp_watch.command('query') if wfp_watch else owned_wfp(client)
        wfp_restored = (wfp_after['sdk_sessions'] == wfp_before['sdk_sessions'] and
                        wfp_after['sdk_dynamic_sessions'] == wfp_before['sdk_dynamic_sessions'])
        if wfp_watch:
            result['retained_service_process_ended'] = wfp_after.get('retained_process_alive') is False
            wfp_restored = (wfp_restored and wfp_after.get('passed') is True
                            and result['retained_service_process_ended'])
        result['sdk_wfp_sessions_restored'] = wfp_restored
        result['passed'] = traffic_ok and restored and wfp_restored
    except Exception as error:
        result['failed_stage'] = stage
        result['error_type'] = type(error).__name__
        reasons = {'wfp_probe_failed', 'fixture_system_command_failed', 'fixture_child_timeout',
                   'fixture_child_closed', 'lease_client_already_exited', 'lease_client_not_forced',
                   'service_crash_not_observed'}
        reason = error.args[0] if error.args else None
        result['failure_reason'] = reason if isinstance(reason, str) and reason in reasons else 'unknown'
        if reason == 'wfp_probe_failed':
            result['wfp_probe_stage'] = getattr(error, 'wfp_stage', 'unknown')
            result['wfp_query_code'] = getattr(error, 'wfp_query_code', None)
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
                watchdog.process.wait(timeout=145 if termination == 'endpoint-restart' else 85)
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
