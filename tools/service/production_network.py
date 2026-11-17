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
from owned_https_fixture import MODES as HTTPS_MODES


def observe_owned_https(session, endpoint, report_path, mode, diagnostic):
    from owned_https_fixture import read_receipt, validate_https_report, REQUEST_HEADERS, HEADERS
    from owned_probe_fixture import validate_report
    path_file = report_path / 'owned-probe-context.json'
    tls_file = report_path / 'owned-https-context.json'
    started = time.monotonic()
    stopping = mode == 'https-cancel'
    if stopping:
        while time.monotonic() - started < 4:
            receiver = endpoint.command('stats')['owned_probe_sink']
            if path_file.exists():
                raise RuntimeError('owned_https_not_waiting')
            if receiver['valid_requests'] == 1 and receiver['waiting_for_owner_close'] == 1:
                break
            time.sleep(.025)
        else:
            raise RuntimeError('owned_https_not_waiting')
        traffic = session.command('traffic')
        if traffic.get('flags', 0) & 2 or traffic.get('tx') is not None or traffic.get('rx') is not None or path_file.exists():
            raise RuntimeError('owned_https_not_waiting')
        started = time.monotonic()
        stop = session.command('stop')
        if stop.get('code') != 0:
            raise RuntimeError('owned_https_not_qualified')
    while time.monotonic() - started < (1.5 if stopping else 8):
        receiver = endpoint.command('stats')['owned_probe_sink']
        diagnostic['receiver'] = receiver
        if path_file.exists() and tls_file.exists():
            path = read_receipt(path_file)
            tls = read_receipt(tls_file)
            if path is None or tls is None:
                time.sleep(.025)
                continue
            path = validate_report(path)
            tls = validate_https_report(tls, path)
            diagnostic.update(path=path, tls=tls)
            if ((mode == 'https-untrusted' and receiver['handshake_failed'] == 1)
                    or (mode != 'https-untrusted' and receiver['owner_closed'] == 1 and receiver['waiting_for_owner_close'] == 0)):
                break
        time.sleep(.025)
    else:
        raise RuntimeError('owned_https_not_qualified')
    elapsed = int((time.monotonic() - started) * 1000)
    common = (path['stage'] == 9 and path['connected'] and path['nonexclusive_rejected']
              and path['arm_accepted'] and path['disarmed']
              and receiver['empty_controls'] == 1 and not receiver['client_certificate_seen']
              and receiver['rejected_frames'] == receiver['owner_reset'] == 0)
    if stopping:
        common = (common and not path['state_epoch_changed'] and path['cancelled'] and path['receive_cancelled']
                  and not path['same_instance_epoch'] and path['snapshot_flags'] == 1)
    elif mode == 'https-epoch-change':
        common = (common and path['state_epoch_changed'] and not path['same_instance_epoch'] and not path['cancelled']
                  and not path['receive_cancelled'] and path['snapshot_flags'] in [1, 129, 257, 513]
                  and path['tx_bytes'] is None and path['rx_bytes'] is None)
    elif mode == 'https-migration':
        common = (common and not path['state_epoch_changed'] and path['same_instance_epoch'] and not path['cancelled']
                  and not path['receive_cancelled'] and not path['receive_timed_out'] and path['snapshot_flags'] == 33
                  and path['tx_bytes'] is None and path['rx_bytes'] is None)
    else:
        common = (common and not path['state_epoch_changed'] and path['same_instance_epoch'] and not path['cancelled'] and not path['receive_cancelled']
                  and path['snapshot_flags'] == 15 and path['tx_bytes'] >= tls['wire_tx'] > 0
                  and path['rx_bytes'] >= tls['wire_rx'] > 0)
    if mode == 'https-untrusted':
        accepted = (tls['tls_result'] == 8 and tls['http_result'] is None and not tls['handshake_verified']
                    and not tls['request_sent'] and receiver['handshake_failed'] == 1
                    and receiver['valid_requests'] == receiver['request_bytes'] == receiver['replies_sent'] == 0)
    else:
        accepted = (tls['handshake_verified'] and tls['request_sent'] and receiver['handshake_complete'] == 1
                    and receiver['handshake_failed'] == 0 and receiver['valid_requests'] == 1
                    and receiver['request_bytes'] == len(REQUEST_HEADERS) + 8)
        if mode in ['https', 'https-wrong-nonce', 'https-migration']:
            accepted = (accepted and tls['tls_result'] == 0 and tls['http_result'] == (2 if mode == 'https-wrong-nonce' else 1)
                        and receiver['replies_sent'] == 1 and receiver['reply_bytes'] == len(HEADERS) + 8
                        and receiver['invalid_replies'] == int(mode == 'https-wrong-nonce'))
        elif mode == 'https-epoch-change':
            accepted = (accepted and tls['tls_result'] in [2, 3, 4, 12, 14] and tls['http_result'] == 7
                        and receiver['replies_sent'] == receiver['reply_bytes'] == 0)
        else:
            accepted = (accepted and tls['tls_result'] == (1 if stopping else 2) and tls['http_result'] == 7
                        and receiver['replies_sent'] == receiver['reply_bytes'] == 0
                        and path['receive_timed_out'] == (not stopping))
    good = mode == 'https'
    verified_response = mode in ['https', 'https-migration']
    if not stopping:
        traffic = session.command('traffic')
    unknown = not traffic.get('flags', 0) & 2 and traffic.get('tx') is None and traffic.get('rx') is None
    if not (common and accepted and tls['qualified'] == good and tls['response_verified'] == verified_response
            and (good or unknown)):
        raise RuntimeError('owned_https_not_qualified')
    return dict(qualified=True, owned_https_qualified=good, path=path, tls=tls, receiver=receiver,
                elapsed_ms=elapsed, unknown_after_negative=unknown if not good and not stopping else None,
                unknown_before_stop=unknown if stopping else None,
                stop_during_receive=stopping, proves_dns=False, proves_internet=False, release_ready=False)


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


def cancel_owned_request(session, endpoint, report_path):
    """Wait for readiness, then require native receive cancellation before its deadline."""
    from owned_probe_fixture import validate_cancel_report
    started = time.monotonic()
    while time.monotonic() - started < 10:
        if report_path.exists():
            raise RuntimeError('owned_probe_not_waiting')
        receiver = endpoint.command('stats')['owned_probe_sink']
        if receiver['waiting_for_owner_close'] == 1 and receiver['valid_requests'] == 1:
            break
        time.sleep(.025)
    else:
        raise RuntimeError('owned_probe_not_waiting')
    traffic = session.command('traffic')
    unknown = (not traffic.get('flags', 0) & 2 and traffic.get('tx') is None and traffic.get('rx') is None)
    if not unknown or report_path.exists():
        raise RuntimeError('owned_probe_not_waiting')
    stop_started = time.monotonic()
    reply = session.command('stop')
    ack_ms = int((time.monotonic() - stop_started) * 1000)
    # Wait for the service's worker receipt and remote EOF, not just Stop ACK.
    while time.monotonic() - stop_started < 1.5:
        receiver = endpoint.command('stats')['owned_probe_sink']
        if report_path.exists() and receiver['owner_closed'] == 1 and receiver['waiting_for_owner_close'] == 0:
            with report_path.open('rb') as source:
                raw = source.read(4097)
            if len(raw) <= 4096 and raw.endswith(b'\n'):
                observation = validate_cancel_report(json.loads(raw), receiver)
                break
        time.sleep(.025)
    else:
        raise RuntimeError('owned_probe_cancellation_not_qualified')
    elapsed_ms = int((time.monotonic() - stop_started) * 1000)
    total_ms = int((time.monotonic() - started) * 1000)
    if reply.get('code') != 0 or ack_ms >= 1500 or elapsed_ms >= 1500:
        raise RuntimeError('owned_probe_cancellation_not_qualified')
    return dict(qualified=True, stop_ack_ms=ack_ms, worker_and_remote_close_ms=elapsed_ms,
                observation_total_ms=total_ms, unknown_before_stop=unknown,
                owned_socket_path=observation, owned_socket_receiver=receiver,
                proves_https=False, proves_dns=False, release_ready=False)


def observe_owned_negative(session, endpoint, report_path, diagnostic, mode, local_receiver=None):
    """Require a completed rejected request and remote EOF before sending Stop."""
    from owned_probe_fixture import (validate_report, validate_deadline_report,
                                     validate_wrong_nonce_report, validate_migration_report,
                                     validate_epoch_change_report, validate_bypass_report)
    validators = {'deadline': validate_deadline_report, 'wrong-nonce': validate_wrong_nonce_report,
                  'migration': validate_migration_report, 'epoch-change': validate_epoch_change_report,
                  'bypass': validate_bypass_report}
    reasons = {'deadline': 'owned_probe_deadline_not_qualified',
               'wrong-nonce': 'owned_probe_wrong_nonce_not_qualified',
               'migration': 'owned_probe_migration_not_qualified',
               'epoch-change': 'owned_probe_epoch_change_not_qualified',
               'bypass': 'owned_probe_bypass_not_qualified'}
    validate = validators[mode]
    started = time.monotonic()
    while time.monotonic() - started < 8:
        receiver = local_receiver.stats() if local_receiver else endpoint.command('stats')['owned_probe_sink']
        diagnostic['receiver'] = receiver
        diagnostic['elapsed_ms'] = int((time.monotonic() - started) * 1000)
        if report_path.exists():
            with report_path.open('rb') as source:
                raw = source.read(4097)
            if len(raw) <= 4096 and raw.endswith(b'\n'):
                observation = validate_report(json.loads(raw))
                diagnostic['worker'] = observation
                if receiver['owner_closed'] == 1 and receiver['waiting_for_owner_close'] == 0:
                    validate(observation, receiver)
                    break
        time.sleep(.025)
    else:
        raise RuntimeError(reasons[mode])
    traffic = session.command('traffic')
    unknown = (not traffic.get('flags', 0) & 2 and traffic.get('tx') is None and traffic.get('rx') is None)
    if not unknown:
        raise RuntimeError(reasons[mode])
    result = dict(qualified=True, observation_total_ms=int((time.monotonic() - started) * 1000),
                owned_socket_path=observation, owned_socket_receiver=receiver,
                proves_https=False, proves_dns=False, release_ready=False)
    if mode == 'deadline':
        result.update(stop_sent_before_deadline=False, unknown_after_deadline=True)
    else:
        result.update(stop_sent_before_rejection=False, unknown_after_rejection=True)
    return result


def restart_during_owned_request(endpoint, report_path):
    """Change actual SDK state through endpoint loss after the owned request is in flight."""
    started = time.monotonic()
    while time.monotonic() - started < 4:
        receiver = endpoint.command('stats')['owned_probe_sink']
        if report_path.exists():
            raise RuntimeError('owned_probe_not_waiting')
        if receiver['valid_requests'] == 1 and receiver['waiting_for_owner_close'] == 1:
            break
        time.sleep(.025)
    else:
        raise RuntimeError('owned_probe_not_waiting')
    restarted = endpoint.command('restart-graceful')
    if restarted != {'restarted': True, 'outage_seconds': 2, 'graceful_shutdown': True}:
        raise RuntimeError('endpoint_restart_failed')
    return restarted


def owned_bypass_receiver():
    """Bind only the task TUN's one preferred IPv4; never serialize its address."""
    from owned_probe_fixture import OwnedProbeSink
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        info = tun()
        if info:
            addresses = ps(f"@(Get-NetIPAddress -InterfaceIndex {int(info['index'])} -AddressFamily IPv4 | Where-Object AddressState -eq 'Preferred').IPAddress | ConvertTo-Json -Compress")
            if isinstance(addresses, str):
                addresses = [addresses]
            if isinstance(addresses, list) and len(addresses) == 1:
                return OwnedProbeSink(port=38557, owned_address=addresses[0])
        time.sleep(.025)
    raise RuntimeError('owned_bypass_receiver_not_ready')


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


def valid_aggregate(value):
    return (isinstance(value, dict) and type(value.get('code')) is int and value.get('code') == 0
            and value.get('flags') == 3 and value.get('core_state') == 2
            and all(type(value.get(key)) is int and 0 <= value[key] <= 2**63 - 1
                    for key in ['instance', 'epoch', 'at_ms', 'tx', 'rx'])
            and value['instance'] > 0 and value['epoch'] > 0)


def aggregate_progress(before, after):
    """Closed counter evidence only; endpoint/DNS transport proof stays separate."""
    observed = valid_aggregate(before) and valid_aggregate(after)
    same = observed and before['instance'] == after['instance'] and before['epoch'] == after['epoch']
    monotonic = observed and after['at_ms'] > before['at_ms'] and after['tx'] >= before['tx'] and after['rx'] >= before['rx']
    tx = after['tx'] - before['tx'] if same and monotonic else None
    rx = after['rx'] - before['rx'] if same and monotonic else None
    return dict(passed=bool(same and monotonic and tx > 0 and rx > 0),
                same_instance_and_epoch=bool(same), monotonic=bool(monotonic),
                tx_delta=tx, rx_delta=rx, proves_dns=False, proves_internet=False)


def aggregate_window(samples, tx_only):
    usable = len(samples) >= 2 and all(valid_aggregate(sample) for sample in samples)
    if not usable:
        return dict(passed=False, classification='unknown', tx_delta=None, rx_delta=None)
    before, after = samples[0], samples[-1]
    coherent = all(sample['instance'] == before['instance'] and sample['epoch'] == before['epoch'] for sample in samples)
    for previous, current in zip(samples, samples[1:]):
        coherent = (coherent and 0 < current['at_ms'] - previous['at_ms'] <= 5000
                    and current['tx'] >= previous['tx'] and current['rx'] >= previous['rx'])
    elapsed = after['at_ms'] - before['at_ms']
    tx, rx = after['tx'] - before['tx'], after['rx'] - before['rx']
    from tx_only_fixture import PAYLOAD
    expected = (tx >= 20 * len(PAYLOAD) and rx == 0) if tx_only else (tx == 0 and rx == 0)
    passed = coherent and 20000 <= elapsed <= 30000 and expected
    return dict(passed=bool(passed), classification=('outgoingWithoutReply' if tx_only else 'idle') if passed else 'unknown',
                elapsed_ms=elapsed, tx_delta=tx if coherent else None, rx_delta=rx if coherent else None,
                samples=len(samples), proves_dns=False, proves_internet=False)


def observe_tx_only_and_idle(session, addresses, endpoint, protocol):
    from tx_only_fixture import TARGET, PAYLOAD
    source_matches = False
    transport_before = totals()
    # Closed totals only, including rejected traffic from other runner tasks.
    # Never retain a destination, process identity or payload from those tasks.
    forwarder_before = endpoint.command('stats')['local_forwarder_counts']
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(TARGET)  # Ordinary route/source selection; no bind/host route.
        source_matches = source_is_tun(stream, addresses)
        sent = [session.command('traffic')]
        started = time.monotonic()
        for index in range(21):
            time.sleep(max(0, started + index - time.monotonic()))
            stream.sendall(PAYLOAD)
            time.sleep(.05)
            sent.append(session.command('traffic'))
        outgoing = aggregate_window(sent, tx_only=True)
        endpoint_after_send = endpoint.command('stats')
        marker = endpoint_after_send['tx_only_sink']
        for _ in range(20):
            if marker['matched_frames'] == 21:
                break
            time.sleep(.1)
            marker = endpoint.command('stats')['tx_only_sink']
        # Keep the flow open: connection teardown is not an idle observation.
        idle = [session.command('traffic')]
        started = time.monotonic()
        for index in range(1, 22):
            time.sleep(max(0, started + index - time.monotonic()))
            idle.append(session.command('traffic'))
        quiet = aggregate_window(idle, tx_only=False)
        endpoint_after_idle = endpoint.command('stats')
        after_idle = endpoint_after_idle['tx_only_sink']
    sink_ok = (marker['matched_frames'] == 21 and marker['sent_bytes'] == 0
               and marker['received_bytes'] == 21 * len(PAYLOAD) and marker['rejected_frames'] == 0
               and marker == after_idle)
    transport_after = totals()
    transport_delta = {key: transport_after[key] - transport_before[key] for key in transport_before}
    transport_ok = (transport_delta[protocol] >= 20 * len(PAYLOAD)
                    and all(value == 0 for key, value in transport_delta.items() if key != protocol))
    return dict(passed=bool(source_matches and sink_ok and transport_ok and outgoing['passed'] and quiet['passed']),
                socket_source_is_tun=source_matches, owned_sink_receipt=marker,
                sink_receipt_after_idle=after_idle, socket_kept_open_during_idle=True,
                outgoing_window=outgoing, idle_window=quiet,
                outgoing_forwarder_delta=forwarder_delta(forwarder_before, endpoint_after_send['local_forwarder_counts']),
                idle_forwarder_delta=forwarder_delta(endpoint_after_send['local_forwarder_counts'], endpoint_after_idle['local_forwarder_counts']),
                response_read_attempted=False, total_payload_bytes=21 * len(PAYLOAD),
                endpoint_transport_bytes=transport_delta,
                sdk_notification_threshold_bytes=102400)


def forwarder_delta(before, after):
    fields = ('tcp_connected', 'tcp_bytes', 'tcp_denied', 'udp_forwarded',
              'udp_replies', 'udp_denied_packets', 'udp_denied_payload_bytes')
    if any(type(value.get(key)) is not int or value[key] < 0
           for value in (before, after) for key in fields):
        raise RuntimeError('invalid_forwarder_totals')
    result = {key: after[key] - before[key] for key in fields}
    if any(value < 0 for value in result.values()):
        raise RuntimeError('invalid_forwarder_totals')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', type=str, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('disposable_windows_required')
    traffic_required = os.environ.get('TRAFFIC_METRICS') == 'true'
    attachment_guard = os.environ.get('ATTACHED_TUN') == 'true'
    owned_probe = os.environ.get('OWNED_PROBE') == 'true'
    owned_probe_mode = os.environ.get('LIWETUN_OWNED_PROBE_MODE', 'echo')
    if owned_probe_mode not in ['echo', 'cancel', 'deadline', 'wrong-nonce', 'migration', 'epoch-change', 'bypass', *HTTPS_MODES] or (owned_probe_mode != 'echo' and not owned_probe):
        raise RuntimeError('invalid_owned_probe_mode')
    cancel_probe = owned_probe and owned_probe_mode == 'cancel'
    negative_probe = owned_probe and owned_probe_mode != 'echo'
    negative_key = {'cancel': 'owned_probe_cancellation', 'deadline': 'owned_probe_deadline',
                    'wrong-nonce': 'owned_probe_wrong_nonce', 'migration': 'owned_probe_migration',
                    'epoch-change': 'owned_probe_epoch_change', 'bypass': 'owned_probe_bypass'}.get(owned_probe_mode)
    if owned_probe_mode in HTTPS_MODES:
        negative_key = 'owned_https'
    if owned_probe and not attachment_guard:
        raise RuntimeError('invalid_owned_probe_mode')
    if attachment_guard and not traffic_required:
        raise RuntimeError('invalid_attachment_guard_mode')
    traffic_pattern = os.environ.get('LIWETUN_TRAFFIC_PATTERN', 'normal')
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
    if traffic_pattern not in ['normal', 'tx-only'] or (traffic_pattern == 'tx-only' and
            (not traffic_required or profile != 'valid' or family != 'ipv4' or termination != 'stop')):
        raise RuntimeError('invalid_traffic_pattern')
    if owned_probe and (profile != 'valid' or family != 'ipv4' or termination != 'stop' or traffic_pattern != 'normal'):
        raise RuntimeError('invalid_owned_probe_mode')
    synthetic_ipv6 = family == 'synthetic-ipv6'
    report = ROOT / 'build/service-evidence/production-network.json'
    report.parent.mkdir(exist_ok=True, parents=True)
    result = {'passed': False, 'mode': 'single_production_unbound_ipv4', 'protocol': protocol,
              'termination': termination, 'traffic_pattern': traffic_pattern,
              'profile': profile,
              'client_family': family,
              'network_test_modes_enabled': attachment_guard, 'routing_test_modes_enabled': False,
              'client_host_routes_added': False,
              'sdk_held_attachment_ci_guard_enabled': attachment_guard,
              'service_owned_socket_ci_probe_enabled': owned_probe,
              'owned_migration_ci_enabled': owned_probe and owned_probe_mode in ['migration', 'https-migration'],
              'owned_bypass_ci_enabled': owned_probe and owned_probe_mode == 'bypass',
              'owned_https_ci_enabled': owned_probe and owned_probe_mode in HTTPS_MODES,
              'owned_probe_mode': owned_probe_mode,
              'attachment_context_proves_endpoint_traversal': False,
              'server_https_egress_bound_physical': True,
              'endpoint_udp_relay': 'wsl_local',
              'endpoint_diagnostic_source_fix': bool(os.environ.get('LIWETUN_ENDPOINT_FIXTURE_RUN')),
              'endpoint_reader_wakeup_candidate': os.environ.get('LIWETUN_ENDPOINT_STREAM_CLOSE') == 'true',
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
    endpoint = forwarder = session = watchdog = wfp_watch = traffic_watch = local_receiver = None
    https_roots = None
    restored = False
    try:
        if owned_probe_mode in HTTPS_MODES:
            from health_tls import generate, FixtureRoots
            generate(directory / 'owned-https')
            https_roots = FixtureRoots()
            https_roots.add(directory / 'owned-https/crl-ca.der')
            https_roots.add_crl(directory / 'owned-https/fixture.crl.der')
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
            'synthetic_ipv6': synthetic_ipv6, 'tx_only': traffic_pattern == 'tx-only',
            'owned_probe': owned_probe, 'owned_probe_mode': owned_probe_mode}))
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
                          '120' if termination == 'endpoint-restart' or traffic_pattern == 'tx-only' else '60'])
        if watchdog.receive() != 'ready':
            raise RuntimeError('watchdog_not_ready')
        before = totals()
        stage = 'production_session'
        profile_file = protocol if profile == 'valid' else profile
        session = Child([str(client), '--network-session', str(directory / (profile_file + '.uri'))])
        if json.loads(session.receive())['code'] not in [0, 6]:
            raise RuntimeError('service_start_rejected')
        if owned_probe_mode == 'bypass':
            stage = 'owned_bypass_receiver_ready'
            local_receiver = owned_bypass_receiver()
        if cancel_probe:
            stage = 'cancel_owned_request_during_receive'
            result['owned_probe_cancellation'] = cancel_owned_request(
                session, endpoint, client.parent / 'owned-probe-context.json')
            session.close()
            session = None
        elif owned_probe_mode in HTTPS_MODES:
            stage = 'owned_https_exchange'
            if owned_probe_mode == 'https-epoch-change':
                result['owned_probe_endpoint_restart'] = restart_during_owned_request(
                    endpoint, client.parent / 'owned-probe-context.json')
            result['owned_https_observation'] = {}
            result['owned_https'] = observe_owned_https(session, endpoint, client.parent, owned_probe_mode,
                                                        result['owned_https_observation'])
            if owned_probe_mode == 'https-cancel':
                session.close()
                session = None
        elif negative_probe:
            stage = {'deadline': 'owned_request_receive_deadline', 'wrong-nonce': 'owned_request_wrong_nonce',
                     'migration': 'owned_request_migration', 'epoch-change': 'owned_request_epoch_change',
                     'bypass': 'owned_request_bypass'}[owned_probe_mode]
            if owned_probe_mode == 'epoch-change':
                result['owned_probe_endpoint_restart'] = restart_during_owned_request(
                    endpoint, client.parent / 'owned-probe-context.json')
            diagnostic_key = negative_key + '_observation'
            result[diagnostic_key] = {}
            result[negative_key] = observe_owned_negative(
                session, endpoint, client.parent / 'owned-probe-context.json',
                result[diagnostic_key], owned_probe_mode, local_receiver)
            if owned_probe_mode == 'bypass':
                endpoint_receiver = endpoint.command('stats')['owned_probe_sink']
                result['owned_bypass_endpoint_receiver'] = endpoint_receiver
                if any(endpoint_receiver[k] != 0 for k in ['valid_requests', 'request_bytes', 'replies_sent', 'reply_bytes']):
                    raise RuntimeError('owned_probe_bypass_not_qualified')
                local_receiver.close() # Release the task-bound listener before SDK adapter removal.
        if negative_probe:
            result['ordinary_https_probe_attempted'] = False
            result['application_dns_probe_attempted'] = False
        info = None
        selected = False
        os.environ['LIWETUN_CI_ORIGIN'] = SYNTHETIC_IPV6 if synthetic_ipv6 else origin
        for _ in range(0 if negative_probe else 20):
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
        if negative_probe:
            traffic_ok = result[negative_key]['qualified']
        elif profile == 'valid':
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
            if traffic_required:
                stage = 'aggregate_traffic_baseline'
                for _ in range(80 if owned_probe else 10):
                    traffic_before = session.command('traffic')
                    if traffic_before.get('flags') == 3:
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('aggregate_traffic_unavailable')
            if owned_probe:
                stage = 'owned_socket_path_evidence'
                from owned_probe_fixture import validate_report, FRAME_BYTES
                with (client.parent / 'owned-probe-context.json').open('rb') as source_file:
                    raw = source_file.read(4097)
                if len(raw) > 4096:
                    raise RuntimeError('invalid_owned_probe_report')
                observation = validate_report(json.loads(raw))
                receiver = endpoint.command('stats')['owned_probe_sink']
                result.update(owned_socket_path=observation, owned_socket_receiver=receiver)
                if not observation['qualified'] or (receiver['valid_requests'] != 1 or receiver['replies_sent'] != 1
                        or receiver['request_bytes'] != FRAME_BYTES or receiver['reply_bytes'] != FRAME_BYTES
                        or receiver['rejected_frames'] != 0):
                    raise RuntimeError('owned_socket_path_not_qualified')
                result.update(owned_socket_path=observation, owned_socket_receiver=receiver,
                              owned_socket_path_qualified=True)
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
        if traffic_required and not negative_probe:
            stage = 'aggregate_traffic_observation'
            traffic_after = session.command('traffic')
            result['aggregate_traffic_after'] = traffic_after
            if profile == 'valid':
                progress = aggregate_progress(traffic_before, traffic_after)
                result.update(aggregate_traffic_before=traffic_before, aggregate_traffic_progress=progress)
                if attachment_guard:
                    # The CI-only backend invalidates every ready counter sample
                    # unless the actual SDK-held context matches under its core lock.
                    # No interface identifiers cross IPC or enter this report.
                    result['sdk_held_attachment_live_context_qualified'] = progress['passed']
                traffic_ok = traffic_ok and progress['passed']
            else:
                unavailable = (not traffic_after.get('flags', 0) & 2
                               and traffic_after.get('tx') is None and traffic_after.get('rx') is None)
                result['aggregate_traffic_unknown_after_refusal'] = unavailable
                traffic_ok = traffic_ok and unavailable
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
            recovery_started = time.monotonic()
            for _ in range(5):
                if time.monotonic() - recovery_started >= 75:
                    break
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
                post_state = session.command('query')
                recovered = recovery_evidence_valid(
                    protocol, post_state['state'], https_ok, https_tun, dns_ok, dns_tun,
                    growth, dns_growth, dns_transport_growth)
                attempts.append({'adapter_present': True,
                                 'state_before': current_state['state'], 'state_after': post_state['state'],
                                 'elapsed_ms': int((time.monotonic() - recovery_started) * 1000),
                                 'https_delivered': https_ok,
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
        if traffic_pattern == 'tx-only':
            stage = 'tx_only_and_idle_counter_windows'
            result['tx_only_fixture'] = observe_tx_only_and_idle(session, addresses, endpoint, protocol)
            traffic_ok = traffic_ok and result['tx_only_fixture']['passed']
        if traffic_required and profile == 'valid' and not negative_probe:
            stage = 'concurrent_traffic_reader'
            traffic_watch = Child([str(client), '--traffic-watch'])
            if traffic_watch.receive() != 'ready':
                raise RuntimeError('aggregate_traffic_watcher_not_ready')
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
        elif session:
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
        if traffic_watch:
            stage = 'concurrent_traffic_reader_completion'
            watched = json.loads(traffic_watch.receive())
            watcher_exit = traffic_watch.process.wait(timeout=15)
            watched['exit_code'] = watcher_exit
            result['aggregate_traffic_concurrent_stop'] = watched
            traffic_ok = (traffic_ok and watcher_exit == 0 and watched.get('passed') is True
                          and watched.get('tunnel_started_by_watcher') is False
                          and watched.get('inactive_after_active', 0) > 0)
        result['passed'] = traffic_ok and restored and wfp_restored
    except Exception as error:
        result['failed_stage'] = stage
        result['error_type'] = type(error).__name__
        reasons = {'wfp_probe_failed', 'fixture_system_command_failed', 'fixture_child_timeout',
                   'fixture_child_closed', 'lease_client_already_exited', 'lease_client_not_forced',
                   'service_crash_not_observed'}
        reasons.update({'owned_probe_not_waiting', 'owned_probe_cancellation_not_qualified',
                        'owned_https_not_waiting', 'owned_https_not_qualified', 'invalid_owned_https_report',
                        'owned_probe_deadline_not_qualified', 'owned_probe_wrong_nonce_not_qualified',
                        'owned_probe_migration_not_qualified',
                        'owned_probe_epoch_change_not_qualified', 'endpoint_restart_failed',
                        'owned_probe_bypass_not_qualified',
                        'owned_bypass_receiver_not_ready',
                        'owned_socket_path_not_qualified', 'invalid_owned_probe_report'})
        reason = error.args[0] if error.args else None
        result['failure_reason'] = reason if isinstance(reason, str) and reason in reasons else 'unknown'
        if reason == 'wfp_probe_failed':
            result['wfp_probe_stage'] = getattr(error, 'wfp_stage', 'unknown')
            result['wfp_query_code'] = getattr(error, 'wfp_query_code', None)
    finally:
        try:
            if local_receiver:
                local_receiver.close()
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
                    watchdog.process.wait(timeout=145 if termination == 'endpoint-restart' or traffic_pattern == 'tx-only' else 85)
                    guard = json.loads((report.parent / 'general-watchdog.json').read_text(encoding='utf-8-sig'))
                    result['deadline_triggered'] = guard['triggered']
                    result['passed'] = result['passed'] and not guard['triggered'] and guard['action_completed']
                except Exception:
                    result['passed'] = False
                    result['deadline_result_unavailable'] = True
                watchdog.close()
            if traffic_watch:
                traffic_watch.close()
            if endpoint and negative_probe:
                try:
                    result['owned_probe_receiver_before_fixture_shutdown'] = endpoint.command('stats')['owned_probe_sink']
                except Exception:
                    result['owned_probe_receiver_observation_unavailable'] = True
            if local_receiver:
                result['owned_bypass_receiver_before_fixture_shutdown'] = local_receiver.stats()
                local_receiver.close()
            if endpoint:
                endpoint.close('quit')
            if forwarder:
                forwarder.close('quit')
            if wfp_watch:
                wfp_watch.close('quit')
            result['routes_dns_adapter_restored'] = wait_clean(baseline)
            result['passed'] = result['passed'] and result['routes_dns_adapter_restored']
        except Exception:
            result['passed'] = False
            result['cleanup_failed'] = True
            result.setdefault('failed_stage', 'fixture_cleanup')
        finally:
            if owned_probe_mode in HTTPS_MODES:
                try:
                    result['owned_https_fixture_roots_removed'] = https_roots.close() if https_roots else False
                except Exception:
                    result['owned_https_fixture_roots_removed'] = False
                result['passed'] = result['passed'] and result['owned_https_fixture_roots_removed']
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
