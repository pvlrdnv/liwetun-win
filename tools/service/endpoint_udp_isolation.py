"""Disposable Linux control for endpoint UDP, with no SDK/TUN/routes involved."""
import ipaddress
import json
import os
import socket
import subprocess
import sys

from endpoint_udp_probe import probe
from network import Child, ROOT


def main():
    if not sys.platform.startswith('linux') or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('disposable_linux_required')
    directory = ROOT / 'build/network-fixture'
    directory.mkdir(parents=True)
    report = ROOT / 'build/endpoint-evidence/udp-isolation.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    result = dict(passed=False, mode='linux_endpoint_only_two_udp_flows_no_sdk_no_tun',
                  endpoint_version=os.environ['LIWETUN_ENDPOINT_VERSION'], release_ready=False)
    result['diagnostic_source_fix'] = os.environ.get('LIWETUN_ENDPOINT_SOURCE_FIX') == 'true'
    endpoint = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(('198.51.100.1', 9))  # Source selection only; no send.
            host = ipaddress.IPv4Address(route.getsockname()[0])
        if not host.is_private or host.is_loopback:
            raise RuntimeError('private_task_address_required')
        (directory / 'dns-host.txt').write_text(str(host))
        # TCP is unused in this UDP control; no Windows exit is running.
        (directory / 'forwarder-inputs.json').write_text(json.dumps(
            dict(origin='1.1.1.1', dns_host=str(host), physical_index=0)))
        command = [sys.executable, str(ROOT / 'tools/service/endpoint_fixture.py'),
                   str(directory), str(ROOT / 'build/endpoint/trusttunnel_endpoint')]
        subprocess.run(command + ['prepare'], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)
        endpoint = Child(command + ['http2'])
        if endpoint.receive() != 'ready':
            raise RuntimeError('endpoint_not_ready')
        result['wire_probe'] = probe(directory, sources=(40000, 40001))
        result['fixture_counts'] = endpoint.command('stats')
        result['passed'] = result['wire_probe']['passed']
    except Exception:
        result['setup_or_probe_failed'] = True
    finally:
        if endpoint:
            endpoint.close('quit')
        report.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
