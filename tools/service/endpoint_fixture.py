"""Real pinned endpoint plus deterministic DNS fixture, disposable WSL1 only.

No replacement tunnel implementation. Raw endpoint output is discarded. TLS
material/credentials are synthetic and remain in the CI task directory.
"""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading
import time
import sys
import ipaddress
import re


def owned_udp_queues(process):
    """Aggregate only this child endpoint's UDP queues, never addresses/inodes."""
    observation = {'available': False, 'sockets': None, 'rx_kernel_bytes': None}
    try:
        descriptors = list(Path(f'/proc/{process.pid}/fd').iterdir())
        if len(descriptors) > 512:
            return observation
        inodes = set()
        for descriptor in descriptors:
            try:
                match = re.fullmatch(r'socket:\[([0-9]+)\]', str(descriptor.readlink()))
                if match:
                    inodes.add(match[1])
            except FileNotFoundError:
                continue
        count = queued = 0
        for name in ['udp', 'udp6']:
            with Path('/proc/net', name).open() as table:
                rows = table.read(1048577)
            if len(rows) > 1048576:
                return observation
            for row in rows.splitlines()[1:]:
                columns = row.split()
                if len(columns) > 9 and columns[9] in inodes:
                    count += 1
                    queued += int(columns[4].split(':')[1], 16)
        observation.update(available=True, sockets=count, rx_kernel_bytes=queued)
    except (OSError, ValueError, IndexError):
        pass
    return observation


def dns_server(stop, counters, sock):
    with sock:
        sock.settimeout(.2)
        while not stop.is_set():
            try:
                packet, address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            counters['requests'] += 1
            counters['request_bytes'] += len(packet)
            if len(packet) < 12 or packet[2] & 0x80:
                counters['non_questions'] += 1
                continue
            # Exact synthetic A question only. No upstream DNS/public query.
            question = b'\x07liwetun\x07invalid\x00\x00\x01\x00\x01'
            # DnsLibs may append EDNS records. Match the single exact question;
            # optional additional records do not change this fixture's answer.
            if packet[4:6] == b'\x00\x01' and packet[12:12 + len(question)] == question:
                response = packet[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
                response += question + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x7b'
                sock.sendto(response, address)
                counters['synthetic_answers'] += 1
            elif packet[4:6] == b'\x00\x01':
                # Deterministically reject unrelated runner DNS instead of
                # provoking retries. Retain only counts, never question names.
                end = 12
                while end < min(len(packet), 268) and 0 < packet[end] <= 63:
                    end += packet[end] + 1
                if end + 5 <= len(packet) and packet[end] == 0:
                    response = packet[:2] + b'\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00' + packet[12:end + 5]
                    sock.sendto(response, address)
                    counters['other_answers'] += 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('binary', type=Path)
    parser.add_argument('protocol', choices=['prepare', 'http2', 'http3'])
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(exist_ok=True, parents=True)
    if args.protocol == 'prepare':
        for prefix in ['', 'wrong-']:
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                '-keyout', str(directory / (prefix + 'key.pem')),
                '-out', str(directory / (prefix + 'cert.pem')),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (directory / (prefix + 'key.pem')).chmod(0o600)
            subprocess.run(['openssl', 'x509', '-in', str(directory / (prefix + 'cert.pem')),
                            '-outform', 'DER', '-out', str(directory / (prefix + 'cert.der'))],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    (directory / 'credentials.toml').write_text('[[client]]\nusername="synthetic-user"\npassword="synthetic-password"\n')
    protocol = 'http2' if args.protocol == 'http2' else 'quic'
    forwarder = ''
    if (directory / 'forwarder-inputs.json').exists():
        forwarder = '[forward_protocol.socks5]\naddress="127.0.0.1:38445"\nextended_auth=false\n'
    # H3 case deliberately has NO H2 listener: fallback cannot pass the test.
    (directory / 'vpn.toml').write_text(
        'listen_address="127.0.0.1:38443"\ncredentials_file="credentials.toml"\n'
        'ipv6_available=false\nallow_private_network_connections=true\n'
        'connection_establishment_timeout_secs=5\n'
        + forwarder +
        f'[listen_protocols.http1]\n[listen_protocols.{protocol}]\n'
        '[metrics]\naddress="127.0.0.1:38444"\nper_client_metrics=false\n')
    (directory / 'hosts.toml').write_text(
        '[[main_hosts]]\nhostname="localhost"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
    stop = threading.Event()
    counters = {'requests': 0, 'request_bytes': 0, 'synthetic_answers': 0, 'other_answers': 0, 'non_questions': 0}
    dns_host = '127.0.0.1'
    if (directory / 'dns-host.txt').exists():
        address = ipaddress.IPv4Address((directory / 'dns-host.txt').read_text().strip())
        if not address.is_private or address.is_loopback:
            raise RuntimeError('task_private_dns_address_required')
        dns_host = str(address)
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind((dns_host, 38553))
    worker = threading.Thread(target=dns_server, args=(stop, counters, dns_socket), daemon=True)
    worker.start()
    endpoint = subprocess.Popen([str(args.binary.resolve()), 'vpn.toml', 'hosts.toml', '--jobs', '2'],
                                cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if endpoint.poll() is not None:
                raise RuntimeError('endpoint_exited')
            try:
                with socket.create_connection(('127.0.0.1', 38444), timeout=.1):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('endpoint_not_ready')
        print('ready', flush=True)
        for command in sys.stdin:
            if command.strip() == 'stats':
                observation = dict(counters)
                if forwarder:
                    observation['owned_endpoint_udp_queues'] = owned_udp_queues(endpoint)
                print(json.dumps(observation), flush=True)
            else:
                break
    finally:
        stop.set()
        endpoint.terminate()
        try:
            endpoint.wait(timeout=5)
        except subprocess.TimeoutExpired:
            endpoint.kill()
            endpoint.wait(timeout=5)
        worker.join(timeout=1)


if __name__ == '__main__':
    main()
