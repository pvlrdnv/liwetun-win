"""Same-host CI SOCKS5 exit for the unmodified official endpoint.

Only the fixed synthetic account and the task's exact HTTPS/DNS destinations
are accepted. Only server-side egress binds the physical interface; the client
probes remain ordinary unbound sockets. No packet/body/domain logs are retained.
"""
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import threading
import time


def exact(stream, size):
    result = b''
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            raise ConnectionError('closed')
        result += part
    return result


def physical_socket(kind, index):
    stream = socket.socket(socket.AF_INET, kind)
    try:
        stream.setsockopt(socket.IPPROTO_IP, 31, struct.pack('!I', index))
        return stream
    except BaseException:
        stream.close()
        raise


class Forwarder:
    def __init__(self, origin, dns, index, factory=physical_socket, port=38445,
                 udp_bind_host='127.0.0.1'):
        self.origin, self.dns, self.index = origin, dns, index
        self.factory = factory
        self.udp_bind_host = udp_bind_host
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', port))
        self.listener.listen(16)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.slots = threading.BoundedSemaphore(32)
        self.lock = threading.Lock()
        self.counts = dict.fromkeys(['auth_rejected', 'destination_denied', 'tcp_connected',
                                     'tcp_bytes', 'udp_forwarded', 'udp_replies', 'errors', 'active'], 0)

    def count(self, name, amount=1):
        with self.lock:
            self.counts[name] += amount

    def stats(self):
        with self.lock:
            return dict(self.counts)

    def address(self, data):
        kind = exact(data, 1)[0]
        if kind == 1:
            host = socket.inet_ntoa(exact(data, 4))
        elif kind == 3:
            name = exact(data, exact(data, 1)[0]).decode('ascii').lower()
            host = self.origin[0] if name == 'example.com' else ''
        else:
            raise ValueError('unsupported_address')
        return host, struct.unpack('!H', exact(data, 2))[0]

    def authenticate(self, client):
        version, methods = exact(client, 2)
        if version != 5 or not 1 <= methods <= 8 or 2 not in exact(client, methods):
            client.sendall(b'\x05\xff')
            return False
        client.sendall(b'\x05\x02')
        version, length = exact(client, 2)
        user = exact(client, length)
        password = exact(client, exact(client, 1)[0])
        accepted = version == 1 and user == b'synthetic-user' and password == b'synthetic-password'
        client.sendall(b'\x01\x00' if accepted else b'\x01\x01')
        if not accepted:
            self.count('auth_rejected')
        return accepted

    def tcp(self, client, destination):
        if destination != self.origin:
            self.count('destination_denied')
            client.sendall(b'\x05\x02\x00\x01' + b'\x00' * 6)
            return
        with self.connect_tcp(destination) as upstream:
            client.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)
            self.count('tcp_connected')
            deadline = time.monotonic() + 30
            while not self.stop.is_set() and time.monotonic() < deadline:
                readable, _, _ = select.select([client, upstream], [], [], .2)
                for source in readable:
                    chunk = source.recv(16384)
                    if not chunk:
                        return
                    (upstream if source is client else client).sendall(chunk)
                    self.count('tcp_bytes', len(chunk))

    def connect_tcp(self, destination):
        upstream = self.factory(socket.SOCK_STREAM, self.index)
        try:
            upstream.settimeout(8)
            upstream.connect(destination)
            return upstream
        except BaseException:
            upstream.close()
            raise

    def udp(self, client):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay, \
                self.factory(socket.SOCK_DGRAM, self.index) as upstream:
            relay.bind((self.udp_bind_host, 0))
            relay.settimeout(2)
            upstream.settimeout(2)
            port = relay.getsockname()[1]
            client.sendall(b'\x05\x00\x00\x01' + socket.inet_aton(self.udp_bind_host) + struct.pack('!H', port))
            deadline = time.monotonic() + 30
            while not self.stop.is_set() and time.monotonic() < deadline:
                readable, _, _ = select.select([client, relay], [], [], .2)
                if client in readable:
                    return  # The control connection's lifetime owns association.
                if relay not in readable:
                    continue
                packet, sender = relay.recvfrom(4106)
                if sender[0] not in ('127.0.0.1', self.udp_bind_host) or len(packet) < 10 or packet[:4] != b'\x00\x00\x00\x01':
                    self.count('destination_denied')
                    continue
                destination = socket.inet_ntoa(packet[4:8]), struct.unpack('!H', packet[8:10])[0]
                if destination != self.dns:
                    self.count('destination_denied')
                    continue
                upstream.sendto(packet[10:], destination)
                self.count('udp_forwarded')
                answer, address = upstream.recvfrom(4096)
                if address == self.dns:
                    relay.sendto(packet[:10] + answer, sender)
                    self.count('udp_replies')

    def handle(self, client):
        self.count('active')
        try:
            with client:
                client.settimeout(10)
                if not self.authenticate(client):
                    return
                version, command, reserved = exact(client, 3)
                destination = self.address(client)
                if version != 5 or reserved != 0:
                    raise ValueError('invalid_header')
                if command == 1:
                    self.tcp(client, destination)
                elif command == 3:
                    self.udp(client)
                else:
                    client.sendall(b'\x05\x07\x00\x01' + b'\x00' * 6)
        except (OSError, ValueError):
            self.count('errors')
        finally:
            self.count('active', -1)
            self.slots.release()

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def close(self):
        self.stop.set()
        self.listener.close()


def main():
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('disposable_windows_required')
    directory = Path(sys.argv[1]).resolve()
    expected = Path(__file__).resolve().parents[2] / 'build/network-fixture'
    if directory != expected.resolve():
        raise RuntimeError('fixed_fixture_directory_required')
    data = json.loads((directory / 'forwarder-inputs.json').read_text())
    origin = ipaddress.IPv4Address(data['origin'])
    dns = ipaddress.IPv4Address(data['dns_host'])
    index = data['physical_index']
    if not origin.is_global or not dns.is_private or dns.is_loopback or type(index) is not int or not 1 <= index <= 0xffffffff:
        raise RuntimeError('invalid_fixture_inputs')
    # WSL1's connected UDP uses the same-host private address for both directions.
    # TCP control remains loopback-only; no public UDP source is admitted.
    proxy = Forwarder((str(origin), 443), (str(dns), 38553), index, udp_bind_host=str(dns))
    thread = threading.Thread(target=proxy.serve, daemon=True)
    thread.start()
    try:
        print('ready', flush=True)
        for command in sys.stdin:
            if command.strip() != 'stats':
                break
            print(json.dumps(proxy.stats()), flush=True)
    finally:
        proxy.close()
        thread.join(timeout=2)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('fixture_failed', flush=True)
        raise SystemExit(2) from None
