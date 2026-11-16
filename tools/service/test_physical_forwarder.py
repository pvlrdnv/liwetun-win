"""Live loopback protocol checks; no public hosts or route/DNS changes."""
from contextlib import contextmanager
import socket
import struct
import threading
import unittest

from physical_forwarder import Forwarder, exact
from endpoint_forwarder import EndpointForwarder


def local_socket(kind, _index):
    return socket.socket(socket.AF_INET, kind)


@contextmanager
def echo(kind):
    server = socket.socket(socket.AF_INET, kind)
    server.bind(('127.0.0.1', 0))
    address = server.getsockname()
    if kind == socket.SOCK_STREAM:
        server.listen(1)
    server.settimeout(.1)
    stopped = threading.Event()
    def serve():
        while not stopped.is_set():
            try:
                if kind == socket.SOCK_STREAM:
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(2)
                        connection.sendall(b'ack:' + connection.recv(4096))
                else:
                    packet, sender = server.recvfrom(4096)
                    server.sendto(b'ack:' + packet, sender)
            except socket.timeout:
                continue
            except OSError:
                return
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield address
    finally:
        stopped.set()
        server.close()
        thread.join(timeout=3)


class ForwarderTest(unittest.TestCase):
    def setUp(self):
        self.forwarders = []

    def tearDown(self):
        for proxy, thread in self.forwarders:
            proxy.close()
            thread.join(timeout=3)

    def start(self, origin=('127.0.0.1', 1), dns=('127.0.0.1', 2), kind=Forwarder, **kwargs):
        proxy = kind(origin, dns, 1, factory=local_socket, port=0, **kwargs)
        thread = threading.Thread(target=proxy.serve, daemon=True)
        thread.start()
        self.forwarders.append((proxy, thread))
        return proxy

    def authenticate(self, proxy, password=b'synthetic-password'):
        client = socket.create_connection(('127.0.0.1', proxy.port), timeout=2)
        self.addCleanup(client.close)
        client.sendall(b'\x05\x01\x02')
        self.assertEqual(exact(client, 2), b'\x05\x02')
        user = b'synthetic-user'
        client.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        result = exact(client, 2)
        return client, result

    def test_authenticated_domain_connect_delivers_bytes(self):
        with echo(socket.SOCK_STREAM) as address:
            proxy = self.start(origin=address)
            client, result = self.authenticate(proxy)
            self.assertEqual(result, b'\x01\x00')
            client.sendall(b'\x05\x01\x00\x03\x0bexample.com' + struct.pack('!H', address[1]))
            self.assertEqual(exact(client, 10)[:2], b'\x05\x00')
            client.sendall(b'fixture-data')
            self.assertEqual(exact(client, 16), b'ack:fixture-data')
            self.assertEqual(proxy.stats()['tcp_connected'], 1)

    def test_wrong_password_never_opens_destination(self):
        proxy = self.start()
        _, result = self.authenticate(proxy, b'wrong-synthetic-password')
        self.assertEqual(result, b'\x01\x01')
        self.assertEqual(proxy.stats()['tcp_connected'], 0)

    def test_local_relay_chains_authenticated_tcp_exit(self):
        with echo(socket.SOCK_STREAM) as address:
            physical = self.start(origin=address)
            local = self.start(origin=address, kind=EndpointForwarder,
                               physical_exit=('127.0.0.1', physical.port))
            client, result = self.authenticate(local)
            self.assertEqual(result, b'\x01\x00')
            client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(address[0]) + struct.pack('!H', address[1]))
            self.assertEqual(exact(client, 10)[:2], b'\x05\x00')
            client.sendall(b'fixture-data')
            self.assertEqual(exact(client, 16), b'ack:fixture-data')
            self.assertEqual(physical.stats()['tcp_connected'], 1)
            self.assertEqual(local.stats()['tcp_connected'], 1)

    def test_unlisted_tcp_destination_denied(self):
        proxy = self.start()
        client, _ = self.authenticate(proxy)
        client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x03')
        self.assertEqual(exact(client, 10)[:2], b'\x05\x02')
        self.assertEqual(proxy.stats()['destination_denied'], 1)
        self.assertEqual(proxy.stats()['tcp_connected'], 0)

    def test_udp_association_delivers_and_rejects_fragments(self):
        with echo(socket.SOCK_DGRAM) as address:
            proxy = self.start(dns=address)
            client, _ = self.authenticate(proxy)
            client.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
            reply = exact(client, 10)
            self.assertEqual(reply[:4], b'\x05\x00\x00\x01')
            relay = socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:10])[0]
            header = b'\x00\x00\x00\x01' + socket.inet_aton(address[0]) + struct.pack('!H', address[1])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(2)
                udp.connect(relay)  # Match the official endpoint's connected UDP.
                udp.send(header + b'dns-fixture')
                self.assertEqual(udp.recv(4096), header + b'ack:dns-fixture')
                udp.settimeout(.3)
                udp.send(b'\x00\x00\x01' + header[3:] + b'dns-fixture')
                with self.assertRaises(socket.timeout):
                    udp.recv(4096)
            self.assertEqual(proxy.stats()['udp_forwarded'], 1)
            self.assertEqual(proxy.stats()['udp_replies'], 1)


if __name__ == '__main__':
    unittest.main()
