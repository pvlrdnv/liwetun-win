"""CI Linux-local UDP relay; HTTPS chains to the Windows physical exit.

The only direct UDP destination is the same-host private synthetic DNS fixture.
The production harness must verify its private route stays physical. This keeps
endpoint UDP sockets/relay in WSL1 while preserving the original client routes.
"""
import socket
import struct

from physical_forwarder import Forwarder, exact


def local_socket(kind, _index):
    return socket.socket(socket.AF_INET, kind)


class EndpointForwarder(Forwarder):
    def __init__(self, *args, physical_exit=('127.0.0.1', 38445), **kwargs):
        super().__init__(*args, **kwargs)
        self.physical_exit = physical_exit

    def connect_tcp(self, destination):
        upstream = socket.create_connection(self.physical_exit, timeout=8)
        try:
            upstream.sendall(b'\x05\x01\x02')
            if exact(upstream, 2) != b'\x05\x02':
                raise ValueError('physical_exit_auth_method')
            user, password = b'synthetic-user', b'synthetic-password'
            upstream.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
            if exact(upstream, 2) != b'\x01\x00':
                raise ValueError('physical_exit_auth_denied')
            upstream.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(destination[0])
                             + struct.pack('!H', destination[1]))
            if exact(upstream, 10)[:4] != b'\x05\x00\x00\x01':
                raise ValueError('physical_exit_connect_denied')
            return upstream
        except BaseException:
            upstream.close()
            raise
