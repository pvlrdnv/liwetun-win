"""Connected WSL1 -> Windows SOCKS5 UDP -> synthetic DNS boundary preflight.

Only closed observations are emitted; no socket addresses or packet data.
The production harness invokes this before starting the SDK or changing routes.
"""
import ipaddress
import json
from pathlib import Path
import socket
import select
import struct
import sys

from physical_forwarder import exact


def probe(directory):
    host = ipaddress.IPv4Address((directory / 'dns-host.txt').read_text().strip())
    if not host.is_private or host.is_loopback:
        raise ValueError('invalid_fixture_address')
    result = dict(authenticated=False, associated=False, reply_received=False,
                  relay_source_matches=False, synthetic_answer=False,
                  poll_readable=False, passed=False)
    try:
        with socket.create_connection(('127.0.0.1', 38445), timeout=3) as control:
            control.sendall(b'\x05\x01\x02')
            if exact(control, 2) != b'\x05\x02':
                return result
            user, password = b'synthetic-user', b'synthetic-password'
            control.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
            result['authenticated'] = exact(control, 2) == b'\x01\x00'
            if not result['authenticated']:
                return result
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(('0.0.0.0', 0))
                control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 4 + struct.pack('!H', udp.getsockname()[1]))
                reply = exact(control, 10)
                result['associated'] = reply[:4] == b'\x05\x00\x00\x01'
                if not result['associated']:
                    return result
                relay_host = socket.inet_ntoa(reply[4:8])
                if relay_host not in ('127.0.0.1', str(host)):
                    return result
                udp.settimeout(3)
                relay = relay_host, struct.unpack('!H', reply[8:10])[0]
                udp.connect(relay)
                header = b'\x00\x00\x00\x01' + host.packed + struct.pack('!H', 38553)
                question = b'\x07liwetun\x07invalid\x00\x00\x01\x00\x01'
                packet = b'\x37\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question
                udp.send(header + packet)
                # Check edge-triggered epoll readiness, as used by Tokio/mio.
                # Blocking recv alone would not establish reactor readiness.
                with select.epoll() as reactor:
                    reactor.register(udp.fileno(), select.EPOLLIN | select.EPOLLET)
                    result['poll_readable'] = bool(reactor.poll(timeout=3))
                answer, sender = udp.recvfrom(4096)
                result['reply_received'] = True
                result['relay_source_matches'] = sender == relay
                expected = (header + packet[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
                            + question + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x7b')
                result['synthetic_answer'] = answer == expected
                result['passed'] = all(value for key, value in result.items() if key != 'passed')
    except (OSError, ValueError) as error:
        result['os_code'] = error.errno if isinstance(error, OSError) else None
    return result


if __name__ == '__main__':
    try:
        observation = probe(Path(sys.argv[1]))
    except Exception:
        observation = {'passed': False, 'preflight_inputs_valid': False}
    print(json.dumps(observation), flush=True)
    raise SystemExit(0 if observation['passed'] else 2)
