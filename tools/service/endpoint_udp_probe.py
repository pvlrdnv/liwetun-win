"""Fixed synthetic UDP wire probe of the official endpoint, before SDK start.

This is a CI diagnostic, not a connection adapter. HTTP/1 CONNECT _udp2 and
fixed-size IPv4 framing follow the pinned endpoint's http_udp_codec.rs.
Only closed observations are returned, never credentials/frames/core output.
"""
import base64
import ipaddress
import socket
import ssl
import struct
import time

from physical_forwarder import exact


def probe(directory, sources=(40000,)):
    result = dict(tls_verified=False, connect_accepted=False, frame_received=False,
                  metadata_matches=False, synthetic_answer=False, completed_flows=0, passed=False)
    target = ipaddress.IPv4Address((directory / 'dns-host.txt').read_text().strip())
    if not target.is_private or target.is_loopback:
        return result
    source = ipaddress.IPv4Address('198.18.0.2')
    question = b'\x07liwetun\x07invalid\x00\x00\x01\x00\x01'
    packet = b'\x37\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question
    target_wire = b'\x00' * 12 + target.packed + struct.pack('!H', 38553)
    context = ssl.create_default_context(cafile=str(directory / 'cert.pem'))
    context.set_alpn_protocols(['http/1.1'])
    try:
        with socket.create_connection(('127.0.0.1', 38443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname='localhost') as tls:
                result['tls_verified'] = True
                auth = base64.b64encode(b'synthetic-user:synthetic-password')
                tls.sendall(b'CONNECT _udp2 HTTP/1.1\r\nHost: _udp2\r\nProxy-Authorization: Basic '
                            + auth + b'\r\n\r\n')
                response = b''
                while not response.endswith(b'\r\n\r\n') and len(response) < 4096:
                    response += exact(tls, 1)
                result['connect_accepted'] = response.startswith(b'HTTP/1.1 200') and response.endswith(b'\r\n\r\n')
                if not result['connect_accepted']:
                    return result
                expected = (packet[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + question
                            + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x7b')
                for port in sources:
                    source_wire = b'\x00' * 12 + source.packed + struct.pack('!H', port)
                    frame = source_wire + target_wire + b'\x00' + packet
                    tls.sendall(struct.pack('!I', len(frame)) + frame)
                    length = struct.unpack('!I', exact(tls, 4))[0]
                    if not 36 <= length <= 4096:
                        return result
                    answer = exact(tls, length)
                    result['frame_received'] = True
                    result['metadata_matches'] = answer[:36] == target_wire + source_wire
                    result['synthetic_answer'] = answer[36:] == expected
                    if not result['metadata_matches'] or not result['synthetic_answer']:
                        return result
                    result['completed_flows'] += 1
                    time.sleep(.1)  # Let the first idle UDP socket return to polling.
                result['passed'] = all(value for key, value in result.items() if key != 'passed')
    except OSError as error:
        result.update(os_code=error.errno, timed_out=isinstance(error, TimeoutError))
    return result
