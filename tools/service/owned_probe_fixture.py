"""Synthetic owned-socket receiver; fixed frames, loopback only, closed totals."""
import socket
import threading
import time

TARGET = ('198.18.0.10', 38556)
REQUEST = b'liwetun-path-v1:'
REPLY = b'liwetun-path-ok:'
FRAME_BYTES = 24
assert len(REQUEST) == len(REPLY) == 16


class OwnedProbeSink:
    def __init__(self, port=38556, mode='echo'):
        if mode not in ['echo', 'cancel', 'deadline']:
            raise ValueError('invalid_owned_probe_mode')
        self.mode = mode
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', port))
        self.socket.listen(4)
        self.socket.settimeout(.2)
        self.address = self.socket.getsockname()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = dict(accepted=0, request_bytes=0, valid_requests=0,
                           replies_sent=0, reply_bytes=0, rejected_frames=0,
                           waiting_for_owner_close=0, owner_closed=0, owner_reset=0)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def count(self, key, value=1):
        with self.lock:
            self.counts[key] += value

    def stats(self):
        with self.lock:
            return dict(self.counts)

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.count('accepted')
            with client:
                client.settimeout(.2)
                packet = b''
                deadline = time.monotonic() + 2
                try:
                    while len(packet) < FRAME_BYTES and not self.stop.is_set() and time.monotonic() < deadline:
                        try:
                            part = client.recv(FRAME_BYTES - len(packet))
                        except socket.timeout:
                            continue
                        if not part:
                            break
                        packet += part
                        self.count('request_bytes', len(part))
                    if not packet:
                        continue # Connected exclusive-port negative control sends nothing.
                    if (len(packet) != FRAME_BYTES or not packet.startswith(REQUEST)
                            or int.from_bytes(packet[16:], 'big') == 0):
                        self.count('rejected_frames')
                        continue
                    self.count('valid_requests')
                    if self.mode != 'echo':
                        # Deliberately withhold every response. The controller
                        # must Stop while the service is blocked in receive.
                        self.count('waiting_for_owner_close')
                        hold = time.monotonic() + 8
                        try:
                            while not self.stop.is_set() and time.monotonic() < hold:
                                try:
                                    extra = client.recv(1)
                                except socket.timeout:
                                    continue
                                except ConnectionResetError:
                                    self.count('owner_reset')
                                    break
                                if not extra:
                                    self.count('owner_closed')
                                else:
                                    self.count('rejected_frames')
                                break
                        finally:
                            self.count('waiting_for_owner_close', -1)
                        continue
                    response = REPLY + packet[16:]
                    client.sendall(response)
                    self.count('replies_sent')
                    self.count('reply_bytes', len(response))
                    # Keep the socket connected until the owner reads the SDK
                    # evidence and closes it. No unsolicited payload is sent.
                    hold = time.monotonic() + 2
                    while not self.stop.is_set() and time.monotonic() < hold:
                        try:
                            extra = client.recv(1)
                        except socket.timeout:
                            continue
                        if extra:
                            self.count('rejected_frames')
                        break
                except OSError:
                    continue

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)


def validate_report(value):
    boolean_fields = {'connected', 'nonexclusive_rejected', 'arm_accepted', 'echo_verified',
                      'same_instance_epoch', 'disarmed', 'cancelled', 'receive_cancelled', 'receive_timed_out', 'qualified', 'proves_dns',
                      'proves_https', 'proves_internet', 'identifiers_exported', 'release_ready'}
    expected = boolean_fields | {'schema_version', 'stage', 'snapshot_flags', 'tx_bytes', 'rx_bytes'}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('invalid_owned_probe_report')
    if any(type(value[key]) is not bool for key in boolean_fields):
        raise ValueError('invalid_owned_probe_report')
    if (type(value['schema_version']) is not int or value['schema_version'] != 2
            or type(value['stage']) is not int or not 1 <= value['stage'] <= 9
            or type(value['snapshot_flags']) is not int or not 1 <= value['snapshot_flags'] <= 1023):
        raise ValueError('invalid_owned_probe_report')
    for key in ['tx_bytes', 'rx_bytes']:
        n = value[key]
        if n is not None and (type(n) is not int or not 0 <= n <= 2**63 - 1):
            raise ValueError('invalid_owned_probe_report')
    flags = value['snapshot_flags']
    if not flags & 1:
        raise ValueError('invalid_owned_probe_report')
    if flags & 2:
        if (flags & ~15 or any(type(value[k]) is not int for k in ['tx_bytes', 'rx_bytes'])
                or (value['tx_bytes'] > 0) != bool(flags & 4) or (value['rx_bytes'] > 0) != bool(flags & 8)):
            raise ValueError('invalid_owned_probe_report')
    elif value['tx_bytes'] is not None or value['rx_bytes'] is not None:
        raise ValueError('invalid_owned_probe_report')
    if any(value[key] for key in ['proves_dns', 'proves_https', 'proves_internet', 'identifiers_exported', 'release_ready']):
        raise ValueError('invalid_owned_probe_report')
    if value['qualified'] and not (
            value['stage'] == 9 and not value['cancelled'] and not value['receive_cancelled']
            and not value['receive_timed_out'] and value['snapshot_flags'] == 15
            and all(value[key] for key in ['connected', 'nonexclusive_rejected', 'arm_accepted',
                                            'echo_verified', 'same_instance_epoch', 'disarmed'])
            and all(type(value[key]) is int and value[key] >= FRAME_BYTES for key in ['tx_bytes', 'rx_bytes'])):
        raise ValueError('invalid_owned_probe_report')
    return value


def validate_cancel_report(value, receiver):
    validate_report(value)
    if not (value['stage'] == 9 and value['connected'] and value['nonexclusive_rejected']
            and value['arm_accepted'] and value['disarmed'] and value['cancelled'] and value['receive_cancelled']
            and not value['qualified'] and not value['receive_timed_out']
            and not value['echo_verified'] and not value['same_instance_epoch']
            and value['snapshot_flags'] == 1 and value['tx_bytes'] is None and value['rx_bytes'] is None
            and receiver['valid_requests'] == 1 and receiver['request_bytes'] == FRAME_BYTES
            and receiver['replies_sent'] == 0 and receiver['reply_bytes'] == 0
            and receiver['rejected_frames'] == 0 and receiver['owner_closed'] == 1
            and receiver['waiting_for_owner_close'] == 0):
        raise ValueError('owned_probe_cancellation_not_qualified')
    return value


def validate_deadline_report(value, receiver):
    validate_report(value)
    if not (value['stage'] == 9 and value['connected'] and value['nonexclusive_rejected']
            and value['arm_accepted'] and value['disarmed'] and value['same_instance_epoch']
            and value['receive_timed_out'] and not value['receive_cancelled'] and not value['cancelled']
            and not value['qualified'] and not value['echo_verified'] and value['snapshot_flags'] == 7
            and value['tx_bytes'] == FRAME_BYTES and value['rx_bytes'] == 0
            and receiver['valid_requests'] == 1 and receiver['request_bytes'] == FRAME_BYTES
            and receiver['replies_sent'] == 0 and receiver['reply_bytes'] == 0
            and receiver['rejected_frames'] == 0 and receiver['owner_closed'] == 1
            and receiver['waiting_for_owner_close'] == 0):
        raise ValueError('owned_probe_deadline_not_qualified')
    return value
