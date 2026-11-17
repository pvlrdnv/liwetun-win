import socket
import unittest
from owned_probe_fixture import OwnedProbeSink, REQUEST, REPLY, TARGET, validate_report
from physical_forwarder import Forwarder
from endpoint_forwarder import EndpointForwarder


class OwnedProbeFixtureTests(unittest.TestCase):
    def test_fixed_nonce_echo_is_exact_and_listener_is_loopback_only(self):
        receiver = OwnedProbeSink(port=0)
        try:
            self.assertEqual(receiver.address[0], '127.0.0.1')
            with socket.create_connection(receiver.address, timeout=1) as client:
                marker = (123).to_bytes(8, 'big')
                client.sendall(REQUEST[:3])
                client.sendall(REQUEST[3:] + marker)
                answer = b''
                while len(answer) < 24:
                    part = client.recv(24 - len(answer))
                    self.assertTrue(part)
                    answer += part
                self.assertEqual(answer, REPLY + marker)
                self.assertEqual(receiver.stats()['valid_requests'], 1)
                self.assertEqual(receiver.stats()['rejected_frames'], 0)
        finally:
            receiver.close()

    def test_wrong_or_zero_nonce_frame_cannot_receive_a_successful_reply(self):
        receiver = OwnedProbeSink(port=0)
        try:
            for frame in [b'X' * 24, REQUEST + b'\x00' * 8]:
                with socket.create_connection(receiver.address, timeout=1) as client:
                    client.sendall(frame)
                    self.assertEqual(client.recv(24), b'')
            self.assertEqual(receiver.stats()['valid_requests'], 0)
            self.assertEqual(receiver.stats()['rejected_frames'], 2)
        finally:
            receiver.close()

    def test_extra_destination_requires_explicit_local_fixture_mode(self):
        base = Forwarder(('127.0.0.1', 1), ('127.0.0.1', 2), 0, port=0)
        disabled = EndpointForwarder(('127.0.0.1', 1), ('127.0.0.1', 2), 0, port=0)
        enabled = EndpointForwarder(('127.0.0.1', 1), ('127.0.0.1', 2), 0, port=0, owned_probe=True)
        try:
            self.assertFalse(base.tcp_allowed(TARGET))
            self.assertFalse(disabled.tcp_allowed(TARGET))
            self.assertTrue(enabled.tcp_allowed(TARGET))
            self.assertFalse(enabled.tcp_allowed(('198.18.0.11', TARGET[1])))
        finally:
            for proxy in [base, disabled, enabled]:
                proxy.close()

    def test_success_oracle_rejects_bypass_expiry_unknown_epoch_and_unverified_response(self):
        value = dict(schema_version=1, stage=9, connected=True, nonexclusive_rejected=True,
                     arm_accepted=True, echo_verified=True, same_instance_epoch=True, disarmed=True, cancelled=False,
                     snapshot_flags=15, tx_bytes=24, rx_bytes=24, qualified=True, proves_dns=False,
                     proves_https=False, proves_internet=False, identifiers_exported=False, release_ready=False)
        self.assertTrue(validate_report(value)['qualified'])
        for field, replacement in [('snapshot_flags', 17), ('snapshot_flags', 65), ('echo_verified', False),
                                   ('same_instance_epoch', False), ('nonexclusive_rejected', False),
                                   ('rx_bytes', None), ('disarmed', False), ('cancelled', True), ('tx_bytes', True),
                                   ('proves_https', True), ('unexpected', 'never export')]:
            with self.assertRaises(ValueError):
                validate_report(dict(value, **{field: replacement}))
