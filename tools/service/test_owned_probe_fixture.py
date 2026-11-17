import socket
import struct
import time
import unittest
from owned_probe_fixture import (OwnedProbeSink, REQUEST, REPLY, TARGET, validate_report,
                                 validate_cancel_report, validate_deadline_report, validate_wrong_nonce_report,
                                 validate_migration_report, validate_epoch_change_report)
from physical_forwarder import Forwarder
from endpoint_forwarder import EndpointForwarder


class OwnedProbeFixtureTests(unittest.TestCase):
    def test_epoch_change_requires_real_changed_epoch_and_discarded_observations(self):
        value = dict(schema_version=3, stage=9, connected=True, nonexclusive_rejected=True,
                     arm_accepted=True, echo_verified=False, same_instance_epoch=False, state_epoch_changed=True,
                     disarmed=True, cancelled=False, receive_cancelled=False, receive_timed_out=False,
                     snapshot_flags=129, tx_bytes=None, rx_bytes=None, qualified=False,
                     proves_dns=False, proves_https=False, proves_internet=False,
                     identifiers_exported=False, release_ready=False)
        receiver = dict(valid_requests=1, request_bytes=24, replies_sent=0, reply_bytes=0,
                        invalid_replies=0, rejected_frames=0, waiting_for_owner_close=0, owner_closed=1)
        validate_epoch_change_report(value, receiver)
        for flags in [1, 257, 513]:
            validate_epoch_change_report(dict(value, snapshot_flags=flags), receiver)
        for field, replacement in [('state_epoch_changed', False), ('same_instance_epoch', True),
                                   ('echo_verified', True), ('qualified', True), ('disarmed', False),
                                   ('snapshot_flags', 33), ('tx_bytes', 0), ('cancelled', True)]:
            with self.assertRaises(ValueError):
                validate_epoch_change_report(dict(value, **{field: replacement}), receiver)
        with self.assertRaises(ValueError):
            validate_report(dict(value, snapshot_flags=15, tx_bytes=24, rx_bytes=24))

    def test_migration_oracle_requires_invalidated_proof_even_with_valid_reply_and_same_epoch(self):
        value = dict(schema_version=3, stage=9, connected=True, nonexclusive_rejected=True,
                     arm_accepted=True, echo_verified=True, same_instance_epoch=True, state_epoch_changed=False, disarmed=True,
                     cancelled=False, receive_cancelled=False, receive_timed_out=False,
                     snapshot_flags=33, tx_bytes=None, rx_bytes=None, qualified=False,
                     proves_dns=False, proves_https=False, proves_internet=False,
                     identifiers_exported=False, release_ready=False)
        receiver = dict(valid_requests=1, request_bytes=24, replies_sent=1, reply_bytes=24,
                        invalid_replies=0, rejected_frames=0, waiting_for_owner_close=0, owner_closed=1)
        validate_migration_report(value, receiver)
        for field, replacement in [('qualified', True), ('echo_verified', False), ('disarmed', False),
                                   ('same_instance_epoch', False), ('snapshot_flags', 1), ('snapshot_flags', 17),
                                   ('snapshot_flags', 15), ('tx_bytes', 0), ('rx_bytes', 0), ('cancelled', True)]:
            with self.assertRaises(ValueError):
                validate_migration_report(dict(value, **{field: replacement}), receiver)
        for field, replacement in [('invalid_replies', 1), ('replies_sent', 0), ('owner_closed', 0)]:
            with self.assertRaises(ValueError):
                validate_migration_report(value, dict(receiver, **{field: replacement}))

    def test_wrong_nonce_receiver_sends_exact_frame_without_reflecting_token(self):
        receiver = OwnedProbeSink(port=0, mode='wrong-nonce')
        try:
            with socket.create_connection(receiver.address, timeout=1) as client:
                client.sendall(REQUEST + (123).to_bytes(8, 'big'))
                answer = b''
                while len(answer) < 24:
                    part = client.recv(24 - len(answer))
                    self.assertTrue(part)
                    answer += part
                self.assertEqual(answer, REPLY + bytes(8))
            deadline = time.monotonic() + 1
            while receiver.stats()['owner_closed'] != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            counts = receiver.stats()
            self.assertEqual(counts['owner_closed'], 1)
            self.assertEqual(counts['invalid_replies'], 1)
            self.assertEqual(counts['valid_requests'], 1)
            self.assertEqual(counts['reply_bytes'], 24)
        finally:
            receiver.close()

    def test_wrong_nonce_oracle_requires_bidirectional_path_but_no_echo_or_success(self):
        value = dict(schema_version=3, stage=9, connected=True, nonexclusive_rejected=True,
                     arm_accepted=True, echo_verified=False, same_instance_epoch=True, state_epoch_changed=False, disarmed=True,
                     cancelled=False, receive_cancelled=False, receive_timed_out=False,
                     snapshot_flags=15, tx_bytes=24, rx_bytes=24, qualified=False,
                     proves_dns=False, proves_https=False, proves_internet=False,
                     identifiers_exported=False, release_ready=False)
        receiver = dict(valid_requests=1, request_bytes=24, replies_sent=1, reply_bytes=24,
                        invalid_replies=1, rejected_frames=0, waiting_for_owner_close=0, owner_closed=1)
        validate_wrong_nonce_report(value, receiver)
        for field, replacement in [('qualified', True), ('echo_verified', True), ('disarmed', False),
                                   ('same_instance_epoch', False), ('rx_bytes', 0), ('snapshot_flags', 7),
                                   ('cancelled', True), ('receive_timed_out', True)]:
            with self.assertRaises(ValueError):
                validate_wrong_nonce_report(dict(value, **{field: replacement}), receiver)
        for field, replacement in [('invalid_replies', 0), ('reply_bytes', 0), ('owner_closed', 0)]:
            with self.assertRaises(ValueError):
                validate_wrong_nonce_report(value, dict(receiver, **{field: replacement}))

    def test_withheld_response_records_tcp_reset_separately_from_eof(self):
        receiver = OwnedProbeSink(port=0, mode='deadline')
        try:
            with socket.create_connection(receiver.address, timeout=.1) as client:
                client.sendall(REQUEST + (123).to_bytes(8, 'big'))
                with self.assertRaises(socket.timeout):
                    client.recv(24)
                self.assertEqual(receiver.stats()['waiting_for_owner_close'], 1)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            deadline = time.monotonic() + 1
            while receiver.stats()['owner_reset'] != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(receiver.stats()['owner_reset'], 1)
            self.assertEqual(receiver.stats()['owner_closed'], 0)
            self.assertEqual(receiver.stats()['replies_sent'], 0)
        finally:
            receiver.close()

    def test_deadline_oracle_requires_one_sided_endpoint_bytes_and_no_reply_or_cancel(self):
        value = dict(schema_version=3, stage=9, connected=True, nonexclusive_rejected=True,
                     arm_accepted=True, echo_verified=False, same_instance_epoch=True, state_epoch_changed=False, disarmed=True,
                     cancelled=False, receive_cancelled=False, receive_timed_out=True,
                     snapshot_flags=7, tx_bytes=24, rx_bytes=0, qualified=False,
                     proves_dns=False, proves_https=False, proves_internet=False,
                     identifiers_exported=False, release_ready=False)
        receiver = dict(valid_requests=1, request_bytes=24, replies_sent=0, reply_bytes=0,
                        rejected_frames=0, waiting_for_owner_close=0, owner_closed=1)
        validate_deadline_report(value, receiver)
        for field, replacement in [('receive_timed_out', False), ('receive_cancelled', True),
                                   ('cancelled', True), ('disarmed', False), ('same_instance_epoch', False),
                                   ('snapshot_flags', 15), ('tx_bytes', 0), ('rx_bytes', 24),
                                   ('qualified', True), ('echo_verified', True)]:
            with self.assertRaises(ValueError):
                validate_deadline_report(dict(value, **{field: replacement}), receiver)
        for field, replacement in [('reply_bytes', 24), ('owner_closed', 0), ('waiting_for_owner_close', 1)]:
            with self.assertRaises(ValueError):
                validate_deadline_report(value, dict(receiver, **{field: replacement}))

    def test_cancel_receiver_withholds_reply_and_observes_owner_close(self):
        receiver = OwnedProbeSink(port=0, mode='cancel')
        try:
            with socket.create_connection(receiver.address, timeout=.1) as client:
                client.sendall(REQUEST + (123).to_bytes(8, 'big'))
                with self.assertRaises(socket.timeout):
                    client.recv(24)
                self.assertEqual(receiver.stats()['waiting_for_owner_close'], 1)
                self.assertEqual(receiver.stats()['replies_sent'], 0)
            deadline = time.monotonic() + 1
            while receiver.stats()['owner_closed'] != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(receiver.stats()['owner_closed'], 1)
            self.assertEqual(receiver.stats()['request_bytes'], 24)
            self.assertEqual(receiver.stats()['reply_bytes'], 0)
        finally:
            receiver.close()

    def test_cancel_oracle_rejects_timeout_success_echo_or_unclosed_socket(self):
        value = dict(schema_version=3, stage=9, connected=True, nonexclusive_rejected=True,
                     arm_accepted=True, echo_verified=False, same_instance_epoch=False, state_epoch_changed=False, disarmed=True,
                     cancelled=True, receive_cancelled=True, receive_timed_out=False, snapshot_flags=1, tx_bytes=None, rx_bytes=None, qualified=False,
                     proves_dns=False, proves_https=False, proves_internet=False,
                     identifiers_exported=False, release_ready=False)
        receiver = dict(valid_requests=1, request_bytes=24, replies_sent=0, reply_bytes=0,
                        rejected_frames=0, waiting_for_owner_close=0, owner_closed=1)
        validate_cancel_report(value, receiver)
        for field, replacement in [('cancelled', False), ('echo_verified', True), ('arm_accepted', False),
                                   ('snapshot_flags', 7), ('tx_bytes', 24), ('same_instance_epoch', True),
                                   ('disarmed', False), ('receive_cancelled', False)]:
            with self.assertRaises(ValueError):
                validate_cancel_report(dict(value, **{field: replacement}), receiver)
        for field, replacement in [('owner_closed', 0), ('waiting_for_owner_close', 1),
                                   ('replies_sent', 1), ('reply_bytes', 24), ('rejected_frames', 1)]:
            with self.assertRaises(ValueError):
                validate_cancel_report(value, dict(receiver, **{field: replacement}))

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
        value = dict(schema_version=3, stage=9, connected=True, nonexclusive_rejected=True,
                     arm_accepted=True, echo_verified=True, same_instance_epoch=True, state_epoch_changed=False, disarmed=True, cancelled=False, receive_cancelled=False, receive_timed_out=False,
                     snapshot_flags=15, tx_bytes=24, rx_bytes=24, qualified=True, proves_dns=False,
                     proves_https=False, proves_internet=False, identifiers_exported=False, release_ready=False)
        self.assertTrue(validate_report(value)['qualified'])
        for field, replacement in [('snapshot_flags', 17), ('snapshot_flags', 65), ('echo_verified', False),
                                   ('same_instance_epoch', False), ('nonexclusive_rejected', False),
                                   ('rx_bytes', None), ('disarmed', False), ('cancelled', True), ('tx_bytes', True),
                                   ('proves_https', True), ('unexpected', 'never export')]:
            with self.assertRaises(ValueError):
                validate_report(dict(value, **{field: replacement}))
