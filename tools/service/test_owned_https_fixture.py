import copy
from pathlib import Path
import socket
import ssl
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from owned_https_fixture import OwnedHttpsSink, REQUEST_HEADERS, HEADERS, validate_https_report
from health_tls import generate
from network import Child
from production_network import observe_owned_https


def reports():
    path = dict(schema_version=4, stage=9, socket_failure=0, connected=True, nonexclusive_rejected=True,
                arm_accepted=True, echo_verified=True, same_instance_epoch=True, state_epoch_changed=False,
                disarmed=True, cancelled=False, receive_cancelled=False, receive_timed_out=False,
                snapshot_flags=15, tx_bytes=1000, rx_bytes=3000, qualified=True,
                proves_dns=False, proves_https=False, proves_internet=False, identifiers_exported=False, release_ready=False)
    tls = dict(schema_version=1, tls_result=0, http_result=1, handshake_verified=True, request_sent=True,
               response_verified=True, wire_tx=900, wire_rx=2900, qualified=True,
               proves_dns=False, proves_internet=False, release_ready=False)
    return path, tls


class OwnedHttpsReportTests(unittest.TestCase):
    def test_owned_tls_listener_requires_explicit_disposable_windows(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'false'}):
            with self.assertRaises(ValueError):
                OwnedHttpsSink(Path('/unused'), 'https-bypass', port=0, owned_address='198.18.0.1')

    def test_correct_local_https_cannot_supply_endpoint_bytes(self):
        import json
        path, tls = reports()
        path.update(qualified=False, snapshot_flags=3, tx_bytes=0, rx_bytes=0)
        tls.update(qualified=False)
        receiver = dict(empty_controls=1, client_certificate_seen=False, rejected_frames=0, owner_reset=0,
                        handshake_complete=1, handshake_failed=0, valid_requests=1,
                        request_bytes=len(REQUEST_HEADERS) + 8, replies_sent=1, reply_bytes=len(HEADERS) + 8,
                        invalid_replies=0, owner_closed=1, waiting_for_owner_close=0)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
            (directory / 'owned-https-context.json').write_text(json.dumps(tls) + '\n')
            session = SimpleNamespace(command=lambda _: dict(flags=1, tx=None, rx=None))
            endpoint = SimpleNamespace(command=Mock(side_effect=AssertionError('Use the local receiver')))
            local = SimpleNamespace(stats=lambda: receiver)
            result = observe_owned_https(session, endpoint, directory, 'https-bypass', {}, local)
            self.assertTrue(result['qualified'])
            self.assertFalse(result['owned_https_qualified'])
            self.assertTrue(result['tls']['response_verified'])
            path.update(snapshot_flags=15, tx_bytes=1000, rx_bytes=3000)
            (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
            with self.assertRaises(RuntimeError):
                observe_owned_https(session, endpoint, directory, 'https-bypass', {}, local)

    def test_valid_https_reply_after_actual_migration_stays_unqualified(self):
        import json
        path, tls = reports()
        path.update(qualified=False, snapshot_flags=33, tx_bytes=None, rx_bytes=None)
        tls.update(qualified=False)
        receiver = dict(empty_controls=0, client_certificate_seen=False, rejected_frames=0, owner_reset=0,
                        handshake_complete=1, handshake_failed=0, valid_requests=1,
                        request_bytes=len(REQUEST_HEADERS) + 8, replies_sent=1, reply_bytes=len(HEADERS) + 8,
                        invalid_replies=0, owner_closed=1, waiting_for_owner_close=0)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
            (directory / 'owned-https-context.json').write_text(json.dumps(tls) + '\n')
            session = SimpleNamespace(command=lambda _: dict(flags=1, tx=None, rx=None))
            endpoint = SimpleNamespace(command=lambda _: {'owned_probe_sink': receiver})
            result = observe_owned_https(session, endpoint, directory, 'https-migration', {})
            self.assertTrue(result['qualified'])
            self.assertFalse(result['owned_https_qualified'])
            self.assertTrue(result['tls']['response_verified'])
            path.update(snapshot_flags=15, tx_bytes=1000, rx_bytes=3000)
            (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
            with self.assertRaises(RuntimeError):
                observe_owned_https(session, endpoint, directory, 'https-migration', {})

    def test_timeout_cannot_substitute_for_actual_epoch_change(self):
        import json
        path, tls = reports()
        path.update(echo_verified=False, qualified=False, same_instance_epoch=False, state_epoch_changed=True,
                    receive_timed_out=True, snapshot_flags=129, tx_bytes=None, rx_bytes=None)
        tls.update(tls_result=2, http_result=7, response_verified=False, qualified=False)
        receiver = dict(empty_controls=1, client_certificate_seen=False, rejected_frames=0, owner_reset=0,
                        handshake_complete=1, handshake_failed=0, valid_requests=1,
                        request_bytes=len(REQUEST_HEADERS) + 8, replies_sent=0, reply_bytes=0,
                        owner_closed=1, waiting_for_owner_close=0)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
            (directory / 'owned-https-context.json').write_text(json.dumps(tls) + '\n')
            session = SimpleNamespace(command=lambda _: dict(flags=1, tx=None, rx=None))
            endpoint = SimpleNamespace(command=lambda _: {'owned_probe_sink': receiver})
            result = observe_owned_https(session, endpoint, directory, 'https-epoch-change', {})
            self.assertTrue(result['qualified'])
            self.assertFalse(result['owned_https_qualified'])
            path.update(state_epoch_changed=False)
            (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
            with self.assertRaises(RuntimeError):
                observe_owned_https(session, endpoint, directory, 'https-epoch-change', {})

    def test_broken_pipe_close_still_closes_other_stream(self):
        child = Child.__new__(Child)
        child.process = SimpleNamespace(poll=lambda: 0, stdin=Mock(), stdout=Mock())
        child.process.stdin.close.side_effect = BrokenPipeError()
        child.close()
        child.process.stdout.close.assert_called_once()

    def test_untrusted_observer_waits_for_independent_handshake_failure(self):
        import json
        path, tls = reports()
        path.update(echo_verified=False, qualified=False, tx_bytes=165, rx_bytes=1278)
        tls.update(tls_result=8, http_result=None, handshake_verified=False, request_sent=False,
                   response_verified=False, qualified=False, wire_tx=165, wire_rx=1278)
        calls = []
        receiver = dict(empty_controls=1, client_certificate_seen=False, rejected_frames=0, owner_reset=0,
                        handshake_failed=0, valid_requests=0, request_bytes=0, replies_sent=0)
        def command(_):
            calls.append(True)
            return {'owned_probe_sink': dict(receiver, handshake_failed=int(len(calls) > 1))}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
            (directory / 'owned-https-context.json').write_text(json.dumps(tls) + '\n')
            session = SimpleNamespace(command=lambda _: dict(flags=1, tx=None, rx=None))
            result = observe_owned_https(session, SimpleNamespace(command=command), directory, 'https-untrusted', {})
            self.assertTrue(result['qualified'])
            self.assertGreaterEqual(len(calls), 2)

    def test_cancel_never_queries_a_session_after_stop_exits_it(self):
        import json
        path, tls = reports()
        path.update(echo_verified=False, qualified=False, cancelled=True, receive_cancelled=True,
                    same_instance_epoch=False, snapshot_flags=1, tx_bytes=None, rx_bytes=None)
        tls.update(tls_result=1, http_result=7, response_verified=False, qualified=False, wire_tx=497, wire_rx=1544)
        stopped = []
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def command(value):
                if value == 'traffic':
                    self.assertFalse(stopped, 'Exited child cannot receive a command')
                    return dict(flags=1, tx=None, rx=None)
                self.assertEqual(value, 'stop')
                stopped.append(True)
                (directory / 'owned-probe-context.json').write_text(json.dumps(path) + '\n')
                (directory / 'owned-https-context.json').write_text(json.dumps(tls) + '\n')
                return dict(code=0)
            def stats(_):
                receiver = dict(empty_controls=1, client_certificate_seen=False, rejected_frames=0, owner_reset=0,
                                handshake_complete=1, handshake_failed=0, valid_requests=1,
                                request_bytes=len(REQUEST_HEADERS) + 8, replies_sent=0, reply_bytes=0,
                                owner_closed=int(bool(stopped)), waiting_for_owner_close=int(not stopped))
                return {'owned_probe_sink': receiver}
            result = observe_owned_https(SimpleNamespace(command=command), SimpleNamespace(command=stats),
                                         directory, 'https-cancel', {})
            self.assertTrue(result['qualified'])
            self.assertTrue(result['unknown_before_stop'])
            self.assertIsNone(result['unknown_after_negative'])

    def test_valid_https_alone_cannot_replace_missing_disarm_epoch_or_path(self):
        path, tls = reports()
        validate_https_report(tls, path)
        for changes in [dict(disarmed=False), dict(same_instance_epoch=False), dict(snapshot_flags=3),
                        dict(state_epoch_changed=True), dict(qualified=False), dict(tx_bytes=899), dict(rx_bytes=2899)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_https_report(tls, dict(path, **changes))

    def test_tls_failure_wrong_nonce_and_unsupported_claims_cannot_be_success(self):
        path, tls = reports()
        for changes in [dict(tls_result=8), dict(http_result=2), dict(request_sent=False),
                        dict(handshake_verified=False), dict(wire_tx=0), dict(wire_rx=0),
                        dict(proves_dns=True), dict(proves_internet=True), dict(release_ready=True)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_https_report(dict(tls, **changes), path)

    def test_unknown_fields_and_unbounded_or_mistyped_values_are_refused(self):
        path, tls = reports()
        for changes in [dict(raw='not_allowed'), dict(wire_tx=True), dict(wire_rx=-1), dict(wire_tx=262145),
                        dict(tls_result=True), dict(tls_result=16), dict(http_result=True), dict(http_result=8)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_https_report(dict(tls, **changes), path)
        for key in tls:
            missing = copy.copy(tls)
            del missing[key]
            with self.assertRaises(ValueError):
                validate_https_report(missing, path)


class OwnedHttpsReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='liwetun-owned-https-')
        cls.directory = Path(cls.temporary.name) / 'certificates'
        generate(cls.directory)  # Files only, no trust-store or network changes.

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def exchange(self, mode):
        sink = OwnedHttpsSink(self.directory, mode, port=0)
        try:
            # The first descriptor is the nonexclusive negative control. It
            # closes without TLS; the next connection must still be served.
            with socket.create_connection(('127.0.0.1', sink.port), timeout=1):
                pass
            context = ssl.create_default_context(cafile=str(self.directory / 'crl-ca.pem'))
            with socket.create_connection(('127.0.0.1', sink.port), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname='health.liwetun.invalid') as client:
                    client.sendall(REQUEST_HEADERS + b'fixture1')
                    response = b''
                    while len(response) < len(HEADERS) + 8:
                        part = client.recv(len(HEADERS) + 8 - len(response))
                        self.assertTrue(part)
                        response += part
            for _ in range(30):
                counts = sink.stats()
                if counts['owner_closed'] == 1:
                    break
                time.sleep(.02)
            self.assertEqual(counts['empty_controls'], 1)
            self.assertEqual(counts['handshake_complete'], 1)
            self.assertEqual(counts['valid_requests'], 1)
            self.assertEqual(counts['request_bytes'], len(REQUEST_HEADERS) + 8)
            self.assertEqual(counts['owner_closed'], 1)
            self.assertEqual(counts['waiting_for_owner_close'], 0)
            self.assertEqual(counts['rejected_frames'], 0)
            self.assertFalse(counts['client_certificate_seen'])
            return response, counts
        finally:
            self.assertTrue(sink.close())

    def test_exact_https_echo_survives_prior_empty_control(self):
        response, counts = self.exchange('https')
        self.assertEqual(response, HEADERS + b'fixture1')
        self.assertEqual(counts['invalid_replies'], 0)

    def test_wrong_nonce_returns_only_the_deliberate_invalid_response(self):
        response, counts = self.exchange('https-wrong-nonce')
        self.assertEqual(response, HEADERS + bytes(8))
        self.assertEqual(counts['invalid_replies'], 1)


if __name__ == '__main__':
    unittest.main()
