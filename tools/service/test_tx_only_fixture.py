import socket
import time
import unittest
from production_network import aggregate_window
from tx_only_fixture import TxOnlySink, PAYLOAD, TARGET
from endpoint_forwarder import EndpointForwarder
from physical_forwarder import Forwarder


class TxOnlyFixtureTests(unittest.TestCase):
    def test_owned_sink_accepts_fragmented_fixed_frames_without_response(self):
        sink = TxOnlySink(port=0)
        try:
            with socket.create_connection(sink.address, timeout=1) as client:
                client.sendall(PAYLOAD[:3])
                client.sendall(PAYLOAD[3:] + PAYLOAD)
                for _ in range(50):
                    if sink.stats()['matched_frames'] == 2:
                        break
                    time.sleep(.01)
                client.settimeout(.05)
                with self.assertRaises(socket.timeout):
                    client.recv(1)
                data = sink.stats()
                self.assertEqual(data['matched_frames'], 2)
                self.assertEqual(data['received_bytes'], 2 * len(PAYLOAD))
                self.assertEqual(data['sent_bytes'], 0)
                self.assertEqual(data['rejected_frames'], 0)
        finally:
            sink.close()

    def test_extra_forwarding_target_is_explicit_and_absent_from_physical_exit(self):
        base = Forwarder(('127.0.0.1', 1), ('127.0.0.1', 2), 0, port=0)
        disabled = EndpointForwarder(('127.0.0.1', 1), ('127.0.0.1', 2), 0, port=0)
        enabled = EndpointForwarder(('127.0.0.1', 1), ('127.0.0.1', 2), 0, port=0, tx_only=True)
        try:
            self.assertFalse(base.tcp_allowed(TARGET))
            self.assertFalse(disabled.tcp_allowed(TARGET))
            self.assertTrue(enabled.tcp_allowed(TARGET))
            self.assertFalse(enabled.tcp_allowed(('198.18.0.10', TARGET[1])))
        finally:
            for proxy in [base, disabled, enabled]:
                proxy.close()

    def test_window_refuses_rx_growth_gaps_epoch_changes_and_unknown_counters(self):
        samples = [dict(code=0, flags=3, core_state=2, instance=1, epoch=2,
                        at_ms=i * 1000, tx=i * len(PAYLOAD), rx=100) for i in range(21)]
        self.assertTrue(aggregate_window(samples, tx_only=True)['passed'])
        for field, value in [('rx', 101), ('flags', 1), ('epoch', 3), ('instance', 2), ('at_ms', 40000)]:
            changed = [dict(sample) for sample in samples]
            changed[-1][field] = value
            self.assertFalse(aggregate_window(changed, tx_only=True)['passed'])
        idle = [dict(sample, tx=10) for sample in samples]
        self.assertTrue(aggregate_window(idle, tx_only=False)['passed'])
        self.assertFalse(aggregate_window(idle, tx_only=True)['passed'])
        self.assertFalse(aggregate_window(samples[:10], tx_only=True)['passed'])
