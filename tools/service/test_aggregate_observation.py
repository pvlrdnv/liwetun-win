import unittest
from production_network import aggregate_progress


class AggregateObservationTests(unittest.TestCase):
    def test_missing_or_unknown_metrics_never_become_zero_growth(self):
        for missing in [{}, dict(flags=0), dict(code=0, flags=3, core_state=2, instance=1, epoch=1, at_ms=1, tx=None, rx=0)]:
            result = aggregate_progress(missing, missing)
            self.assertFalse(result['passed'])
            self.assertIsNone(result['tx_delta'])
            self.assertIsNone(result['rx_delta'])

    def test_epoch_restart_or_counter_reset_cannot_fake_positive_traffic(self):
        before = dict(code=0, flags=3, core_state=2, instance=1, epoch=2, at_ms=1, tx=10, rx=20)
        for changes in [dict(instance=2), dict(epoch=3), dict(tx=0), dict(rx=0), dict(at_ms=1)]:
            after = dict(before, at_ms=2, tx=11, rx=21)
            after.update(changes)
            result = aggregate_progress(before, after)
            self.assertFalse(result['passed'])
            self.assertIsNone(result['tx_delta'])

    def test_known_bidirectional_progress_is_not_dns_or_internet_proof(self):
        before = dict(code=0, flags=3, core_state=2, instance=1, epoch=2, at_ms=1, tx=0, rx=0)
        after = dict(before, at_ms=2, tx=3, rx=5)
        result = aggregate_progress(before, after)
        self.assertTrue(result['passed'])
        self.assertEqual(result['tx_delta'], 3)
        self.assertEqual(result['rx_delta'], 5)
        self.assertFalse(result['proves_dns'])
        self.assertFalse(result['proves_internet'])
