import unittest
from unittest.mock import patch

import network


class RestorationObservationTests(unittest.TestCase):
    def test_transient_failed_observation_requires_later_coherent_clean_result(self):
        observation = {}
        with patch('network.adapter_absent', side_effect=[RuntimeError('fixture_system_command_failed'), True, True]), \
                patch('network.snapshot', return_value={'synthetic': 'baseline'}), \
                patch('network.time.sleep'):
            self.assertTrue(network.wait_clean({'synthetic': 'baseline'}, observation))
        self.assertEqual(observation, dict(attempts=2, query_failures=1, coherent_clean_observed=True))

    def test_persistent_query_failure_or_changed_network_never_counts_as_clean(self):
        for failure in [True, False]:
            observation = {}
            with self.subTest(failure=failure), \
                    patch('network.adapter_absent', side_effect=RuntimeError('fixture_system_command_failed') if failure else None,
                          return_value=True), \
                    patch('network.snapshot', return_value={'synthetic': 'changed'}), \
                    patch('network.time.sleep'):
                self.assertFalse(network.wait_clean({'synthetic': 'baseline'}, observation))
            self.assertEqual(observation['attempts'], 20)
            self.assertEqual(observation['query_failures'], 20 if failure else 0)
            self.assertFalse(observation['coherent_clean_observed'])

    def test_unexpected_failure_is_not_suppressed(self):
        with patch('network.adapter_absent', side_effect=RuntimeError('unexpected_fixture_failure')):
            with self.assertRaisesRegex(RuntimeError, 'unexpected_fixture_failure'):
                network.wait_clean({})

    def test_adapter_reappearing_after_snapshot_is_not_clean(self):
        with patch('network.adapter_absent', side_effect=[True, False] + [False] * 19), \
                patch('network.snapshot', return_value={'synthetic': 'baseline'}), \
                patch('network.time.sleep'):
            self.assertFalse(network.wait_clean({'synthetic': 'baseline'}))


if __name__ == '__main__':
    unittest.main()
