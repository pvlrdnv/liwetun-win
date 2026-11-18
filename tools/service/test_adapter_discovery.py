import re
import unittest
from unittest.mock import patch
from adapter_discovery import selector, FRESH_PATTERN


class AdapterDiscoveryTests(unittest.TestCase):
    def test_legacy_observer_selection_unchanged_without_explicit_candidate(self):
        for value in ['', 'false']:
            with patch.dict('os.environ', {'FRESH_ADAPTER': value}, clear=True):
                self.assertEqual(selector(), "Get-NetAdapter -IncludeHidden | Where-Object Name -eq 'LiWeTun'")

    def test_candidate_selection_refuses_missing_ci_or_preceding_profile(self):
        flags = dict(FRESH_ADAPTER='true', GITHUB_ACTIONS='true', SOURCE_PINNED='true',
                     TRAFFIC_METRICS='true', ATTACHED_TUN='true', OWNED_PROBE='true')
        for missing in ['GITHUB_ACTIONS', 'SOURCE_PINNED', 'TRAFFIC_METRICS', 'ATTACHED_TUN']:
            incomplete = dict(flags); incomplete.pop(missing)
            with patch.dict('os.environ', incomplete, clear=True), self.assertRaises(ValueError):
                selector()
        with patch.dict('os.environ', flags, clear=True):
            self.assertIn(FRESH_PATTERN, selector())

    def test_fresh_observer_does_not_require_enabling_the_owned_socket_worker(self):
        flags = dict(FRESH_ADAPTER='true', GITHUB_ACTIONS='true', SOURCE_PINNED='true',
                     TRAFFIC_METRICS='true', ATTACHED_TUN='true', OWNED_PROBE='false')
        with patch.dict('os.environ', flags, clear=True):
            self.assertIn(FRESH_PATTERN, selector())

    def test_candidate_pattern_excludes_other_names_and_short_or_truncated_aliases(self):
        name = 'LiWeTun-' + '0123456789abcdef' * 2 + 'x' * 87
        self.assertEqual(len(name), 127)
        self.assertIsNotNone(re.fullmatch(FRESH_PATTERN, name))
        for invalid in ['LiWeTun', name[:-1], name + 'x', name + ' 1', name.upper(),
                        name.replace('LiWeTun-', 'Other-'), name[:40], name[:-1] + 'y', name + '\n']:
            self.assertIsNone(re.fullmatch(FRESH_PATTERN, invalid))

    def test_unknown_mode_cannot_silently_select_legacy_adapter(self):
        with patch.dict('os.environ', {'FRESH_ADAPTER': 'True'}, clear=True), self.assertRaises(ValueError):
            selector()


if __name__ == '__main__':
    unittest.main()
