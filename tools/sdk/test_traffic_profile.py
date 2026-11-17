import hashlib
from pathlib import Path
import tempfile
import unittest
from traffic_profile import verify_inputs, safe_file, transform


class TrafficProfileGuards(unittest.TestCase):
    def test_later_tamper_is_rejected_without_mutating_earlier_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = b'synthetic input\n'
            (root / 'one').write_bytes(body)
            (root / 'two').write_bytes(b'tampered synthetic input\n')
            manifest = dict(baseline_files={name: hashlib.sha256(body).hexdigest() for name in ['one', 'two']})
            with self.assertRaisesRegex(ValueError, 'traffic_baseline_digest_mismatch'):
                verify_inputs(root, manifest)
            self.assertEqual((root / 'one').read_bytes(), body)

    def test_parent_redirect_escape_and_missing_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'real').mkdir()
            (root / 'real/file').write_bytes(b'synthetic')
            (root / 'redirect').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'redirected_traffic_source_path'):
                safe_file(root, 'redirect/file')
            with self.assertRaisesRegex(ValueError, 'unsafe_traffic_source_path'):
                safe_file(root, '../other')
            with self.assertRaisesRegex(ValueError, 'missing_traffic_source'):
                safe_file(root, 'missing')

    def test_windows_and_unix_baselines_share_only_canonical_newline_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = b'synthetic\nsource\n'
            manifest = dict(baseline_files={'file': hashlib.sha256(original).hexdigest()})
            for value in [original, original.replace(b'\n', b'\r\n')]:
                (root / 'file').write_bytes(value)
                self.assertEqual(verify_inputs(root, manifest)['file'], original.decode())

    def test_unexpected_anchor_cannot_silently_patch_a_different_source(self):
        with self.assertRaisesRegex(ValueError, 'traffic_source_anchor_mismatch'):
            transform({'core/src/connection_statistics.h': 'synthetic changed upstream'})


if __name__ == '__main__':
    unittest.main()
