import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import owned_probe_profile as profile


class OwnedProbeProfileGuards(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            (source / 'baseline').write_bytes(b'synthetic baseline\n')
            (root / 'one.h').write_bytes(b'first synthetic header\n')
            (root / 'two.h').write_bytes(b'second synthetic header\n')
            digest = lambda data: hashlib.sha256(data).hexdigest()
            manifest = dict(baseline_files={'baseline': digest((source / 'baseline').read_bytes())},
                            added_files={'one.h': 'one.h', 'two.h': 'two.h'},
                            added_input_sha256={n: digest((root / n).read_bytes()) for n in ['one.h', 'two.h']})
            if mode == 'header_tamper':
                (root / 'two.h').write_bytes(b'tampered')
            elif mode == 'source_tamper':
                (source / 'baseline').write_bytes(b'tampered baseline')
            elif mode == 'existing_output':
                (source / 'two.h').write_bytes(b'preserve existing output')
            elif mode == 'unsafe_output':
                manifest['added_files']['two.h'] = '../escape.h'
            manifest_file = root / 'manifest.json'
            manifest_file.write_text(json.dumps(manifest))
            before = {p.name: p.read_bytes() for p in source.iterdir()}
            with patch.object(profile, 'ROOT', root), patch.object(profile, 'transform', return_value={'baseline': 'new content'}):
                with self.assertRaises(ValueError):
                    profile.prepare(source, root / 'report', manifest_file)
            self.assertEqual(before, {p.name: p.read_bytes() for p in source.iterdir()})
            self.assertFalse((root / 'report').exists())
            self.assertFalse((root / 'escape.h').exists())

    def test_late_header_tamper_cannot_partially_mutate_vendor(self):
        self.exercise('header_tamper')

    def test_source_tamper_cannot_write_headers(self):
        self.exercise('source_tamper')

    def test_existing_output_is_preserved_without_partial_mutation(self):
        self.exercise('existing_output')

    def test_output_escape_is_rejected_before_first_write(self):
        self.exercise('unsafe_output')

    def test_unexpected_source_anchor_is_rejected(self):
        with self.assertRaises(ValueError):
            profile.transform({'core/include/vpn/internal/vpn_client.h': 'changed upstream'})


if __name__ == '__main__':
    unittest.main()
