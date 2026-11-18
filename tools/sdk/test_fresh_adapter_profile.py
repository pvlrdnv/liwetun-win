import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import fresh_adapter_profile as profile


class FreshAdapterProfileGuards(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            (source / 'baseline').write_bytes(b'synthetic baseline\n')
            for name in ['one.h', 'two.h']:
                (root / name).write_bytes(name.encode())
            digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            manifest = dict(sdk_commit='synthetic', baseline_files={'baseline': digest(source / 'baseline')},
                            added_files={'one.h': 'one.h', 'two.h': 'two.h'},
                            added_input_sha256={n: digest(root / n) for n in ['one.h', 'two.h']})
            if mode == 'header_tamper':
                (root / 'two.h').write_bytes(b'tampered')
            elif mode == 'source_tamper':
                (source / 'baseline').write_bytes(b'tampered baseline')
            elif mode == 'existing_output':
                (source / 'two.h').write_bytes(b'preserve existing file')
            elif mode == 'unsafe_output':
                manifest['added_files']['two.h'] = '../escape.h'
            elif mode == 'symlink_output':
                (source / 'two.h').symlink_to(root / 'two.h')
            manifest_file = root / 'manifest.json'
            manifest_file.write_text(json.dumps(manifest))
            before = {p.name: p.read_bytes() for p in source.iterdir()}
            with patch.object(profile, 'ROOT', root), patch.object(profile, 'transform', return_value={'baseline': 'new content'}):
                if mode == 'valid':
                    profile.prepare(source, root / 'report', manifest_file)
                    report = json.loads((root / 'report/fresh-adapter-profile.json').read_text())
                    self.assertFalse(report['release_ready'])
                    self.assertFalse(report['adapter_ownership_qualified'])
                    self.assertEqual((source / 'two.h').read_bytes(), b'two.h')
                    return
                with self.assertRaises(ValueError):
                    profile.prepare(source, root / 'report', manifest_file)
            self.assertEqual(before, {p.name: p.read_bytes() for p in source.iterdir()})
            self.assertFalse((root / 'report').exists())
            self.assertFalse((root / 'escape.h').exists())

    def test_late_header_tamper_is_atomic(self):
        self.exercise('header_tamper')

    def test_source_tamper_is_atomic(self):
        self.exercise('source_tamper')

    def test_existing_output_is_preserved(self):
        self.exercise('existing_output')

    def test_path_escape_is_atomic(self):
        self.exercise('unsafe_output')

    def test_symlink_is_atomic(self):
        self.exercise('symlink_output')

    def test_success_has_closed_unqualified_report(self):
        self.exercise('valid')

    def test_unknown_anchor_is_rejected(self):
        with self.assertRaises((ValueError, KeyError)):
            profile.transform({'net/src/os_tunnel_win.cpp': 'changed upstream'})


if __name__ == '__main__':
    unittest.main()
