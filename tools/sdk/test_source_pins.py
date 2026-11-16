import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from closure import ROOT, check_lock
from pin_sources import prepare, candidate_lock


class SourcePinTests(unittest.TestCase):
    def fixture(self, root):
        rows = []
        for name in ['alpha', 'beta']:
            path = root / 'conan/recipes' / name / 'conanfile.py'
            path.parent.mkdir(parents=True)
            original = b'synthetic_tag_source\n'
            path.write_bytes(original)
            rows.append(dict(path=path.relative_to(root).as_posix(),
                             input_sha256=hashlib.sha256(original).hexdigest(),
                             patched_sha256=hashlib.sha256(b'# modified\nsynthetic_commit_source\n').hexdigest(),
                             before='tag', after='commit'))
        return dict(recipes=rows, modified_file_header='# modified\n')

    def test_tampered_last_input_does_not_partially_change_vendor_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = self.fixture(root)
            (root / pin['recipes'][1]['path']).write_bytes(b'tampered synthetic input')
            with self.assertRaisesRegex(ValueError, 'recipe_input_digest_mismatch'):
                prepare(root, pin)
            self.assertEqual((root / pin['recipes'][0]['path']).read_bytes(), b'synthetic_tag_source\n')

    def test_redirect_and_escape_are_rejected_before_read_or_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = self.fixture(root)
            escaped = copy.deepcopy(pin)
            escaped['recipes'][0]['path'] = '../private/conanfile.py'
            with self.assertRaisesRegex(ValueError, 'unsafe_recipe_path'):
                prepare(root, escaped)
            path = root / pin['recipes'][0]['path']
            target = root / 'unrelated-file'
            target.write_bytes(b'unrelated synthetic file')
            path.unlink()
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'redirected_recipe_path'):
                prepare(root, pin)
            self.assertEqual(target.read_bytes(), b'unrelated synthetic file')

    def test_dns_failure_leaves_common_root_recipe_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common, dns = root / 'common', root / 'dns'
            common.mkdir()
            dns.mkdir()
            pin = self.fixture(common)
            row = pin['recipes'][0]
            (common / 'conanfile.py').write_bytes(b'synthetic_tag_source\n')
            row['path'] = 'conanfile.py'
            second = pin['recipes'][1]
            second['repository'] = 'dns'
            (dns / 'conanfile.py').write_bytes(b'tampered synthetic input')
            second['path'] = 'conanfile.py'
            with self.assertRaisesRegex(ValueError, 'recipe_input_digest_mismatch'):
                prepare(common, pin, dns_source=dns)
            self.assertEqual((common / 'conanfile.py').read_bytes(), b'synthetic_tag_source\n')

    def test_candidate_changes_only_reviewed_refs_and_active_lock_still_refuses_it(self):
        active = json.loads((ROOT / 'native/sdk/conan.lock').read_text())
        pin = json.loads((ROOT / 'native/sdk/source-pins.json').read_text())
        replacements = {row['old_reference']: row['old_reference'].split('#')[0] + '#' + '0' * 32
                        for row in pin['recipes']}
        snapshot = copy.deepcopy(active)
        candidate = candidate_lock(active, replacements)
        self.assertEqual(active, snapshot)
        self.assertEqual(set(candidate['requires']) - set(active['requires']), set(replacements.values()))
        for old, values in active['overrides'].items():
            self.assertEqual(candidate['overrides'][replacements.get(old, old)],
                             [None if value is None else replacements.get(value, value) for value in values])
        with self.assertRaisesRegex(ValueError, 'dependency_lock_drift'):
            check_lock(active, candidate)


if __name__ == '__main__':
    unittest.main()
