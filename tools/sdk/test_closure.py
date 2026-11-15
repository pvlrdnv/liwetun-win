import copy
import json
from pathlib import Path
import tempfile
import unittest

from closure import ROOT, check_graph, check_lock, collect


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads((ROOT / 'native/sdk/conan.lock').read_text())
        self.lock = check_lock(self.original, self.original)

    def test_exact_recipe_revision_required_but_export_timestamp_may_change(self):
        actual = copy.deepcopy(self.original)
        actual['requires'][0] = actual['requires'][0].split('%')[0] + '%9999999999.0'
        check_lock(self.original, actual)
        actual['requires'][0] = actual['requires'][0].split('#')[0] + '#' + '0' * 32
        with self.assertRaisesRegex(ValueError, 'dependency_lock_drift'):
            check_lock(self.original, actual)

    def test_new_omitted_or_looser_dependencies_fail(self):
        for mutation in ('add', 'remove', 'unpin'):
            actual = copy.deepcopy(self.original)
            if mutation == 'add':
                actual['requires'].append('unexpected/1.0#' + '0' * 32)
            elif mutation == 'remove':
                actual['requires'].pop()
            else:
                actual['requires'][0] = actual['requires'][0].split('#')[0]
            with self.assertRaises(ValueError):
                check_lock(self.original, actual)

    def test_graph_rejects_unlocked_recipe_even_if_output_lock_unchanged(self):
        with self.assertRaisesRegex(ValueError, 'unlocked_graph_recipe'):
            check_graph({'graph': {'nodes': {'1': {'ref': 'unexpected/1.0#' + '0' * 32, 'context': 'host'}}}}, self.lock)

    def test_collect_preserves_notices_marks_missing_and_never_invents_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'cache'
            package = cache / 'package'
            (package / 'licenses').mkdir(parents=True)
            notice = b'Synthetic copyright notice\n'
            (package / 'licenses/LICENSE').write_bytes(notice)
            missing = cache / 'missing'
            missing.mkdir()
            graph = {'graph': {'nodes': {
                '1': {'ref': self.lock['requires'][0], 'context': 'host', 'package_folder': str(package)},
                '2': {'ref': self.lock['requires'][1], 'context': 'host', 'package_folder': str(missing)},
            }}}
            output = root / 'output'
            collect(graph, self.lock, cache, output)
            report = json.loads((output / 'inventory.json').read_text())
            self.assertFalse(report['release_qualified'])
            self.assertEqual(report['missing_notice_packages'], 1)
            first = report['packages'][0]['notices'][0]
            self.assertEqual((output / first['file']).read_bytes(), notice)
            self.assertNotIn(str(root), json.dumps(report))

    def test_notice_collection_rejects_external_paths_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'cache'
            cache.mkdir()
            external = root / 'external'
            external.mkdir()
            (external / 'LICENSE').write_text('Unrelated confidential file')
            graph = {'graph': {'nodes': {'1': {
                'ref': self.lock['requires'][0], 'context': 'host', 'package_folder': str(external),
            }}}}
            with self.assertRaisesRegex(ValueError, 'package_outside_conan_cache'):
                collect(graph, self.lock, cache, root / 'output1')
            package = cache / 'package'
            package.mkdir()
            (package / 'licenses').symlink_to(external, target_is_directory=True)
            graph['graph']['nodes']['1']['package_folder'] = str(package)
            with self.assertRaisesRegex(ValueError, 'unsafe_notice_directory'):
                collect(graph, self.lock, cache, root / 'output2')


if __name__ == '__main__':
    unittest.main()
