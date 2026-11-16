import json
from pathlib import Path
import shutil
import tempfile
import unittest

from verify_notices import ROOT, verify_sdk, verify_rust


class NoticeIntegrityTests(unittest.TestCase):
    def test_current_archived_sets_match_exact_dependency_locks(self):
        self.assertEqual(verify_sdk(), 38)
        self.assertEqual(verify_rust(), 22)

    def test_tampered_missing_extra_or_escaping_notices_fail(self):
        for mode in ('tamper', 'missing', 'extra', 'escape', 'recipe_drift'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / 'sdk'
                shutil.copytree(ROOT / 'third_party/sdk', target)
                path = target / 'inventory.json'
                data = json.loads(path.read_text())
                notice = data['packages'][0]['notices'][0]
                if mode == 'tamper':
                    (target / notice['file']).write_bytes(b'changed')
                elif mode == 'missing':
                    data['packages'][0]['notices'] = []
                elif mode == 'extra':
                    (target / 'unrelated.txt').write_text('PRIVATE_CANARY')
                elif mode == 'escape':
                    notice['file'] = '../PRIVATE_CANARY.txt'
                else:
                    data['packages'][0]['ref'] = 'unexpected/1.0#' + '0' * 32
                path.write_text(json.dumps(data))
                with self.assertRaises((ValueError, OSError)):
                    verify_sdk(target)


if __name__ == '__main__':
    unittest.main()
