import json
from pathlib import Path
import shutil
import tempfile
import unittest

from verify_notices import ROOT, verify_sdk, verify_rust, verify_candidate_sdk, check_candidate_notices, read_json
from unittest.mock import patch


class NoticeIntegrityTests(unittest.TestCase):
    def test_candidate_notices_require_review_for_new_bodies_or_dependencies(self):
        old = 'synthetic/1.0#' + '1' * 32
        new = 'synthetic/1.0#' + '2' * 32
        archived = {'packages': [{'ref': old, 'notices': [{'sha256': 'a' * 64}]}]}
        actual = {'packages': [{'ref': new, 'context': 'host', 'notices': [{'sha256': 'a' * 64}]}]}
        self.assertEqual(check_candidate_notices(archived, actual, {old: new})[0]['packaged_notices'], 1)
        actual['packages'][0]['notices'] = [{'sha256': 'b' * 64}]
        with self.assertRaisesRegex(ValueError, 'candidate_packaged_notice_changed'):
            check_candidate_notices(archived, actual, {old: new})
        actual['packages'][0]['notices'] = []
        self.assertTrue(check_candidate_notices(archived, actual, {old: new})[0]['archived_supplement_required'])
        actual['packages'][0]['ref'] = 'unreviewed/1.0#' + '3' * 32
        with self.assertRaisesRegex(ValueError, 'candidate_notice_dependency_drift'):
            check_candidate_notices(archived, actual, {old: new})

    def test_current_archived_sets_match_exact_dependency_locks(self):
        self.assertEqual(verify_sdk(), 38)
        self.assertEqual(verify_rust(), 22)

    def test_traffic_candidate_requires_its_own_exact_provenance(self):
        self.assertEqual(verify_candidate_sdk(traffic_metrics=True), 38)
        for field in ['traffic_profile_manifest_sha256', 'traffic_abi_header_sha256', 'sdk_variant']:
            def altered(path):
                data = read_json(path)
                if path.name == 'runtime-traffic.json':
                    data[field] = 'synthetic_wrong_provenance'
                return data
            with self.subTest(field=field), patch('verify_notices.read_json', side_effect=altered):
                with self.assertRaisesRegex(ValueError, 'traffic_notice_provenance_mismatch'):
                    verify_candidate_sdk(traffic_metrics=True)

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
