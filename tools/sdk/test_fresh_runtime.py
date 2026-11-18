import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import check_fresh_runtime as checker


class FreshRuntimeGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        for name in ['trusttunnel.dll', 'wintun.dll']:
            (self.runtime / name).write_bytes(('synthetic ' + name).encode())
        self.driver = checker.digest(self.runtime / 'wintun.dll')
        for relative in checker.HASH_INPUTS.values():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(relative.encode())
        header = self.root / 'native/health/fresh_adapter.h'
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_bytes(b'synthetic policy header')
        self.inputs = dict(adapter_creation_policy=2, physical_alias_characters=127,
                           original_wintun_sha256=self.driver,
                           added_input_sha256={'native/health/fresh_adapter.h': checker.digest(header)})
        (self.root / 'native/sdk/fresh-adapter-inputs.json').write_text(json.dumps(self.inputs))
        self.pin = dict(source_run=17, source_commit='a' * 40, sdk_variant='fresh_adapter_candidate',
                        sdk_commit='a1ce3f9d2572e8c3fd6c31e6c31881d307131f40', source_pinned_candidate=True,
                        adapter_creation_policy=2, privacy_policy_version=1, traffic_abi=1,
                        attached_tun_abi=1, owned_probe_abi=1,
                        files={n: checker.digest(self.runtime / n) for n in ['trusttunnel.dll','wintun.dll']})
        self.pin.update({n: False for n in checker.CLOSED_GATES})
        self.pin.update({n: checker.digest(self.root / relative) for n, relative in checker.HASH_INPUTS.items()})
        self.pin['qualification_scope'] = checker.SCOPE
        receipt = self.root / 'docs/evidence/synthetic-factory.json'
        receipt.parent.mkdir(parents=True)
        receipt.write_text(json.dumps(dict(source_commit='a'*40, adapter_creation_policy=2,
                                          focused_factory_race_control_passed=True,
                                          adapter_ownership_qualified=False,
                                          service_admitted=False, package_admitted=False)))
        self.pin['factory_qualification_receipt'] = 'docs/evidence/synthetic-factory.json'
        self.pin['factory_qualification_receipt_sha256'] = checker.digest(receipt)
        self.run = dict(id=17, name='Windows SDK qualification', status='completed',
                        conclusion='success', head_sha='a' * 40)
        self.addCleanup(patch.stopall)
        patch.object(checker, 'ROOT', self.root).start()
        patch.object(checker, 'WINTUN_SHA256', self.driver).start()

    def verify(self):
        return checker.verify(self.pin, self.run, self.runtime, 17)

    def test_valid_pin_confirms_only_provenance_without_promotion(self):
        report = self.verify()
        self.assertTrue(report['pinned_sources_and_binaries_matched'])
        for name in ['service_admitted','package_admitted','adapter_ownership_qualified','release_ready','sdk_started']:
            self.assertIs(report[name], False)

    def test_each_promotion_gate_must_be_literal_false(self):
        for name in checker.CLOSED_GATES:
            for wrong in [True, 0, None]:
                self.pin[name] = wrong
                with self.assertRaises(ValueError): self.verify()
            self.pin[name] = False

    def test_run_identity_status_and_success_cannot_be_substituted(self):
        for key, wrong in [('id',18),('head_sha','b'*40),('status','in_progress'),
                           ('conclusion','cancelled'),('name','Another workflow')]:
            original = self.run[key]; self.run[key] = wrong
            with self.assertRaises(ValueError): self.verify()
            self.run[key] = original

    def test_changed_source_manifest_is_rejected(self):
        path = self.root / checker.HASH_INPUTS['fresh_adapter_profile_manifest_sha256']
        path.write_bytes(b'tampered policy manifest')
        with self.assertRaises(ValueError): self.verify()

    def test_changed_creation_header_is_rejected(self):
        (self.root / 'native/health/fresh_adapter.h').write_bytes(b'changed header')
        with self.assertRaises(ValueError): self.verify()

    def test_tampered_sdk_and_driver_bytes_are_rejected(self):
        for name in ['trusttunnel.dll', 'wintun.dll']:
            path = self.runtime / name; original = path.read_bytes()
            path.write_bytes(b'tampered binary')
            with self.assertRaises(ValueError): self.verify()
            path.write_bytes(original)

    def test_different_driver_cannot_be_recorded_as_acceptable(self):
        self.pin['files']['wintun.dll'] = 'b' * 64
        with self.assertRaises(ValueError): self.verify()

    def test_factory_receipt_from_another_source_cannot_authorize_candidate(self):
        path = self.root / self.pin['factory_qualification_receipt']
        value = json.loads(path.read_text()); value['source_commit'] = 'b' * 40
        path.write_text(json.dumps(value))
        self.pin['factory_qualification_receipt_sha256'] = checker.digest(path)
        with self.assertRaises(ValueError): self.verify()

    def test_symlinked_runtime_file_is_rejected(self):
        path = self.runtime / 'trusttunnel.dll'
        path.rename(self.root / 'redirected.dll')
        path.symlink_to(self.root / 'redirected.dll')
        with self.assertRaises(ValueError): self.verify()


if __name__ == '__main__':
    unittest.main()
