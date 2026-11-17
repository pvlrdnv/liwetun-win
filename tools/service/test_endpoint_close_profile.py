import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import endpoint_close_profile as profile


class EndpointCloseProfileTests(unittest.TestCase):
    def test_guarded_wakeup_and_refusal_to_reapply(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'lib/src/http3_codec.rs'
            target.parent.mkdir(parents=True)
            before = b'prefix\n' + profile.OLD + b'\nsuffix\n'
            after = before.replace(profile.OLD, profile.NEW)
            pin = root / 'inputs.json'
            pin.write_text(json.dumps(dict(file='lib/src/http3_codec.rs',
                input_sha256=hashlib.sha256(before).hexdigest(),
                output_sha256=hashlib.sha256(after).hexdigest())))
            target.write_bytes(before)
            with patch.object(profile, 'PIN', pin):
                profile.prepare(root)
                self.assertEqual(target.read_bytes(), after)
                with self.assertRaises(RuntimeError):
                    profile.prepare(root)
                self.assertEqual(target.read_bytes(), after)

    def test_wrong_source_or_output_pin_cannot_mutate_source(self):
        for invalid in ['input_sha256', 'output_sha256']:
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'lib/src/http3_codec.rs'
                target.parent.mkdir(parents=True)
                before = profile.OLD
                pin = root / 'inputs.json'
                values = dict(file='lib/src/http3_codec.rs', input_sha256=profile.digest(before),
                              output_sha256=profile.digest(profile.NEW))
                values[invalid] = '0' * 64
                pin.write_text(json.dumps(values))
                target.write_bytes(before)
                with patch.object(profile, 'PIN', pin), self.assertRaises(RuntimeError):
                    profile.prepare(root)
                self.assertEqual(target.read_bytes(), before)
