import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import endpoint_shutdown_profile as profile


class ShutdownProfileGuards(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'source'
            target=source/'endpoint/src/main.rs'
            target.parent.mkdir(parents=True)
            before=profile.CAPTURE+b'\nsynthetic body\n'+profile.EXIT+b'\n'
            target.write_bytes(before)
            pin=dict(file='endpoint/src/main.rs',input_sha256=profile.digest(before),
                     output_sha256=profile.digest(profile.transform(before)))
            if mode=='source':
                target.write_bytes(before+b'changed')
            elif mode=='output':
                pin['output_sha256']='0'*64
            elif mode=='anchor':
                before=before.replace(profile.EXIT,b'changed exit anchor')
                target.write_bytes(before);pin['input_sha256']=profile.digest(before)
            elif mode=='symlink':
                original=root/'outside.rs';original.write_bytes(before)
                target.unlink();target.symlink_to(original)
            pin_path=root/'pin.json';pin_path.write_text(json.dumps(pin))
            preserved=target.read_bytes()
            with patch.object(profile,'PIN',pin_path):
                if mode=='valid':
                    profile.prepare(source)
                    self.assertEqual(target.read_bytes(),profile.transform(before))
                    return
                with self.assertRaises(RuntimeError): profile.prepare(source)
            self.assertEqual(target.read_bytes(),preserved)

    def test_expected_transform(self): self.exercise('valid')
    def test_source_tamper_cannot_write(self): self.exercise('source')
    def test_output_hash_mismatch_cannot_write(self): self.exercise('output')
    def test_unknown_anchor_cannot_write(self): self.exercise('anchor')
    def test_redirected_file_cannot_write(self): self.exercise('symlink')


if __name__=='__main__': unittest.main()
