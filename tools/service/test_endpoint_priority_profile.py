import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import endpoint_priority_profile as profile


class PriorityProfileGuards(unittest.TestCase):
    def exercise(self,mode):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';target=source/'lib/src/tunnel.rs'
            target.parent.mkdir(parents=True);before=profile.ANCHOR+b' synthetic body'
            target.write_bytes(before)
            pin=dict(file='lib/src/tunnel.rs',input_sha256=profile.digest(before),output_sha256=profile.digest(profile.transform(before)))
            if mode=='source':target.write_bytes(before+b'changed')
            if mode=='output':pin['output_sha256']='0'*64
            if mode=='anchor':
                target.write_bytes(b'changed anchor');pin['input_sha256']=profile.digest(target.read_bytes())
            if mode=='symlink':
                outside=root/'outside.rs';outside.write_bytes(before);target.unlink();target.symlink_to(outside)
            receipt=root/'pin.json';receipt.write_text(json.dumps(pin));preserved=target.read_bytes()
            with patch.object(profile,'PIN',receipt):
                if mode=='valid':
                    profile.prepare(source);self.assertEqual(target.read_bytes(),profile.transform(before))
                else:
                    with self.assertRaises(RuntimeError):profile.prepare(source)
                    self.assertEqual(target.read_bytes(),preserved)

    def test_exact_transform(self):self.exercise('valid')
    def test_source_tamper_no_write(self):self.exercise('source')
    def test_output_mismatch_no_write(self):self.exercise('output')
    def test_unknown_anchor_no_write(self):self.exercise('anchor')
    def test_redirected_target_no_write(self):self.exercise('symlink')


if __name__=='__main__':unittest.main()
