import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import endpoint_trace_profile as profile


def fixture():
    return {
        profile.FILES[0]:b'mod quic_multiplexer;\n',
        profile.FILES[1]:b'const TOKEN_PREFIX_SIZE: usize = 16;\n'+profile.GRACEFUL+b'''
    match socket.try_send_to(data, *peer) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) => {
            Ok(())
        }
        Err(e) => Err(e),
    }
}''',
        profile.FILES[2]:profile.EXIT+b'\n',
    }


class TraceProfileGuards(unittest.TestCase):
    def exercise(self,mode):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';original=fixture();files={}
            for name,before in original.items():
                target=source/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(before)
                files[name]=dict(input_sha256=profile.digest(before),output_sha256=profile.digest(profile.transform(name,before)))
            last=source/profile.FILES[-1]
            if mode=='source':last.write_bytes(last.read_bytes()+b'changed')
            if mode=='output':files[profile.FILES[-1]]['output_sha256']='0'*64
            if mode=='anchor':
                last.write_bytes(b'changed exit');files[profile.FILES[-1]]['input_sha256']=profile.digest(last.read_bytes())
            if mode=='symlink':
                outside=root/'outside.rs';outside.write_bytes(last.read_bytes());last.unlink();last.symlink_to(outside)
            pin=root/'pin.json';pin.write_text(json.dumps(dict(files=files)))
            preserved={name:(source/name).read_bytes() for name in original}
            with patch.object(profile,'PIN',pin):
                if mode=='valid':
                    profile.prepare(source)
                    for name,before in original.items():self.assertEqual((source/name).read_bytes(),profile.transform(name,before))
                else:
                    with self.assertRaises(RuntimeError):profile.prepare(source)
                    self.assertEqual(preserved,{name:(source/name).read_bytes() for name in original})

    def test_exact_transform(self):self.exercise('valid')
    def test_last_source_tamper_leaves_all_files_unchanged(self):self.exercise('source')
    def test_last_output_mismatch_leaves_all_files_unchanged(self):self.exercise('output')
    def test_missing_anchor_leaves_all_files_unchanged(self):self.exercise('anchor')
    def test_redirected_last_file_leaves_all_files_unchanged(self):self.exercise('symlink')


if __name__=='__main__':unittest.main()
