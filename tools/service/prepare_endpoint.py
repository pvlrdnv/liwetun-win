"""Hash-checked two-file patch for a disposable diagnostic endpoint only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / 'tools/service/endpoint-source.json'
PATCH = ROOT / 'tools/service/endpoint_socks5.patch'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_files(source, files):
    for name, expected in files.items():
        if digest(source / name) != expected:
            raise RuntimeError('endpoint_source_digest_mismatch')


def prepare(source):
    pin = json.loads(PIN.read_text())
    if digest(PATCH) != pin['patch_sha256']:
        raise RuntimeError('endpoint_patch_digest_mismatch')
    verify_files(source, pin['input_files'])
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
                   cwd=source, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    verify_files(source, pin['patched_files'])


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or sys.platform != 'linux':
        raise RuntimeError('disposable_linux_required')
    pin = json.loads(PIN.read_text())
    source = ROOT / 'build/endpoint-source'
    if digest(ROOT / 'build/endpoint-source.tar.gz') != pin['source_archive_sha256']:
        raise RuntimeError('endpoint_archive_digest_mismatch')
    if sys.argv[1:] == ['prepare']:
        prepare(source)
    elif sys.argv[1:] == ['record']:
        verify_files(source, pin['patched_files'])
        if digest(PATCH) != pin['patch_sha256']:
            raise RuntimeError('endpoint_patch_digest_mismatch')
        result = dict(source_commit=pin['source_commit'], patch_sha256=pin['patch_sha256'],
                      source_archive_sha256=pin['source_archive_sha256'],
                      binary_sha256=digest(ROOT / 'build/endpoint/trusttunnel_endpoint'),
                      diagnostic_source_fix=True, release_ready=False)
        (ROOT / 'build/endpoint/fixture-provenance.json').write_text(json.dumps(result, indent=2) + '\n')
    else:
        raise RuntimeError('invalid_preparation_mode')


if __name__ == '__main__':
    main()
