"""Verify archived candidate notice integrity and exact dependency membership.

This is not a license interpretation or release approval. No network/cache
access, source execution, source rewriting or arbitrary diagnostic text.
"""
import hashlib
import json
from pathlib import Path
import re
import tomllib

from closure import ROOT, GROUPS, normalized_lock, redirected


def read_json(path):
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('inventory_size_limit')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def verify_files(root, records):
    root = root.resolve(strict=True)
    referenced = set()
    total = 0
    for record in records:
        notices = record.get('notices')
        if not isinstance(notices, list) or not notices:
            raise ValueError('missing_notice_set')
        for notice in notices:
            name = notice['file']
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.+/-]+\.txt', name):
                raise ValueError('unsafe_notice_path')
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name:
                raise ValueError('unsafe_notice_path')
            path = root / relative
            for parent in [path, *path.parents]:
                if parent == root:
                    break
                if redirected(parent):
                    raise ValueError('redirected_notice_path')
            if not path.resolve(strict=True).is_relative_to(root):
                raise ValueError('unsafe_notice_path')
            size = path.stat().st_size
            if not 0 < size <= 2 * 1024 * 1024 or size != notice['bytes']:
                raise ValueError('notice_size_mismatch')
            if hashlib.sha256(path.read_bytes()).hexdigest() != notice['sha256']:
                raise ValueError('notice_digest_mismatch')
            if name not in referenced:
                referenced.add(name)
                total += size
            if total > 20 * 1024 * 1024 or len(referenced) > 500:
                raise ValueError('notice_set_size_limit')
    actual = {path.relative_to(root).as_posix() for path in root.rglob('*.txt')}
    if actual != referenced:
        raise ValueError('unreferenced_notice_file')
    return len(referenced)


def verify_sdk(root=None):
    root = root or ROOT / 'third_party/sdk'
    data = read_json(root / 'inventory.json')
    runtime = read_json(ROOT / 'native/sdk/runtime.json')
    if data.get('sdk_source_run') != runtime['source_run'] or data.get('sdk_source_commit') != runtime['source_commit']:
        raise ValueError('sdk_notice_provenance_mismatch')
    if data.get('release_qualified') is not False:
        raise ValueError('candidate_review_boundary_missing')
    lock = normalized_lock(read_json(ROOT / 'native/sdk/conan.lock'))
    expected = {ref for group in GROUPS for ref in lock[group]}
    packages = data['packages']
    if not isinstance(packages, list) or not 0 < len(packages) <= 200 or {item['ref'] for item in packages} != expected:
        raise ValueError('sdk_notice_dependency_drift')
    components = data['components']
    if len(components) != 2 or {item['component'] for item in components} != {'trusttunnel_sdk', 'wintun'}:
        raise ValueError('sdk_component_notices_missing')
    return verify_files(root, [*packages, *components])


def verify_rust(root=None):
    root = root or ROOT / 'third_party/rust'
    data = read_json(root / 'inventory.json')
    lock_bytes = (ROOT / 'native/trusttunnel_bridge/Cargo.lock').read_bytes().replace(b'\r\n', b'\n')
    if data.get('lock_hash_normalization') == 'windows_checkout_crlf':
        if data['lock_sha256'] != hashlib.sha256(lock_bytes.replace(b'\n', b'\r\n')).hexdigest():
            raise ValueError('rust_original_lock_digest_mismatch')
        digest = data['lock_canonical_lf_sha256']
    elif data.get('lock_hash_normalization') == 'lf':
        digest = data['lock_sha256']
    else:
        raise ValueError('unsupported_rust_lock_normalization')
    if digest != hashlib.sha256(lock_bytes).hexdigest() or data.get('release_qualified') is not False:
        raise ValueError('rust_notice_lock_drift')
    expected = {(item['name'], item['version'], item['source']): item
                for item in tomllib.loads(lock_bytes.decode())['package'] if item.get('source')}
    packages = data['packages']
    if len(packages) != len(expected) or {(item['name'], item['version'], item['source']) for item in packages} != set(expected):
        raise ValueError('rust_notice_dependency_drift')
    for item in packages:
        locked = expected[item['name'], item['version'], item['source']]
        checksum = locked.get('checksum') or locked['source'].rsplit('#', 1)[1]
        if item['source_checksum'] != checksum:
            raise ValueError('rust_notice_source_drift')
    return verify_files(root, packages)


if __name__ == '__main__':
    try:
        sdk, rust = verify_sdk(), verify_rust()
        print(f'candidate_notice_integrity_verified:sdk={sdk}:rust={rust}:release_approval=false')
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        raise SystemExit('candidate_notice_verification_failed') from None
