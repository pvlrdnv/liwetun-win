"""Bundle verified native notices for Flutter's offline license page.

Original source notice bytes stay untouched. Coverage/integrity checks are not
a license interpretation, source-provenance closure or redistribution approval.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path

from verify_notices import ROOT, verify_sdk, verify_rust

TARGET = ROOT / 'third_party/client/NOTICES.txt'
SEPARATOR = b'\n' + b'-' * 80 + b'\n'


def native_notices():
    counts = {'sdk': verify_sdk(), 'rust': verify_rust()}
    entries = []
    for kind in ['sdk', 'rust']:
        root = ROOT / 'third_party' / kind
        inventory = json.loads((root / 'inventory.json').read_text(encoding='utf-8'))
        for record in inventory['packages'] + inventory.get('components', []):
            if kind == 'rust':
                label = f"{record['name']} (Rust {record['version']})"
            elif 'component' in record:
                label = {'trusttunnel_sdk': 'TrustTunnel SDK', 'wintun': 'Wintun'}[record['component']]
            else:
                label = 'TrustTunnel dependency: ' + record['ref'].split('#')[0].split('@')[0]
            if not label or len(label) > 256 or any(ord(char) < 32 for char in label):
                raise ValueError('invalid_notice_label')
            for item in record['notices']:
                original = (root / item['file']).read_bytes()
                original.decode('utf-8', errors='strict')
                if SEPARATOR in original:
                    raise ValueError('nested_flutter_separator_requires_review')
                entries.append(label.encode('utf-8') + b'\n\n' + original)
    return SEPARATOR.join(entries), counts


def check_bundle(path, native, engine_license=None):
    if not 0 < path.stat().st_size <= 2 * 1024 * 1024:
        raise ValueError('compressed_notice_size_limit')
    with gzip.GzipFile(fileobj=io.BytesIO(path.read_bytes())) as archive:
        content = archive.read(8 * 1024 * 1024 + 1)
    if len(content) > 8 * 1024 * 1024:
        raise ValueError('expanded_notice_size_limit')
    content.decode('utf-8', errors='strict')
    if native not in content:
        raise ValueError('native_notice_bundle_missing_or_changed')
    result = dict(compressed_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  expanded_sha256=hashlib.sha256(content).hexdigest(), expanded_bytes=len(content),
                  native_notice_bytes_preserved=True)
    if engine_license:
        if not 0 < engine_license.stat().st_size <= 4 * 1024 * 1024:
            raise ValueError('engine_notice_size_limit')
        engine = engine_license.read_bytes()
        pin = json.loads((ROOT / 'tools/sdk/client-notices.json').read_text())
        if hashlib.sha256(engine).hexdigest() != pin['engine_notice_sha256']:
            raise ValueError('pinned_engine_notice_digest_mismatch')
        engine.decode('utf-8', errors='strict')
        sections = engine.split(SEPARATOR)
        for section in sections:
            # Flutter's collector may coalesce package names, but license body
            # bytes must remain intact after its de-duplication/sorting.
            if b'\n\n' not in section:
                raise ValueError('unknown_engine_notice_format')
            body = section.split(b'\n\n', 1)[1]
            if not body or body not in content:
                raise ValueError('engine_notice_body_missing_or_changed')
        result.update(engine_notice_sha256=hashlib.sha256(engine).hexdigest(),
                      engine_sections=len(sections), engine_notice_bodies_preserved=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--engine-license', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    native, counts = native_notices()
    if (ROOT / 'pubspec.yaml').read_text(encoding='utf-8').count('    - third_party/client/NOTICES.txt') != 1:
        raise ValueError('flutter_additional_notice_declaration_missing')
    if args.write:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(native)
    elif not TARGET.exists() or TARGET.read_bytes() != native:
        raise ValueError('generated_native_notices_drift')
    result = dict(native_notice_files=counts, native_bundle_sha256=hashlib.sha256(native).hexdigest(),
                  native_bundle_bytes=len(native), license_approval=False, release_ready=False)
    if args.engine_license and not args.bundle:
        raise ValueError('bundle_required_for_engine_check')
    if args.bundle:
        result['application_bundle'] = check_bundle(args.bundle, native, args.engine_license)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('client_notice_bytes_verified:license_approval=false')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('client_notice_verification_failed') from None
