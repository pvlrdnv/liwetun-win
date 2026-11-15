"""Collect notice candidates for the exact locked native-parser dependency set.

Run cargo metadata --locked --offline --format-version 1 first; no compilation,
network download, credential inspection or dependency code execution here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
OFFICIAL = 'git+https://github.com/TrustTunnel/TrustTunnel?rev=48f424c0874eb6f6374ee84492c5cd55aa04dca9#48f424c0874eb6f6374ee84492c5cd55aa04dca9'


def identity(package):
    return package['name'], package['version'], package.get('source')


def collect(metadata, cargo_home, output):
    locked = tomllib.loads((ROOT / 'native/trusttunnel_bridge/Cargo.lock').read_text())['package']
    wanted = {identity(package): package for package in locked}
    packages = metadata['packages']
    if len(packages) != len(wanted) or {identity(package) for package in packages} != set(wanted):
        raise ValueError('rust_dependency_drift')
    local = [package for package in packages if package.get('source') is None]
    if len(local) != 1 or Path(local[0]['manifest_path']).resolve() != ROOT / 'native/trusttunnel_bridge/Cargo.toml':
        raise ValueError('unexpected_local_dependency')
    cargo_home = cargo_home.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    records = []
    total = 0
    for package in sorted(packages, key=identity):
        name, version, source = identity(package)
        if source is None:
            continue
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or not re.fullmatch(r'[A-Za-z0-9_.+-]+', version):
            raise ValueError('unsafe_package_identity')
        root = Path(package['manifest_path']).resolve(strict=True).parent
        if not root.is_relative_to(cargo_home):
            raise ValueError('rust_package_outside_cache')
        if source == REGISTRY:
            checksum = wanted[identity(package)]['checksum']
            archives = list((cargo_home / 'registry/cache').glob(f'*/{name}-{version}.crate'))
            if len(archives) != 1 or archives[0].is_symlink() or not archives[0].resolve().is_relative_to(cargo_home) or archives[0].stat().st_size > 20 * 1024 * 1024 or hashlib.sha256(archives[0].read_bytes()).hexdigest() != checksum:
                raise ValueError('rust_archive_checksum_mismatch')
        elif source == OFFICIAL and name == 'trusttunnel-deeplink':
            checksum = source.rsplit('#', 1)[1]
        else:
            raise ValueError('unexpected_rust_source')
        candidates = [file for file in root.iterdir()
                      if re.match(r'^(licen[sc]e|copying|copyright|notice)(\.|-|$)', file.name.lower()) and file.is_file()]
        if source == OFFICIAL:
            candidates += [root.parent / 'LICENSE']  # License at this pinned workspace root.
        record = {'name': name, 'version': version, 'source': source, 'source_checksum': checksum,
                  'declared_license': package.get('license'), 'notices': []}
        for index, file in enumerate(sorted(set(candidates))):
            if file.is_symlink() or not file.resolve(strict=True).is_relative_to(cargo_home):
                raise ValueError('unsafe_rust_notice_path')
            size = file.stat().st_size
            total += size
            if not 0 < size <= 2 * 1024 * 1024 or total > 20 * 1024 * 1024:
                raise ValueError('rust_notice_size_limit')
            data = file.read_bytes()
            if len(data) != size:
                raise ValueError('rust_notice_changed_during_read')
            target = Path(f'{name}-{version}') / f'{index:02d}.txt'
            (output / target).parent.mkdir(exist_ok=True)
            (output / target).write_bytes(data)
            record['notices'].append({'file': target.as_posix(), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        record['notice_status'] = 'collected_for_review' if record['notices'] else 'missing'
        records.append(record)
    report = {'lock_sha256': hashlib.sha256((ROOT / 'native/trusttunnel_bridge/Cargo.lock').read_bytes().replace(b'\r\n', b'\n')).hexdigest(),
              'lock_hash_normalization': 'lf',
              'release_qualified': False, 'license_review': 'pending; includes build/procedural-macro dependencies conservatively',
              'missing_notice_packages': sum(not record['notices'] for record in records), 'packages': records}
    (output / 'inventory.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--cargo-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        collect(json.loads(args.metadata.read_text(encoding='utf-8-sig')), args.cargo_home, args.output)
        print('rust_notice_candidates_collected')
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit('rust_notice_collection_failed') from None
