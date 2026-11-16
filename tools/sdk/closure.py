"""Check the exact Conan recipe closure and collect bounded notice candidates.

No package-cache mutation. Missing notices remain explicit release blockers;
presence of a license file alone is not a redistribution audit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
REF = re.compile(r'^[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+(?:@[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+)?#[0-9a-f]{32}$')
GROUPS = ('requires', 'build_requires', 'python_requires', 'config_requires')


def reference(value):
    if not isinstance(value, str):
        raise ValueError('invalid_recipe_reference')
    value = value.split('%', 1)[0]
    if not REF.fullmatch(value):
        raise ValueError('invalid_recipe_reference')
    return value


def normalized_lock(data):
    if not isinstance(data, dict) or set(data) != {'version', 'overrides', *GROUPS} or data['version'] != '0.5':
        raise ValueError('unsupported_lock_schema')
    result = {'version': '0.5'}
    for group in GROUPS:
        items = data[group]
        if not isinstance(items, list):
            raise ValueError('invalid_lock_group')
        refs = [reference(item) for item in items]
        if len(refs) != len(set(refs)):
            raise ValueError('duplicate_locked_recipe')
        result[group] = sorted(refs)
    overrides = data['overrides']
    if not isinstance(overrides, dict):
        raise ValueError('invalid_lock_overrides')
    result['overrides'] = {}
    for key, values in overrides.items():
        if not isinstance(values, list):
            raise ValueError('invalid_lock_overrides')
        result['overrides'][reference(key)] = [None if value is None else reference(value) for value in values]
    return result


def check_lock(expected, actual):
    wanted = normalized_lock(expected)
    if wanted != normalized_lock(actual):
        raise ValueError('dependency_lock_drift')
    return wanted


def check_graph(graph, lock):
    nodes = graph.get('graph', {}).get('nodes')
    if not isinstance(nodes, dict) or not nodes or len(nodes) > 200:
        raise ValueError('invalid_dependency_graph')
    allowed = {ref for group in GROUPS for ref in lock[group]}
    packages = []
    for key, node in nodes.items():
        if key == '0':
            continue  # Local SDK consumer, pinned independently by source commit.
        ref = reference(node.get('ref'))
        if ref not in allowed or node.get('context') not in ('host', 'build'):
            raise ValueError('unlocked_graph_recipe')
        packages.append(node)
    if not packages:
        raise ValueError('empty_dependency_closure')
    return packages


def redirected(path):
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


def notice_files(package, cache):
    """Only packaged notices, no source-tree scraping or license inference."""
    if not package:
        return []
    original = Path(package)
    if redirected(original):
        raise ValueError('redirected_package_folder')
    root = original.resolve(strict=True)
    if not root.is_relative_to(cache):
        raise ValueError('package_outside_conan_cache')
    results = []
    for entry in root.iterdir():
        name = entry.name.lower()
        if name in ('licenses', 'license', 'notices') and entry.is_dir():
            # Inspect at most the dedicated notice directory, including nested
            # licenses for bundled third-party code. Never follow reparse paths.
            pending = [(entry, 0)]
            while pending:
                directory, depth = pending.pop()
                if redirected(directory) or not directory.resolve().is_relative_to(root) or depth > 8:
                    raise ValueError('unsafe_notice_directory')
                for file in directory.iterdir():
                    if redirected(file):
                        raise ValueError('redirected_notice_file')
                    if file.is_dir():
                        pending.append((file, depth + 1))
                    elif file.is_file():
                        results.append(file)
                    if len(results) + len(pending) > 500:
                        raise ValueError('too_many_notice_files')
        elif entry.is_file() and re.match(r'^(licen[sc]e|copying|copyright|notice)(\.|$)', name):
            if redirected(entry):
                raise ValueError('redirected_notice_file')
            results.append(entry)
    return sorted(set(results))


def collect(graph, lock, cache, output):
    cache = cache.resolve(strict=True)
    packages = check_graph(graph, lock)
    output.mkdir(parents=True, exist_ok=False)
    records = []
    total = 0
    for index, node in enumerate(packages):
        files = notice_files(node.get('package_folder'), cache)
        record = {key: node.get(key) for key in ('ref', 'context', 'license', 'package_id', 'prev')}
        record['notices'] = []
        for number, file in enumerate(files):
            size = file.stat().st_size
            total += size
            if size <= 0 or size > 2 * 1024 * 1024 or total > 20 * 1024 * 1024:
                raise ValueError('notice_size_limit')
            data = file.read_bytes()
            if len(data) != size or not file.resolve().is_relative_to(cache):
                raise ValueError('notice_changed_during_read')
            name = f'{index:03d}/{number:03d}.txt'
            destination = output / name
            destination.parent.mkdir(exist_ok=True)
            destination.write_bytes(data)
            record['notices'].append({'file': name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': size})
        record['notice_status'] = 'collected_for_review' if files else 'missing'
        records.append(record)
    report = {
        'recipe_closure_verified': True,
        'release_qualified': False,
        'license_review': 'pending; collection is not an approval to redistribute',
        'missing_notice_packages': sum(not item['notices'] for item in records),
        'packages': records,
    }
    (output / 'inventory.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-pinned', action='store_true')
    parser.add_argument('--actual-lock', type=Path, required=True)
    parser.add_argument('--graph', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        expected = ROOT / 'native/sdk' / ('conan-sources.lock' if args.source_pinned else 'conan.lock')
        lock = check_lock(json.loads(expected.read_text()), json.loads(args.actual_lock.read_text()))
        if any((args.graph, args.cache, args.output)):
            if not all((args.graph, args.cache, args.output)):
                raise ValueError('incomplete_collection_arguments')
            collect(json.loads(args.graph.read_text()), lock, args.cache, args.output)
        print('sdk_recipe_closure_verified')
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit('sdk_dependency_qualification_failed') from None
