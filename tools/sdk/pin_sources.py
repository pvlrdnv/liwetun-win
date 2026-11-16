"""Prepare an isolated candidate source-pin profile; never promote runtime pins."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from closure import ROOT, check_lock, normalized_lock, reference, redirected

PIN = ROOT / 'native/sdk/source-pins.json'


def prepare(source, pin, write=True, dns_source=None):
    sources = {'common': source, 'dns': dns_source}
    changes = []
    for recipe in pin['recipes']:
        source = sources.get(recipe.get('repository', 'common'))
        if source is None:
            raise ValueError('missing_recipe_source')
        if redirected(source):
            raise ValueError('redirected_recipe_path')
        source = source.resolve(strict=True)
        name = recipe['path']
        if name != 'conanfile.py' and not re.fullmatch(r'conan/recipes/[A-Za-z0-9_.+-]+/conanfile\.py', name):
            raise ValueError('unsafe_recipe_path')
        path = source / name
        for parent in [path, *path.parents]:
            if parent == source:
                break
            if redirected(parent):
                raise ValueError('redirected_recipe_path')
        if not path.resolve(strict=True).is_relative_to(source):
            raise ValueError('unsafe_recipe_path')
        original = path.read_bytes().replace(b'\r\n', b'\n')
        if hashlib.sha256(original).hexdigest() != recipe['input_sha256']:
            raise ValueError('recipe_input_digest_mismatch')
        text = original.decode('utf-8')
        if text.count(recipe['before']) != 1:
            raise ValueError('recipe_anchor_mismatch')
        patched = (pin['modified_file_header'] + text.replace(recipe['before'], recipe['after'])).encode('utf-8')
        if hashlib.sha256(patched).hexdigest() != recipe['patched_sha256']:
            raise ValueError('recipe_output_digest_mismatch')
        changes.append((path, patched))
    # Validate every input before making any change to the disposable vendor tree.
    if write:
        for path, patched in changes:
            path.write_bytes(patched)


def candidate_lock(active, replacements):
    original = normalized_lock(active)
    candidate = copy.deepcopy(active)
    found = set()
    for index, value in enumerate(candidate['requires']):
        old = reference(value)
        if old in replacements:
            new = reference(replacements[old])
            if old.split('#')[0] != new.split('#')[0] or old == new:
                raise ValueError('unexpected_recipe_identity')
            candidate['requires'][index] = new
            found.add(old)
    if found != set(replacements):
        raise ValueError('candidate_recipe_membership_mismatch')
    overrides = original['overrides']
    candidate['overrides'] = {replacements.get(key, key):
                              [None if value is None else replacements.get(value, value) for value in values]
                              for key, values in overrides.items()}
    checked = normalized_lock(candidate)
    for group in ['build_requires', 'python_requires', 'config_requires']:
        if checked[group] != original[group]:
            raise ValueError('unrelated_lock_change')
    return candidate


def export(source, version=None):
    command = ['conan', 'export', str(source), '--user', 'adguard', '--channel', 'oss', '--format=json']
    if version:
        command += ['--version', version]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=60)
    if process.returncode or len(process.stdout) > 131072:
        raise ValueError('recipe_export_failed')
    return reference(json.loads(process.stdout)['reference'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-recorded', action='store_true')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dns-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('disposable_ci_required')
    if (args.source.resolve() != (ROOT / 'build/vendor/common').resolve()
            or args.dns_source.resolve() != (ROOT / 'build/vendor/dns').resolve()
            or args.output.resolve() != (ROOT / 'build/source-pin-evidence').resolve()):
        raise ValueError('fixed_candidate_paths_required')
    pin = json.loads(PIN.read_text())
    version = subprocess.run(['conan', '--version'], capture_output=True, text=True, timeout=10)
    if version.returncode or version.stdout.strip() != 'Conan version ' + pin['conan_version']:
        raise ValueError('conan_version_mismatch')
    active = json.loads((ROOT / 'native/sdk/conan.lock').read_text())
    allowed = set(normalized_lock(active)['requires'])
    prepare(args.source, pin, write=False, dns_source=args.dns_source)
    args.output.mkdir(parents=True, exist_ok=False)
    sources = {'common': args.source, 'dns': args.dns_source}
    def export_recipe(recipe):
        return export(sources[recipe.get('repository', 'common')] / Path(recipe['path']).parent,
                      recipe.get('version'))
    original_refs = []
    for recipe in pin['recipes']:
        if recipe['old_reference'] not in allowed:
            raise ValueError('unreviewed_original_recipe')
        observed = export_recipe(recipe)
        original_refs.append(dict(expected=recipe['old_reference'], observed=observed))
        (args.output / 'original-references.json').write_text(json.dumps(original_refs, indent=2) + '\n')
        if observed != recipe['old_reference']:
            raise ValueError('original_recipe_revision_drift')
    prepare(args.source, pin, dns_source=args.dns_source)
    replacements = {recipe['old_reference']: export_recipe(recipe)
                    for recipe in pin['recipes']}
    candidate = candidate_lock(active, replacements)
    if args.verify_recorded:
        check_lock(json.loads((ROOT / 'native/sdk/conan-sources.lock').read_text()), candidate)
    (args.output / 'conan-sources.lock').write_text(json.dumps(candidate, indent=2) + '\n')
    result = dict(common_commit=pin['common_commit'], dns_commit=pin['dns_commit'], conan_version=pin['conan_version'],
                  source_pin_manifest_sha256=hashlib.sha256(PIN.read_bytes()).hexdigest(),
                  candidate_references=replacements, active_runtime_unchanged=True,
                  compiled_or_network_qualified=False, release_qualified=False)
    (args.output / 'recipe-revisions.json').write_text(json.dumps(result, indent=2) + '\n')
    print('candidate_recipe_revisions_verified:release_approval=false')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        allowed = {'dependency_lock_drift', 'missing_recipe_source', 'disposable_ci_required', 'fixed_candidate_paths_required', 'conan_version_mismatch',
                   'unreviewed_original_recipe', 'original_recipe_revision_drift', 'recipe_export_failed',
                   'recipe_input_digest_mismatch', 'recipe_output_digest_mismatch', 'recipe_anchor_mismatch',
                   'unsafe_recipe_path', 'redirected_recipe_path', 'unexpected_recipe_identity',
                   'candidate_recipe_membership_mismatch', 'unrelated_lock_change'}
        candidate = error.args[0] if error.args else None
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            destination = ROOT / 'build/source-pin-evidence'
            destination.mkdir(parents=True, exist_ok=True)
            result = dict(passed=False, reason=candidate if isinstance(candidate, str) and candidate in allowed else 'unknown',
                          release_qualified=False)
            (destination / 'preparation-failure.json').write_text(json.dumps(result, indent=2) + '\n')
        raise SystemExit('candidate_source_pin_preparation_failed') from None
