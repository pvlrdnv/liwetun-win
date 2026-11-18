"""Verify an explicit CI-only fresh SDK pin. Never admits service/package use."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from traffic_profile import safe_file
from fresh_adapter_profile import WINTUN_SHA256

ROOT = Path(__file__).resolve().parents[2]
SCOPE = 'disposable_server_2022_fresh_adapter_candidate_not_service_or_package_admission'
HASH_INPUTS = {
    'source_pin_manifest_sha256': 'native/sdk/source-pins.json',
    'conan_input_lock_sha256': 'native/sdk/conan-sources.lock',
    'traffic_profile_manifest_sha256': 'native/sdk/traffic-inputs.json',
    'traffic_abi_header_sha256': 'native/traffic/traffic_abi.h',
    'attached_tun_profile_manifest_sha256': 'native/sdk/attached-tun-inputs.json',
    'attached_tun_abi_header_sha256': 'native/health/attached_tun_abi.h',
    'owned_probe_profile_manifest_sha256': 'native/sdk/owned-probe-inputs.json',
    'owned_probe_abi_header_sha256': 'native/probe/probe_abi.h',
    'fresh_adapter_profile_manifest_sha256': 'native/sdk/fresh-adapter-inputs.json',
}
CLOSED_GATES = ('network_requalified', 'release_qualified', 'windows_10_qualified',
                'windows_11_qualified', 'native_ipv6_egress_qualified', 'service_admitted',
                'package_admitted', 'adapter_ownership_qualified', 'https_health_qualified',
                'dns_health_qualified', 'actual_interface_qualified', 'owned_socket_path_qualified',
                'focused_owned_https_ci_qualified')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(pin, run, runtime, run_id):
    if (type(run_id) is not int or not 1 <= run_id < 10**20 or type(pin.get('source_run')) is not int
            or pin['source_run'] != run_id or type(run.get('id')) is not int or run['id'] != run_id
            or run.get('name') != 'Windows SDK qualification' or run.get('status') != 'completed'
            or run.get('conclusion') != 'success' or run.get('head_sha') != pin.get('source_commit')
            or not re.fullmatch(r'[0-9a-f]{40}', pin.get('source_commit', ''))):
        raise ValueError('fresh_runtime_run_not_qualified')
    if (pin.get('sdk_variant') != 'fresh_adapter_candidate'
            or pin.get('qualification_scope') != SCOPE
            or pin.get('sdk_commit') != 'a1ce3f9d2572e8c3fd6c31e6c31881d307131f40'
            or pin.get('source_pinned_candidate') is not True
            or type(pin.get('adapter_creation_policy')) is not int or pin['adapter_creation_policy'] != 2
            or any(pin.get(name) is not False for name in CLOSED_GATES)):
        raise ValueError('fresh_runtime_scope_not_closed')
    for name in ['privacy_policy_version', 'traffic_abi', 'attached_tun_abi', 'owned_probe_abi']:
        if type(pin.get(name)) is not int or pin[name] != 1:
            raise ValueError('fresh_runtime_abi_mismatch')
    for name, relative in HASH_INPUTS.items():
        if pin.get(name) != digest(safe_file(ROOT, relative)):
            raise ValueError('fresh_runtime_source_digest_mismatch')
    inputs = json.loads(safe_file(ROOT, 'native/sdk/fresh-adapter-inputs.json').read_text())
    if (inputs.get('adapter_creation_policy') != 2 or inputs.get('physical_alias_characters') != 127
            or inputs.get('original_wintun_sha256') != WINTUN_SHA256):
        raise ValueError('fresh_runtime_creation_dependency_mismatch')
    for name, expected in inputs['added_input_sha256'].items():
        if digest(safe_file(ROOT, name)) != expected:
            raise ValueError('fresh_runtime_creation_header_mismatch')
    receipt_file = safe_file(ROOT, pin['factory_qualification_receipt'])
    receipt = json.loads(receipt_file.read_text())
    if (digest(receipt_file) != pin.get('factory_qualification_receipt_sha256')
            or receipt.get('source_commit') != pin['source_commit']
            or type(receipt.get('adapter_creation_policy')) is not int or receipt['adapter_creation_policy'] != 2
            or receipt.get('focused_factory_race_control_passed') is not True
            or receipt.get('adapter_ownership_qualified') is not False
            or receipt.get('service_admitted') is not False or receipt.get('package_admitted') is not False):
        raise ValueError('fresh_runtime_factory_receipt_mismatch')
    files = pin.get('files')
    if not isinstance(files, dict) or set(files) != {'trusttunnel.dll', 'wintun.dll'}:
        raise ValueError('fresh_runtime_file_set_mismatch')
    if files['wintun.dll'] != WINTUN_SHA256:
        raise ValueError('fresh_runtime_original_driver_mismatch')
    for name, expected in files.items():
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('fresh_runtime_invalid_binary_digest')
        if digest(safe_file(runtime, name)) != expected:
            raise ValueError('fresh_runtime_binary_mismatch')
    return dict(source_run=run_id, source_commit=pin['source_commit'], adapter_creation_policy=2,
                pinned_sources_and_binaries_matched=True, original_wintun_matched=True,
                build_marker_inspected=False, sdk_started=False, identifiers_exported=False,
                adapter_ownership_qualified=False, network_requalified=False,
                service_admitted=False, package_admitted=False, release_ready=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--run-metadata', type=Path, required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(json.loads(args.manifest.read_text()), json.loads(args.run_metadata.read_text()),
                    args.runtime, args.run_id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError):
        raise SystemExit('fresh_runtime_verification_failed') from None
