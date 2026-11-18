"""Build-marker inspection only: no instance, adapter, driver or network startup."""
import argparse
import ctypes
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('disposable_windows_required')
    runtime = args.runtime.resolve()
    with os.add_dll_directory(str(runtime)):
        sdk = ctypes.WinDLL(str(runtime / 'trusttunnel.dll'))
        marker = sdk.liwetun_adapter_creation_policy_v1
        marker.argtypes = []
        marker.restype = ctypes.c_uint32
        if marker() != 2 or marker() != 2:
            raise ValueError('creation_policy_marker_mismatch')
    args.output.write_text(json.dumps(dict(adapter_creation_policy=2,
        build_marker_only=True, tunnel_started=False, network_changed=False,
        adapter_ownership_qualified=False, network_requalified=False,
        service_admitted=False, package_admitted=False, release_ready=False), indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, AttributeError):
        raise SystemExit('fresh_adapter_abi_check_failed') from None
