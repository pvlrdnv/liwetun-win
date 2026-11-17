"""Inspect the isolated candidate ABI without starting an SDK instance or network."""
import argparse
import ctypes
import json
import os
from pathlib import Path


class Snapshot(ctypes.Structure):
    _fields_ = [('abi', ctypes.c_uint32), ('size', ctypes.c_uint32),
                ('flags', ctypes.c_uint32), ('state', ctypes.c_uint32),
                ('epoch', ctypes.c_uint64), ('at_ms', ctypes.c_uint64),
                ('tx', ctypes.c_uint64), ('rx', ctypes.c_uint64),
                ('last_tx_ms', ctypes.c_uint64), ('last_rx_ms', ctypes.c_uint64)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('disposable_windows_required')
    if ctypes.sizeof(Snapshot) != 64 or Snapshot.epoch.offset != 16 or Snapshot.last_rx_ms.offset != 56:
        raise ValueError('traffic_abi_layout_mismatch')
    runtime = args.runtime.resolve()
    with os.add_dll_directory(str(runtime)):
        sdk = ctypes.WinDLL(str(runtime / 'trusttunnel.dll'))
        sdk.liwetun_core_policy_version.restype = ctypes.c_int32
        if sdk.liwetun_core_policy_version() != 1:
            raise ValueError('traffic_abi_privacy_marker_mismatch')
        getter = sdk.liwetun_traffic_snapshot_v1
        getter.restype = ctypes.c_uint32
        getter.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(Snapshot)]
        output = Snapshot()
        output.flags = 0x41414141
        before = bytes(output)
        if getter(None, 64, ctypes.byref(output)) != 0 or bytes(output) != before:
            raise ValueError('traffic_abi_null_instance_not_rejected')
        if getter(None, 0, None) != 0:
            raise ValueError('traffic_abi_null_request_not_rejected')
    report = dict(traffic_abi=1, snapshot_bytes=64, null_reads_rejected=True,
                  privacy_policy_version=1, tunnel_started=False, network_changed=False,
                  release_ready=False)
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, AttributeError):
        raise SystemExit('traffic_abi_check_failed') from None
