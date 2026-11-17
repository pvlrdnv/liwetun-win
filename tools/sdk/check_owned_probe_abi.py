"""Null-only ABI inspection; no SDK instance, socket, TUN or network startup."""
import argparse
import ctypes
import json
import os
from pathlib import Path


class Request(ctypes.Structure):
    _fields_ = [('abi', ctypes.c_uint32), ('size', ctypes.c_uint32),
                ('ttl_ms', ctypes.c_uint32), ('reserved', ctypes.c_uint32),
                ('token', ctypes.c_uint64), ('epoch', ctypes.c_uint64)]


class Snapshot(ctypes.Structure):
    _fields_ = [('abi', ctypes.c_uint32), ('size', ctypes.c_uint32),
                ('flags', ctypes.c_uint32), ('reserved', ctypes.c_uint32),
                ('token', ctypes.c_uint64), ('epoch', ctypes.c_uint64),
                ('at_ms', ctypes.c_uint64), ('tx', ctypes.c_uint64), ('rx', ctypes.c_uint64)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('disposable_windows_required')
    if ctypes.sizeof(Request) != 32 or ctypes.sizeof(Snapshot) != 56 or Snapshot.tx.offset != 40:
        raise ValueError('owned_probe_layout_mismatch')
    runtime = args.runtime.resolve()
    with os.add_dll_directory(str(runtime)):
        sdk = ctypes.WinDLL(str(runtime / 'trusttunnel.dll'))
        arm = sdk.liwetun_probe_arm_socket_v1
        arm.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(Request)]
        arm.restype = ctypes.c_uint32
        request = Request(1, 32, 5000, 0, 11, 3)
        before_request = bytes(request)
        if arm(None, 0, 32, ctypes.byref(request)) != 3 or bytes(request) != before_request:
            raise ValueError('owned_probe_null_arm_not_rejected')
        if arm(None, 0, 0, None) != 3:
            raise ValueError('owned_probe_null_request_not_rejected')
        read = sdk.liwetun_probe_snapshot_socket_v1
        read.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(Snapshot)]
        read.restype = ctypes.c_uint32
        snapshot = Snapshot()
        snapshot.flags = 0x41414141
        before = bytes(snapshot)
        if read(None, 0, 11, 56, ctypes.byref(snapshot)) != 0 or bytes(snapshot) != before:
            raise ValueError('owned_probe_null_read_not_rejected')
        if read(None, 0, 0, 0, None) != 0:
            raise ValueError('owned_probe_null_output_not_rejected')
        disarm = sdk.liwetun_probe_disarm_v1
        disarm.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        disarm.restype = ctypes.c_uint32
        if disarm(None, 11) != 0:
            raise ValueError('owned_probe_null_disarm_not_rejected')
    report = dict(owned_probe_abi=1, request_bytes=32, snapshot_bytes=56,
                  null_reads_rejected=True, null_arm_rejected=True, null_disarm_rejected=True,
                  tunnel_started=False, network_changed=False, live_sdk_path_qualified=False,
                  release_ready=False)
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, AttributeError):
        raise SystemExit('owned_probe_abi_check_failed') from None
