"""Null-read ABI check only; never starts an SDK, adapter or network probe."""
import argparse
import ctypes
import json
import os
from pathlib import Path


class AttachedTun(ctypes.Structure):
    _fields_ = [('abi', ctypes.c_uint32), ('size', ctypes.c_uint32),
                ('flags', ctypes.c_uint32), ('index', ctypes.c_uint32),
                ('luid', ctypes.c_uint64), ('epoch', ctypes.c_uint64),
                ('at_ms', ctypes.c_uint64)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('disposable_windows_required')
    if ctypes.sizeof(AttachedTun) != 40 or AttachedTun.luid.offset != 16 or AttachedTun.at_ms.offset != 32:
        raise ValueError('attached_tun_abi_layout_mismatch')
    runtime = args.runtime.resolve()
    with os.add_dll_directory(str(runtime)):
        sdk = ctypes.WinDLL(str(runtime / 'trusttunnel.dll'))
        getter = sdk.liwetun_attached_tun_v1
        getter.restype = ctypes.c_uint32
        getter.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(AttachedTun)]
        output = AttachedTun()
        output.flags = 0x41414141
        before = bytes(output)
        if getter(None, 40, ctypes.byref(output)) != 0 or bytes(output) != before:
            raise ValueError('attached_tun_null_instance_not_rejected')
        if getter(None, 0, None) != 0:
            raise ValueError('attached_tun_null_request_not_rejected')
    report = dict(attached_tun_abi=1, snapshot_bytes=40, null_reads_rejected=True,
                  tunnel_started=False, network_changed=False,
                  actual_interface_qualified=False, probe_traversal_proven=False,
                  adapter_ownership_proven=False, release_ready=False)
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, AttributeError):
        raise SystemExit('attached_tun_abi_check_failed') from None
