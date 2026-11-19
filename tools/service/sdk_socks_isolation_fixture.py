"""Disposable feasibility only: no Wintun beside SDK; retained foreign problem node."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from network import Child, ROOT, snapshot, wait_clean
from problem_node_service_fixture import adapters, exact, sample


def main():
    if sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true' or not re.fullmatch(r'[0-9]{1,20}', os.environ.get('GITHUB_RUN_ID', '')):
        raise ValueError('disposable_windows_required')
    runtime = ROOT / 'build/socks-sdk'
    if (runtime / 'wintun.dll').exists():
        raise ValueError('driver_must_be_absent_from_sdk_directory')
    pins = json.loads((ROOT / 'native/sdk/runtime-traffic.json').read_text())
    for path, key in [(runtime / 'trusttunnel.dll', 'trusttunnel.dll'), (ROOT / 'build/socks-owner/wintun.dll', 'wintun.dll')]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != pins['files'][key]:
            raise ValueError('input_hash_mismatch')
    baseline = snapshot(); adapter_baseline = adapters()
    owner = client = None
    result = dict(passed=False, identifies_owner_refusal=False, upstream_payload_verified=False,
                  production_profile_used=False, release_ready=False, identifiers_exported=False)
    report = ROOT / 'build/socks-evidence/sdk-socks-isolation.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    stage = 'retained_node_ready'
    try:
        owner = Child([str(ROOT/'build/socks-owner/owner.exe'), str(ROOT/'build/socks-owner/wintun.dll'), '--hold'])
        exact(json.loads(owner.receive()), dict(ready=True, retained_creation_handle=True, problem_disabled_observed=True, identifiers_exported=False))
        result['before_sdk'] = sample(owner)
        stage = 'sdk_start_and_local_auth'
        client = Child([str(ROOT/'build/socks-sdk/probe.exe'), str(runtime/'trusttunnel.dll')])
        observed = json.loads(client.receive())
        if observed.get('probe_failed') is True and type(observed.get('stage')) is int and 0 <= observed['stage'] <= 4:
            result['failed_probe_stage'] = observed['stage']
        result['sdk_started'] = exact(observed, dict(ready=True, authenticated_socks_handshake=True, no_auth_refused=True, wrong_proxy_auth_refused=True, wintun_not_loaded=True, upstream_payload_verified=False))
        result['during_sdk'] = sample(owner)
        stage = 'sdk_stop'
        result['sdk_stopped'] = exact(client.command('stop'), dict(stopped=True, wintun_not_loaded=True, upstream_payload_verified=False))
        if client.process.wait(timeout=15) != 0:
            raise ValueError('sdk_probe_failed')
        client.close(); client = None
        result['after_sdk'] = sample(owner)
        stage = 'creator_cleanup'
        result['creator_cleanup'] = exact(owner.command('close'), dict(creator_restored_own_node=True, creator_closed_own_handle=True, released_node_absent=True, adapter_ownership_qualified=False, release_ready=False))
        if owner.process.wait(timeout=15) != 0:
            raise ValueError('creator_cleanup_failed')
        owner.close(); owner = None
        result['passed'] = True
    except Exception:
        result['failure'] = 'probe_or_observation_failed'
        result['failed_stage'] = stage
    finally:
        try:
            if client: client.close('stop')
            if owner: owner.close('close')
            result['routes_dns_restored'] = wait_clean(baseline)
            result['adapter_baseline_restored'] = adapters() == adapter_baseline
            result['passed'] = result['passed'] and result['routes_dns_restored'] and result['adapter_baseline_restored']
        except Exception:
            result['passed'] = False; result['cleanup_unavailable'] = True
        report.write_text(json.dumps(result, indent=2)+'\n')
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception: raise SystemExit('socks_isolation_fixture_failed') from None
