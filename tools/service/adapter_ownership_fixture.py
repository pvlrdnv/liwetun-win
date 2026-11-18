"""Closed disposable-CI reproduction, not ownership-safety qualification."""
import json
import subprocess
import time


FIELDS = {'available', 'alias_unchanged', 'ipv4_changed', 'mtu_changed', 'metric_changed',
          'fixture_marker_present', 'nonlink_ipv4_count'}


def validate_ready(value):
    expected = dict(ready=True, fixture_created_adapter=True, retained_creation_handle=True,
                    marker_verified=True, identifiers_exported=False, release_ready=False)
    if (not isinstance(value, dict) or value != expected or set(value) != set(expected)
            or any(type(v) is not bool for v in value.values())):
        raise ValueError('adapter_owner_fixture_not_ready')
    return value


def validate_cleanup(value):
    if (not isinstance(value, dict) or set(value) != {'fixture_adapter_removed', 'release_ready'}
            or value != dict(fixture_adapter_removed=True, release_ready=False)
            or any(type(v) is not bool for v in value.values())):
        raise ValueError('adapter_owner_fixture_cleanup_failed')
    return value


def validate_sample(value):
    if not isinstance(value, dict) or set(value) != FIELDS or type(value['available']) is not bool:
        raise ValueError('invalid_adapter_owner_sample')
    others = FIELDS - {'available', 'nonlink_ipv4_count'}
    if value['available']:
        if (any(type(value[k]) is not bool for k in others)
                or type(value['nonlink_ipv4_count']) is not int or not 0 <= value['nonlink_ipv4_count'] <= 32):
            raise ValueError('invalid_adapter_owner_sample')
    elif any(value[k] is not None for k in FIELDS - {'available'}):
        raise ValueError('invalid_adapter_owner_sample')
    return value


def pristine(value):
    validate_sample(value)
    return (value['available'] and value['alias_unchanged'] and value['fixture_marker_present']
            and not any(value[k] for k in ['ipv4_changed', 'mtu_changed', 'metric_changed'])
            and value['nonlink_ipv4_count'] == 0)


def interference(value):
    validate_sample(value)
    return (value['available'] and value['alias_unchanged'] and not value['fixture_marker_present']
            and all(value[k] for k in ['ipv4_changed', 'mtu_changed', 'metric_changed'])
            and value['nonlink_ipv4_count'] > 0)


def observe_reproduction(session, owner, client, diagnostic):
    """Require actual changes on the retained fixture adapter; process state alone is insufficient."""
    started = time.monotonic()
    active = None
    while time.monotonic() - started < 12:
        state = session.command('query')
        active = validate_sample(owner.command('sample'))
        diagnostic.update(active=active, state=state.get('state'))
        if type(state.get('code')) is int and state['code'] == 0 and type(state.get('state')) is int and state['state'] == 2 and interference(active):
            break
        if state.get('state') == 4:
            break
        time.sleep(.05)
    else:
        raise RuntimeError('adapter_interference_not_reproduced')
    if type(state.get('code')) is not int or state['code'] != 0 or type(state.get('state')) is not int or state['state'] != 2 or not interference(active):
        raise RuntimeError('adapter_interference_not_reproduced')
    stopped = session.command('stop')
    if type(stopped.get('code')) is not int or stopped['code'] != 0:
        raise RuntimeError('adapter_owner_stop_failed')
    # The network-session child exits after Stop. Query via a fresh trusted
    # client, requiring SDK teardown before releasing the fixture's own handle.
    for _ in range(20):
        process = subprocess.run([str(client), '--query'], capture_output=True, text=True, timeout=10)
        if process.returncode or len(process.stdout) > 2048:
            raise RuntimeError('adapter_owner_stop_failed')
        state = json.loads(process.stdout)
        if type(state.get('code')) is int and state['code'] == 0 and type(state.get('state')) is int and state['state'] == 0:
            break
        time.sleep(.05)
    else:
        raise RuntimeError('adapter_owner_stop_failed')
    after = validate_sample(owner.command('sample'))
    diagnostic['after_stop'] = after
    if not after['available'] or not after['alias_unchanged']:
        raise RuntimeError('fixture_adapter_not_retained')
    return dict(reproduction_passed=True, ownership_safe=False, active=active, after_stop=after,
                scope='retained_fixture_adapter_ipv4_mtu_metric_alias_only',
                sdk_stopped_before_fixture_close=True, identifiers_exported=False,
                adapter_ownership_qualified=False, release_ready=False)
