"""Bounded closed shutdown observations; send acceptance never proves delivery."""
import json
from pathlib import Path

FIELDS=('quic_close_attempts','quic_close_accepted','quic_close_errors','close_flush_ok',
        'close_flush_errors','process_udp_send_ok','process_udp_would_block_drops','process_udp_send_errors')


def validate_raw(value):
    if (not isinstance(value,dict) or set(value)!={'schema_version','counters','release_ready'}
            or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['release_ready'] is not False or not isinstance(value['counters'],list)
            or len(value['counters'])!=len(FIELDS)
            or any(type(v) is not int or not 0<=v<=2**64-1 for v in value['counters'])):
        raise ValueError('invalid_endpoint_shutdown_observation')
    values=dict(zip(FIELDS,value['counters']))
    if (values['quic_close_attempts']!=values['quic_close_accepted']+values['quic_close_errors']
            or values['quic_close_accepted']!=values['close_flush_ok']+values['close_flush_errors']):
        raise ValueError('invalid_endpoint_shutdown_observation')
    return dict(schema_version=1,available=True,counters=values,proves_close_delivery=False,
                proves_client_epoch_change=False,release_ready=False)


def read(directory):
    target=Path(directory)/'liwetun-ci-shutdown.json'
    try:
        if target.is_symlink() or target.stat().st_size>1024:
            raise ValueError('invalid_endpoint_shutdown_observation')
        with target.open('rb') as source:raw=source.read(1025)
        if len(raw)>1024:raise ValueError('invalid_endpoint_shutdown_observation')
        return validate_raw(json.loads(raw))
    except (OSError,ValueError):
        return dict(schema_version=1,available=False,counters=None,proves_close_delivery=False,
                    proves_client_epoch_change=False,release_ready=False)


def validate(value):
    if not isinstance(value,dict) or set(value)!={'schema_version','available','counters',
            'proves_close_delivery','proves_client_epoch_change','release_ready'}:
        raise ValueError('invalid_endpoint_shutdown_observation')
    if (type(value['schema_version']) is not int or value['schema_version']!=1
            or type(value['available']) is not bool or value['proves_close_delivery'] is not False
            or value['proves_client_epoch_change'] is not False or value['release_ready'] is not False):
        raise ValueError('invalid_endpoint_shutdown_observation')
    if value['available']:
        if not isinstance(value['counters'],dict) or set(value['counters'])!=set(FIELDS):
            raise ValueError('invalid_endpoint_shutdown_observation')
        validate_raw(dict(schema_version=1,counters=[value['counters'][k] for k in FIELDS],release_ready=False))
    elif value['counters'] is not None:
        raise ValueError('invalid_endpoint_shutdown_observation')
    return value


def validate_restart(value, trace):
    expected={'restarted','outage_seconds','graceful_shutdown'}
    if trace:expected.add('shutdown_observation')
    if (not isinstance(value,dict) or set(value)!=expected or value['restarted'] is not True
            or type(value['outage_seconds']) is not int or value['outage_seconds']!=2
            or value['graceful_shutdown'] is not True):
        raise ValueError('endpoint_restart_failed')
    if trace:validate(value['shutdown_observation'])
    return value
