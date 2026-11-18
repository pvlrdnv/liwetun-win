"""Explicit diagnostic hypothesis: prioritize submitted shutdown over ready EOF."""
import json
from pathlib import Path
import sys
from endpoint_trace_profile import digest, replace_once

ROOT=Path(__file__).resolve().parents[2]
PIN=ROOT/'tools/service/endpoint-priority-inputs.json'
ANCHOR=b'''        tokio::select! {
            x = shutdown_notification.wait() => {'''
REPLACEMENT=b'''        tokio::select! {
            // LiWeTun diagnostic: shutdown and downstream EOF can be ready together.
            biased;
            x = shutdown_notification.wait() => {'''


def transform(before):return replace_once(before,ANCHOR,REPLACEMENT)


def target(source,pin):
    if pin['file']!='lib/src/tunnel.rs':raise RuntimeError('endpoint_priority_path_mismatch')
    path=source/pin['file']
    for current in [path,*path.parents]:
        if current==source:break
        if current.is_symlink():raise RuntimeError('endpoint_priority_redirected_path')
    if path.resolve()!=source.resolve()/pin['file']:raise RuntimeError('endpoint_priority_path_mismatch')
    return path


def prepare(source):
    pin=json.loads(PIN.read_bytes());path=target(source,pin);before=path.read_bytes()
    if digest(before)!=pin['input_sha256']:raise RuntimeError('endpoint_priority_source_mismatch')
    after=transform(before)
    if digest(after)!=pin['output_sha256']:raise RuntimeError('endpoint_priority_output_mismatch')
    path.write_bytes(after)


def record(source,output):
    pin=json.loads(PIN.read_bytes())
    if digest(target(source,pin).read_bytes())!=pin['output_sha256']:raise RuntimeError('endpoint_priority_output_mismatch')
    receipt=json.loads(output.read_bytes())
    trace_pin=ROOT/'tools/service/endpoint-trace-inputs.json'
    if receipt.get('endpoint_shutdown_trace') is not True or receipt.get('endpoint_trace_manifest_sha256')!=digest(trace_pin.read_bytes()):
        raise RuntimeError('endpoint_priority_requires_trace_profile')
    receipt.update(endpoint_shutdown_priority=True,endpoint_priority_manifest_sha256=digest(PIN.read_bytes()),endpoint_priority_source_sha256=pin['output_sha256'])
    output.write_text(json.dumps(receipt,indent=2)+'\n')


if __name__=='__main__':
    try:
        source=ROOT/'build/endpoint-source'
        if sys.argv[1:]==['prepare']:prepare(source)
        elif sys.argv[1:]==['record']:record(source,ROOT/'build/endpoint/fixture-provenance.json')
        else:raise RuntimeError('invalid_endpoint_priority_mode')
    except (OSError,ValueError,KeyError,RuntimeError):
        raise SystemExit('endpoint_priority_profile_failed') from None
