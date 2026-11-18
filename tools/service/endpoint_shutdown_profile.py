"""Opt-in diagnostic endpoint shutdown completion barrier; never production."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / 'tools/service/endpoint-shutdown-inputs.json'
CAPTURE = b'''    #[allow(clippy::await_holding_lock)]
    let interrupt_task = async move {'''
EXIT = b'    std::process::exit(exit_code);'
BARRIER = b'''    // LiWeTun disposable fixture: listen_task may win the shutdown select
    // before connection guards drain. Do not exit(0) before completion.
    if exit_code == 0 {
        #[allow(clippy::await_holding_lock)]
        let completed = rt.block_on(async move {
            tokio::time::timeout(std::time::Duration::from_secs(2), async move {
                liwetun_shutdown_completion.lock().unwrap().completion().await
            }).await
        });
        if completed.is_err() {
            std::process::exit(1);
        }
    }
    std::process::exit(exit_code);'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transform(before):
    if before.count(CAPTURE) != 1 or before.count(EXIT) != 1:
        raise RuntimeError('endpoint_shutdown_anchor_mismatch')
    return before.replace(CAPTURE, b'    let liwetun_shutdown_completion = shutdown.clone();\n\n' + CAPTURE).replace(EXIT, BARRIER)


def checked_target(source, pin):
    if pin['file'] != 'endpoint/src/main.rs':
        raise RuntimeError('endpoint_shutdown_path_mismatch')
    target = source / pin['file']
    for current in [target, *target.parents]:
        if current == source:
            break
        if current.is_symlink():
            raise RuntimeError('endpoint_shutdown_redirected_path')
    if target.resolve() != source.resolve() / pin['file']:
        raise RuntimeError('endpoint_shutdown_path_mismatch')
    return target


def prepare(source):
    pin = json.loads(PIN.read_bytes())
    target = checked_target(source, pin)
    before = target.read_bytes()
    if digest(before) != pin['input_sha256']:
        raise RuntimeError('endpoint_shutdown_source_mismatch')
    after = transform(before)
    if digest(after) != pin['output_sha256']:
        raise RuntimeError('endpoint_shutdown_output_mismatch')
    target.write_bytes(after)


def record(source, output):
    pin = json.loads(PIN.read_bytes())
    if digest(checked_target(source, pin).read_bytes()) != pin['output_sha256']:
        raise RuntimeError('endpoint_shutdown_output_mismatch')
    receipt = json.loads(output.read_bytes())
    close_pin = ROOT / 'tools/service/endpoint-close-inputs.json'
    if (receipt.get('endpoint_close_fix') is not True
            or receipt.get('endpoint_close_manifest_sha256') != digest(close_pin.read_bytes())):
        raise RuntimeError('endpoint_shutdown_requires_close_profile')
    receipt.update(endpoint_shutdown_fix=True, endpoint_shutdown_manifest_sha256=digest(PIN.read_bytes()),
                   endpoint_shutdown_source_sha256=pin['output_sha256'])
    output.write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    try:
        source = ROOT / 'build/endpoint-source'
        if sys.argv[1:] == ['prepare']:
            prepare(source)
        elif sys.argv[1:] == ['record']:
            record(source, ROOT / 'build/endpoint/fixture-provenance.json')
        else:
            raise RuntimeError('invalid_endpoint_shutdown_mode')
    except (OSError, ValueError, KeyError, RuntimeError):
        raise SystemExit('endpoint_shutdown_profile_failed') from None
