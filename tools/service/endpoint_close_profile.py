"""Opt-in, exact-source wakeup candidate for the disposable endpoint only."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / 'tools/service/endpoint-close-inputs.json'
OLD = b'''                // Client finished sending request body; keep write side open for response.
                let _ = self.on_stream_shutdown(stream_id, Some(quiche::Shutdown::Read));'''
NEW = b'''                // Wake a body reader before shutting down its read side. It may
                // be parked on readable_event_rx with no more Data event coming.
                let _ = self.on_stream_readable(stream_id);
                // Client finished sending request body; keep write side open for response.
                let _ = self.on_stream_shutdown(stream_id, Some(quiche::Shutdown::Read));'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prepare(source):
    pin = json.loads(PIN.read_bytes())
    target = source / 'lib/src/http3_codec.rs'
    if target.is_symlink() or target.resolve() != source.resolve() / pin['file']:
        raise RuntimeError('endpoint_close_path_mismatch')
    before = target.read_bytes()
    if digest(before) != pin['input_sha256'] or before.count(OLD) != 1:
        raise RuntimeError('endpoint_close_source_mismatch')
    after = before.replace(OLD, NEW)
    if digest(after) != pin['output_sha256']:
        raise RuntimeError('endpoint_close_output_mismatch')
    target.write_bytes(after)


def record(source, output):
    pin = json.loads(PIN.read_bytes())
    if digest((source / pin['file']).read_bytes()) != pin['output_sha256']:
        raise RuntimeError('endpoint_close_output_mismatch')
    receipt = json.loads(output.read_bytes())
    receipt.update(endpoint_close_fix=True, endpoint_close_manifest_sha256=digest(PIN.read_bytes()),
                   endpoint_close_source_sha256=pin['output_sha256'])
    output.write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    source = ROOT / 'build/endpoint-source'
    if sys.argv[1:] == ['prepare']:
        prepare(source)
    elif sys.argv[1:] == ['record']:
        record(source, ROOT / 'build/endpoint/fixture-provenance.json')
    else:
        raise SystemExit('invalid_endpoint_close_mode')
