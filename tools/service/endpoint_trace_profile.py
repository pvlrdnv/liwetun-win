"""Closed counters in a separate disposable endpoint; no transport policy change."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / 'tools/service/endpoint-trace-inputs.json'
FILES = ('lib/src/lib.rs', 'lib/src/quic_multiplexer.rs', 'endpoint/src/main.rs')
COUNTERS = b'''
// LiWeTun disposable shutdown observations: process totals only, no identities.
static LIWETUN_SHUTDOWN: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
pub(crate) fn liwetun_shutdown_observation() -> [u64; 8] {
    std::array::from_fn(|i| LIWETUN_SHUTDOWN[i].load(Ordering::SeqCst))
}
'''
GRACEFUL = b'''        self.quic_conn
            .lock()
            .unwrap()
            .close(true, 0, b"bye")
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.flush_pending_data()
'''
TRACED = b'''        LIWETUN_SHUTDOWN[0].fetch_add(1, Ordering::SeqCst);
        self.quic_conn
            .lock()
            .unwrap()
            .close(true, 0, b"bye")
            .map_err(|e| {
                LIWETUN_SHUTDOWN[2].fetch_add(1, Ordering::SeqCst);
                io::Error::other(e.to_string())
            })?;
        LIWETUN_SHUTDOWN[1].fetch_add(1, Ordering::SeqCst);
        let result = self.flush_pending_data();
        LIWETUN_SHUTDOWN[if result.is_ok() { 3 } else { 4 }].fetch_add(1, Ordering::SeqCst);
        result
'''
EXPORT = b'''
/// Disposable LiWeTun fixture counters, not a public health or delivery proof.
pub fn liwetun_shutdown_observation() -> [u64; 8] {
    quic_multiplexer::liwetun_shutdown_observation()
}
'''
EXIT = b'    std::process::exit(exit_code);'
WRITE = b'''    let observation = trusttunnel::liwetun_shutdown_observation();
    let report = format!("{{\\\"schema_version\\\":1,\\\"counters\\\":{:?},\\\"release_ready\\\":false}}\\n", observation);
    if std::fs::write("liwetun-ci-shutdown.json", report).is_err() {
        std::process::exit(2);
    }
    std::process::exit(exit_code);'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(data, old, new):
    if data.count(old) != 1:
        raise RuntimeError('endpoint_trace_anchor_mismatch')
    return data.replace(old, new)


def transform(name, before):
    if name == FILES[0]:
        return replace_once(before, b'mod quic_multiplexer;', b'mod quic_multiplexer;' + EXPORT)
    if name == FILES[1]:
        after=replace_once(before, b'const TOKEN_PREFIX_SIZE: usize = 16;', COUNTERS + b'\nconst TOKEN_PREFIX_SIZE: usize = 16;')
        after=replace_once(after, GRACEFUL, TRACED)
        anchor=b'''    match socket.try_send_to(data, *peer) {
        Ok(_) => Ok(()),'''
        after=replace_once(after, anchor, b'''    match socket.try_send_to(data, *peer) {
        Ok(_) => { LIWETUN_SHUTDOWN[5].fetch_add(1, Ordering::SeqCst); Ok(()) },''')
        anchor=b'''        Err(e) if e.kind() == ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) => {'''
        after=replace_once(after, anchor, anchor+b'\n            LIWETUN_SHUTDOWN[6].fetch_add(1, Ordering::SeqCst);')
        # Match only this final helper, not unrelated error branches.
        anchor=b'''        Err(e) => Err(e),
    }
}'''
        return replace_once(after, anchor, b'''        Err(e) => { LIWETUN_SHUTDOWN[7].fetch_add(1, Ordering::SeqCst); Err(e) },
    }
}''')
    if name == FILES[2]:
        return replace_once(before, EXIT, WRITE)
    raise RuntimeError('endpoint_trace_path_mismatch')


def targets(source, pin):
    if set(pin['files']) != set(FILES):
        raise RuntimeError('endpoint_trace_path_mismatch')
    result=[]
    for name in FILES:
        target=source/name
        for current in [target,*target.parents]:
            if current==source:
                break
            if current.is_symlink():
                raise RuntimeError('endpoint_trace_redirected_path')
        if target.resolve()!=source.resolve()/name:
            raise RuntimeError('endpoint_trace_path_mismatch')
        result.append((name,target))
    return result


def prepare(source):
    pin=json.loads(PIN.read_bytes());pending=[]
    for name,target in targets(source,pin):
        before=target.read_bytes()
        if digest(before)!=pin['files'][name]['input_sha256']:
            raise RuntimeError('endpoint_trace_source_mismatch')
        after=transform(name,before)
        if digest(after)!=pin['files'][name]['output_sha256']:
            raise RuntimeError('endpoint_trace_output_mismatch')
        pending.append((target,after))
    for target,after in pending:
        target.write_bytes(after)


def record(source,output):
    pin=json.loads(PIN.read_bytes())
    for name,target in targets(source,pin):
        if digest(target.read_bytes())!=pin['files'][name]['output_sha256']:
            raise RuntimeError('endpoint_trace_output_mismatch')
    receipt=json.loads(output.read_bytes())
    shutdown_pin=ROOT/'tools/service/endpoint-shutdown-inputs.json'
    if receipt.get('endpoint_shutdown_fix') is not True or receipt.get('endpoint_shutdown_manifest_sha256')!=digest(shutdown_pin.read_bytes()):
        raise RuntimeError('endpoint_trace_requires_shutdown_profile')
    receipt.update(endpoint_shutdown_trace=True,endpoint_trace_manifest_sha256=digest(PIN.read_bytes()),
                   endpoint_trace_source_hashes={name:pin['files'][name]['output_sha256'] for name in FILES})
    output.write_text(json.dumps(receipt,indent=2)+'\n')


if __name__=='__main__':
    try:
        source=ROOT/'build/endpoint-source'
        if sys.argv[1:]==['prepare']: prepare(source)
        elif sys.argv[1:]==['record']: record(source,ROOT/'build/endpoint/fixture-provenance.json')
        else: raise RuntimeError('invalid_endpoint_trace_mode')
    except (OSError,ValueError,KeyError,RuntimeError):
        raise SystemExit('endpoint_trace_profile_failed') from None
