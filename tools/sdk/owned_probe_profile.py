"""Opt-in owned TCP socket correlation, after privacy/traffic/attachment profiles.

No generic tuple export, logs, browsing events, routing decision or network I/O.
Every source/header/path/anchor is checked before the first vendor mutation.
"""
import argparse
import hashlib
import json
from pathlib import Path
from traffic_profile import safe_file, verify_inputs, once

ROOT = Path(__file__).resolve().parents[2]
HEADER = '// MODIFIED BY LiWeTun: private owned-socket path correlation; no browsing diagnostic output.\n'


def transform(files):
    result = dict(files)
    def edit(name, before, after):
        result[name] = once(result[name], before, after)

    parameters = 'core/include/vpn/internal/vpn_client.h'
    edit(parameters, '#include "vpn/vpn.h"', '#include "vpn/vpn.h"\n#include "vpn/internal/probe_slot.h"')
    edit(parameters, '    CertVerifyHandler cert_verify_handler = {};',
         '    CertVerifyHandler cert_verify_handler = {};\n'
         '    std::shared_ptr<liwetun::probe::Slot> liwetun_owned_probe;')
    manager_h = 'core/src/vpn_manager.h'
    edit(manager_h, '    VpnClient client;',
         '    // Construct before client(make_client_parameters()); stable across recovery.\n'
         '    std::shared_ptr<liwetun::probe::Slot> liwetun_owned_probe = std::make_shared<liwetun::probe::Slot>();\n'
         '    VpnClient client;')
    manager = 'core/src/vpn_manager.cpp'
    edit(manager, '#include "vpn_manager.h"', '#include "vpn_manager.h"\n#include "vpn/internal/sdk_probe_core.h"')
    edit(manager, '            {ssl_verify_callback, (void *) this},',
         '            {ssl_verify_callback, (void *) this},\n            this->liwetun_owned_probe,')
    edit(manager, 'Vpn::~Vpn() = default;',
         'Vpn::~Vpn() = default;\n\n'
         'liwetun::probe::ArmResult liwetun_owned_probe_arm(Vpn *vpn, const liwetun::probe::Request &request,\n'
         '        const liwetun::probe::Key &key) noexcept {\n'
         '    return vpn && vpn->liwetun_owned_probe ? vpn->liwetun_owned_probe->Arm(request, key)\n'
         '        : liwetun::probe::ArmResult::NotReady;\n}\n'
         'liwetun::probe::Snapshot liwetun_owned_probe_read(Vpn *vpn, uint64_t token, uint64_t epoch,\n'
         '        const liwetun::probe::Key &key) noexcept {\n'
         '    return vpn && vpn->liwetun_owned_probe ? vpn->liwetun_owned_probe->Read(token, epoch, key)\n'
         '        : liwetun::probe::Snapshot{};\n}\n'
         'void liwetun_owned_probe_disarm(Vpn *vpn, uint64_t token) noexcept {\n'
         '    if (vpn && vpn->liwetun_owned_probe) vpn->liwetun_owned_probe->Disarm(token);\n}\n')
    client_h = 'trusttunnel/include/vpn/trusttunnel/client.h'
    edit(client_h, '#include "net/os_tunnel.h"', '#include "net/os_tunnel.h"\n#include "vpn/internal/sdk_probe_core.h"')
    edit(client_h, '    bool liwetun_attached_interface(uint32_t &index, uint64_t &luid) const;',
         '    bool liwetun_attached_interface(uint32_t &index, uint64_t &luid) const;\n'
         '    liwetun::probe::ArmResult liwetun_probe_arm(const liwetun::probe::Request &, const liwetun::probe::Key &) const noexcept;\n'
         '    liwetun::probe::Snapshot liwetun_probe_read(uint64_t, uint64_t, const liwetun::probe::Key &) const noexcept;\n'
         '    void liwetun_probe_disarm(uint64_t) const noexcept;')
    client = 'trusttunnel/src/client.cpp'
    edit(client, 'int TrustTunnelClient::disconnect() {',
         '#ifdef _WIN32\n'
         'liwetun::probe::ArmResult TrustTunnelClient::liwetun_probe_arm(const liwetun::probe::Request &request,\n'
         '        const liwetun::probe::Key &key) const noexcept {\n'
         '    return liwetun_owned_probe_arm(m_vpn.load(), request, key);\n}\n'
         'liwetun::probe::Snapshot TrustTunnelClient::liwetun_probe_read(uint64_t token, uint64_t epoch,\n'
         '        const liwetun::probe::Key &key) const noexcept {\n'
         '    return liwetun_owned_probe_read(m_vpn.load(), token, epoch, key);\n}\n'
         'void TrustTunnelClient::liwetun_probe_disarm(uint64_t token) const noexcept {\n'
         '    liwetun_owned_probe_disarm(m_vpn.load(), token);\n}\n#endif\n\n'
         'int TrustTunnelClient::disconnect() {')
    windows = 'platform/windows/src/trusttunnel.cpp'
    edit(windows, '#include "attached_tun_snapshot.h"',
         '#include "attached_tun_snapshot.h"\n#include "vpn/internal/windows_probe_socket.h"')
    edit(windows, 'trusttunnel_t *trusttunnel_start_ex(',
         '#include "owned_probe_exports.inc"\n\ntrusttunnel_t *trusttunnel_start_ex(')
    tunnel = 'core/src/tunnel.cpp'
    edit(tunnel, '#include "vpn/internal/vpn_client.h"',
         '#include "vpn/internal/vpn_client.h"\n#include "vpn/internal/probe_tunnel_adapter.h"')
    edit(tunnel, '            conn->outgoing_bytes += r;',
         '            conn->outgoing_bytes += r;\n'
         '            liwetun_owned_probe_bytes(self->vpn, conn, upstream.get() == self->vpn->endpoint_upstream.get()\n'
         '                && listener.get() == self->vpn->client_listener.get(), static_cast<uint64_t>(r), 0);')
    edit(tunnel, '            conn->incoming_bytes += event->result;',
         '            conn->incoming_bytes += event->result;\n'
         '            liwetun_owned_probe_bytes(this->vpn, conn, upstream.get() == this->vpn->endpoint_upstream.get()\n'
         '                && listener.get() == this->vpn->client_listener.get(), 0, static_cast<uint64_t>(event->result));')
    edit(tunnel, '                conn->outgoing_bytes += event->result;',
         '                conn->outgoing_bytes += event->result;\n'
         '                liwetun_owned_probe_bytes(this->vpn, conn, upstream.get() == this->vpn->endpoint_upstream.get()\n'
         '                    && listener.get() == this->vpn->client_listener.get(), static_cast<uint64_t>(event->result), 0);')
    edit(tunnel, '        Tunnel *self, VpnConnection *conn, std::shared_ptr<ServerUpstream> upstream, U8View packet) {',
         '        Tunnel *self, VpnConnection *conn, std::shared_ptr<ServerUpstream> upstream, U8View packet) {\n'
         '    liwetun_owned_probe_reject(self->vpn, conn, liwetun::probe::kMigrated);')
    edit(tunnel, '    conn->addr.dst = address;',
         '    conn->addr.dst = address;\n'
         '    liwetun_owned_probe_selected(self->vpn, conn, upstream.get() == self->vpn->endpoint_upstream.get());')
    edit(tunnel, '    conn->upstream = upstream;\n    if (!this->endpoint_upstream_connected',
         '    conn->upstream = upstream;\n'
         '    liwetun_owned_probe_selected(this->vpn, conn, upstream.get() == this->vpn->endpoint_upstream.get());\n'
         '    if (!this->endpoint_upstream_connected')
    return {name: HEADER + text for name, text in result.items()}


def prepare(source, output, manifest_file=None):
    manifest_file = manifest_file or ROOT / 'native/sdk/owned-probe-inputs.json'
    manifest = json.loads(manifest_file.read_text())
    files = transform(verify_inputs(source, manifest))
    additions = {}
    for name, destination in manifest['added_files'].items():
        data = safe_file(ROOT, name).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest['added_input_sha256'][name]:
            raise ValueError('owned_probe_header_digest_mismatch')
        path = Path(destination)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise ValueError('unsafe_owned_probe_output')
        current = source
        for part in path.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('redirected_owned_probe_output')
        if current.exists() or not current.parent.is_dir():
            raise ValueError('owned_probe_output_exists_or_parent_missing')
        additions[destination] = data
    written = {name: text.encode('utf-8') for name, text in files.items()} | additions
    for name, data in written.items():
        (source / name).write_bytes(data)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    report = dict(sdk_commit=manifest['sdk_commit'], owned_probe_abi=1, request_bytes=32, snapshot_bytes=56,
                  privacy_policy_version=1, manifest_sha256=digest(manifest_file.read_bytes()),
                  patcher_sha256=digest(Path(__file__).read_bytes()), baseline_files=manifest['baseline_files'],
                  written_files={name: digest(data) for name, data in written.items()},
                  caller_serializes_start_stop=True, caller_holds_fresh_socket=True,
                  private_tuple_registration_exported=False, browsing_events_enabled=False,
                  routing_policy_changed=False, live_sdk_path_qualified=False, release_ready=False)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'owned-probe-profile.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, ValueError, KeyError):
        raise SystemExit('owned_probe_profile_preparation_failed') from None
