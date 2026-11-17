"""Opt-in read-only SDK-held Windows interface export, after traffic preparation.

No alias lookup, pointer-layout assumptions, routing policy, logger or probes.
The caller must serialize this getter against SDK start/stop/destruction.
"""
import argparse
import hashlib
import json
from pathlib import Path
from traffic_profile import safe_file, verify_inputs, once

ROOT = Path(__file__).resolve().parents[2]
HEADER = '// MODIFIED BY LiWeTun: read-only attached Windows TUN identity; no path-health assertion.\n'


def transform(files):
    result = dict(files)
    def edit(path, before, after):
        result[path] = once(result[path], before, after)

    edit('net/include/net/os_tunnel.h', '    /** Get interface name */\n    virtual std::string get_name() = 0;',
         '#ifdef _WIN32\n'
         '    // Caller excludes concurrent init/deinit. No adapter-name lookup.\n'
         '    virtual bool liwetun_attached_interface(uint32_t &index, uint64_t &luid) const {\n'
         '        index = 0; luid = 0; return false;\n    }\n#endif\n\n'
         '    /** Get interface name */\n    virtual std::string get_name() = 0;')
    edit('net/src/os_tunnel_win.h', '    std::string get_name() override;',
         '    std::string get_name() override;\n'
         '    bool liwetun_attached_interface(uint32_t &index, uint64_t &luid) const override;')
    edit('net/src/os_tunnel_win.cpp', 'std::string ag::VpnWinTunnel::get_name() {',
         'bool ag::VpnWinTunnel::liwetun_attached_interface(uint32_t &index, uint64_t &luid) const {\n'
         '    index = 0; luid = 0;\n'
         '    if (!m_wintun_adapter || !m_wintun_session || !m_if_index || !WintunGetAdapterLUID) return false;\n'
         '    NET_LUID value{};\n'
         '    WintunGetAdapterLUID(m_wintun_adapter, &value);\n'
         '    NET_IFINDEX actual = 0;\n'
         '    if (!value.Value || ConvertInterfaceLuidToIndex(&value, &actual) != NO_ERROR\n'
         '            || actual != m_if_index) return false;\n'
         '    index = actual; luid = value.Value; return true;\n}\n\n'
         'std::string ag::VpnWinTunnel::get_name() {')
    edit('trusttunnel/include/vpn/trusttunnel/client.h', '    int disconnect();',
         '    int disconnect();\n#ifdef _WIN32\n'
         '    // Read only after connect returns; serialize against disconnect/destruction.\n'
         '    bool liwetun_attached_interface(uint32_t &index, uint64_t &luid) const;\n#endif')
    edit('trusttunnel/src/client.cpp', 'int TrustTunnelClient::disconnect() {',
         '#ifdef _WIN32\n'
         'bool TrustTunnelClient::liwetun_attached_interface(uint32_t &index, uint64_t &luid) const {\n'
         '    index = 0; luid = 0;\n'
         '    return m_vpn.load() && m_tunnel && m_tunnel->liwetun_attached_interface(index, luid);\n'
         '}\n#endif\n\nint TrustTunnelClient::disconnect() {')
    edit('platform/windows/src/trusttunnel.cpp', '#include "liwetun_traffic_counter.h"',
         '#include "liwetun_traffic_counter.h"\n#include "attached_tun_snapshot.h"')
    edit('platform/windows/src/trusttunnel.cpp', 'trusttunnel_t *trusttunnel_start_ex(',
         'extern "C" __declspec(dllexport) uint32_t liwetun_attached_tun_v1(\n'
         '        trusttunnel_t *vpn, uint32_t size, liwetun::health::AttachedTun *output) noexcept {\n'
         '    if (!vpn || !output || size != sizeof(*output) || !vpn->traffic || !vpn->client) return 0;\n'
         '    *output = {};\n'
         '    try {\n'
         '        const auto before = vpn->traffic->Read();\n'
         '        uint32_t index = 0; uint64_t luid = 0;\n'
         '        const bool attached = vpn->client->liwetun_attached_interface(index, luid);\n'
         '        const auto after = vpn->traffic->Read();\n'
         '        *output = liwetun::health::AttachedSnapshot(before, after, attached, index, luid);\n'
         '    } catch (...) { *output = {}; }\n'
         '    return 1;\n}\n\ntrusttunnel_t *trusttunnel_start_ex(')
    return {name: HEADER + text for name, text in result.items()}


def prepare(source, output, manifest_file=None):
    manifest_file = manifest_file or ROOT / 'native/sdk/attached-tun-inputs.json'
    manifest = json.loads(manifest_file.read_text())
    files = transform(verify_inputs(source, manifest))
    additions = {}
    for relative, destination in manifest['added_files'].items():
        data = safe_file(ROOT, relative).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest['added_input_sha256'][relative]:
            raise ValueError('attached_tun_header_digest_mismatch')
        path = Path(destination)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise ValueError('unsafe_attached_tun_output')
        current = source
        for part in path.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('redirected_attached_tun_output')
        if current.exists() or not current.parent.is_dir():
            raise ValueError('attached_tun_output_already_exists_or_parent_missing')
        additions[destination] = data
    # Validate every source/header/anchor/path before the first vendor write.
    written = {name: text.encode('utf-8') for name, text in files.items()} | additions
    for name, data in written.items():
        (source / name).write_bytes(data)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    report = dict(attached_tun_abi=1, snapshot_bytes=40, privacy_policy_version=1,
                  manifest_sha256=digest(manifest_file.read_bytes()),
                  patcher_sha256=digest(Path(__file__).read_bytes()),
                  baseline_files=manifest['baseline_files'],
                  written_files={name: digest(data) for name, data in written.items()},
                  caller_serializes_start_stop=True, contains_interface_identifiers=True,
                  interface_identifiers_for_internal_use_only=True,
                  adapter_ownership_proven=False, probe_traversal_proven=False,
                  network_requalified=False, release_ready=False)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'attached-tun-profile.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, ValueError, KeyError):
        raise SystemExit('attached_tun_profile_preparation_failed') from None
