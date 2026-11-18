"""Opt-in create-only SDK candidate, after the owned-probe profile.

No existing handle adoption; original signed Wintun remains unmodified.
All source/header/path checks precede vendor writes. Not release admission.
"""
import argparse
import hashlib
import json
from pathlib import Path
from traffic_profile import safe_file, verify_inputs, once

ROOT = Path(__file__).resolve().parents[2]
HEADER = '// MODIFIED BY LiWeTun: private fresh create-only adapter candidate; no ownership qualification.\n'


def transform(files):
    result = dict(files)
    def edit(name, before, after):
        result[name] = once(result[name], before, after)

    cpp = 'net/src/os_tunnel_win.cpp'
    header = 'net/src/os_tunnel_win.h'
    edit(cpp, '#include <openssl/sha.h>\n', '')
    edit(cpp, '#include "os_tunnel_win.h"', '#include "os_tunnel_win.h"\n#include "windows_fresh_adapter.h"')
    edit(cpp, 'static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;\n', '')
    edit(cpp, ' || X(WintunOpenAdapter)', '')
    start = result[cpp].index('static GUID uuid_v5(')
    end = result[cpp].index('static void WINAPI send_wintun_packet(', start)
    edit(cpp, result[cpp][start:end], '''static liwetun::adapter::Created<WINTUN_ADAPTER_HANDLE> create_wintun_adapter(std::string_view tunnel_type) {
    const auto type = ag::utils::to_wstring(tunnel_type);
    liwetun::adapter::WindowsOps ops(WintunCreateAdapter, WintunCloseAdapter, WintunGetAdapterLUID, type.c_str());
    return liwetun::adapter::CreateFresh(ops);
}

''')
    start = result[cpp].index('static uint32_t get_wintun_adapter_index(')
    end = result[cpp].index('static WINTUN_SESSION_HANDLE create_wintun_session(', start)
    edit(cpp, result[cpp][start:end], '')
    edit(cpp, '    init_settings(settings);',
         '    if (m_wintun_adapter || m_wintun_session || m_liwetun_created.luid) {\n'
         '        return {-1, "Tunnel already initialized"};\n    }\n    init_settings(settings);')
    edit(cpp, '    m_wintun_adapter = create_wintun_adapter(settings->device_name, win_settings->tunnel_type);',
         '    const auto created = create_wintun_adapter(win_settings->tunnel_type);\n'
         '    m_wintun_adapter = created.handle;\n    m_liwetun_created = created.authority;')
    edit(cpp, '    m_if_index = get_wintun_adapter_index(m_wintun_adapter);',
         '    m_if_index = m_liwetun_created.index;')
    edit(cpp, '    stop_recv_packets(); // for case when it wasn\'t called manually\n'
         '    close_wintun(m_wintun_session, m_wintun_adapter);',
         '    stop_recv_packets(); // for case when it wasn\'t called manually\n'
         '    m_liwetun_created = {}; // withdraw authority before releasing this attempt\n'
         '    close_wintun(m_wintun_session, m_wintun_adapter);\n    m_if_index = 0;')
    edit(cpp, 'ag::VpnWinTunnel::~VpnWinTunnel() {',
         'ag::VpnWinTunnel::~VpnWinTunnel() {\n    m_liwetun_created = {};')
    start = result[cpp].index('    NET_LUID value{};', result[cpp].index('bool ag::VpnWinTunnel::liwetun_attached_interface('))
    end = result[cpp].index('\n}', start)
    edit(cpp, result[cpp][start:end], '''    liwetun::adapter::WindowsOps ops(WintunCreateAdapter, WintunCloseAdapter, WintunGetAdapterLUID, nullptr);
    liwetun::adapter::Observation actual{};
    if (!ops.Observe(m_wintun_adapter, actual) || !liwetun::adapter::Matches(actual, m_liwetun_created)
            || actual.index != m_if_index) return false;
    index = actual.index; luid = actual.luid; return true;''')
    edit(header, '#include <wintun.h>', '#include <wintun.h>\n#include "fresh_adapter.h"')
    edit(header, '    WINTUN_ADAPTER_HANDLE m_wintun_adapter{nullptr};',
         '    liwetun::adapter::Observation m_liwetun_created{};\n'
         '    WINTUN_ADAPTER_HANDLE m_wintun_adapter{nullptr};')
    windows = 'platform/windows/src/trusttunnel.cpp'
    edit(windows, 'trusttunnel_t *trusttunnel_start_ex(',
         '// Build policy marker only; never a per-instance ownership/health receipt.\n'
         'extern "C" __declspec(dllexport) uint32_t liwetun_adapter_creation_policy_v1() noexcept { return 1; }\n\n'
         'trusttunnel_t *trusttunnel_start_ex(')
    if 'WintunOpenAdapter' in result[cpp] or 'uuid_v5' in result[cpp]:
        raise ValueError('adoption_path_remains')
    return {name: HEADER + text for name, text in result.items()}


def prepare(source, output, manifest_file=None):
    manifest_file = manifest_file or ROOT / 'native/sdk/fresh-adapter-inputs.json'
    manifest = json.loads(manifest_file.read_text())
    sdk_commit = manifest['sdk_commit']
    files = transform(verify_inputs(source, manifest))
    additions = {}
    for name, destination in manifest['added_files'].items():
        data = safe_file(ROOT, name).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest['added_input_sha256'][name]:
            raise ValueError('fresh_adapter_header_digest_mismatch')
        path = Path(destination)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise ValueError('unsafe_fresh_adapter_output')
        current = source
        for part in path.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('redirected_fresh_adapter_output')
        if current.exists() or not current.parent.is_dir():
            raise ValueError('fresh_adapter_output_exists_or_parent_missing')
        additions[destination] = data
    written = {name: text.encode('utf-8') for name, text in files.items()} | additions
    for name, data in written.items():
        (source / name).write_bytes(data)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    report = dict(sdk_commit=sdk_commit, adapter_creation_policy=1,
                  manifest_sha256=digest(manifest_file.read_bytes()),
                  patcher_sha256=digest(Path(__file__).read_bytes()), baseline_files=manifest['baseline_files'],
                  written_files={name: digest(data) for name, data in written.items()},
                  open_existing_adapter=False, private_random_guid_and_alias=True,
                  verify_created_handle_before_configuration=True, original_wintun_unchanged=True,
                  identifiers_exported=False, privileged_physical_name_race_qualified=False,
                  adapter_ownership_qualified=False, network_requalified=False,
                  service_admitted=False, package_admitted=False, release_ready=False)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'fresh-adapter-profile.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, ValueError, KeyError):
        raise SystemExit('fresh_adapter_profile_preparation_failed') from None
