"""Add aggregate-only traffic instrumentation to the pinned privacy SDK candidate.

Opt-in, no runtime promotion. Every baseline is verified before any vendor write.
No connection-info generation, log sink, routing, DNS or TLS policy is enabled.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = '// MODIFIED BY LiWeTun: aggregate-only traffic instrumentation; no per-destination output.\n'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_file(root, relative):
    path = Path(relative)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('unsafe_traffic_source_path')
    current = root
    if root.is_symlink():
        raise ValueError('redirected_traffic_source_path')
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('redirected_traffic_source_path')
    if not current.is_file():
        raise ValueError('missing_traffic_source')
    return current


def verify_inputs(source, manifest):
    checked = {}
    for relative, expected in manifest['baseline_files'].items():
        data = safe_file(source, relative).read_bytes().replace(b'\r\n', b'\n')
        if digest(data) != expected:
            raise ValueError('traffic_baseline_digest_mismatch')
        checked[relative] = data.decode('utf-8')
    return checked


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('traffic_source_anchor_mismatch')
    return text.replace(before, after, 1)


def transform(files):
    result = dict(files)
    def edit(path, before, after):
        result[path] = once(result[path], before, after)

    monitor_h = 'core/src/connection_statistics.h'
    monitor_cpp = 'core/src/connection_statistics.cpp'
    edit(monitor_h, '    using Handler = std::function<void(ConnectionStatistics)>;',
         '    using Handler = std::function<void(ConnectionStatistics)>;\n'
         '    using AggregateHandler = std::function<void(uint64_t, uint64_t)>;')
    edit(monitor_h, 'uint64_t threshold_bytes = DEFAULT_THRESHOLD_BYTES);',
         'uint64_t threshold_bytes = DEFAULT_THRESHOLD_BYTES, AggregateHandler aggregate_handler = {});')
    edit(monitor_h, '    Handler m_handler;', '    Handler m_handler;\n    AggregateHandler m_aggregate_handler;')
    edit(monitor_cpp, 'VpnEventLoop *event_loop, Handler handler, Millis throttling_period, uint64_t threshold_bytes)',
         'VpnEventLoop *event_loop, Handler handler, Millis throttling_period, uint64_t threshold_bytes,\n'
         '        AggregateHandler aggregate_handler)')
    edit(monitor_cpp, '        , m_handler(std::move(handler)) {',
         '        , m_handler(std::move(handler))\n        , m_aggregate_handler(std::move(aggregate_handler)) {')
    edit(monitor_cpp, '    stats.upload += inc;',
         '    if (inc && m_aggregate_handler) m_aggregate_handler(inc, 0);\n    stats.upload += inc;')
    edit(monitor_cpp, '    stats.download += inc;',
         '    if (inc && m_aggregate_handler) m_aggregate_handler(0, inc);\n    stats.download += inc;')

    public = 'core/include/vpn/vpn.h'
    edit(public, '} VpnEvent;', '    VPN_EVENT_LIWETUN_TRAFFIC_DELTA, // Aggregate bytes only, no connection ID.\n} VpnEvent;')
    edit(public, 'typedef struct {\n    uint64_t id;       // Connection id, corresponds to the one raised in `VpnConnectRequestEvent`',
         'typedef struct {\n    uint64_t upload;\n    uint64_t download;\n} VpnLiWeTunTrafficDelta;\n\n'
         'typedef struct {\n    uint64_t id;       // Connection id, corresponds to the one raised in `VpnConnectRequestEvent`')
    internal = 'core/include/vpn/internal/vpn_client.h'
    edit(internal, '#endif                                    // __APPLE__\n};',
         '#endif                                    // __APPLE__\n    EVENT_LIWETUN_TRAFFIC_DELTA, // Aggregate bytes only.\n};')
    manager = 'core/src/vpn_manager.cpp'
    edit(manager, '    case vpn_client::EVENT_CONNECTION_STATS:\n',
         '    case vpn_client::EVENT_LIWETUN_TRAFFIC_DELTA:\n'
         '        vpn->handler.func(vpn->handler.arg, VPN_EVENT_LIWETUN_TRAFFIC_DELTA, data);\n'
         '        break;\n    case vpn_client::EVENT_CONNECTION_STATS:\n')
    tunnel = 'core/src/tunnel.cpp'
    edit(tunnel, '                raise_statistics(this, stats);\n            });',
         '                raise_statistics(this, stats);\n'
         '            }, ConnectionStatisticsMonitor::DEFAULT_THROTTLING_PERIOD,\n'
         '            ConnectionStatisticsMonitor::DEFAULT_THRESHOLD_BYTES, [this](uint64_t tx, uint64_t rx) {\n'
         '                VpnLiWeTunTrafficDelta delta{tx, rx};\n'
         '                const auto &handler = this->vpn->parameters.handler;\n'
         '                handler.func(handler.arg, vpn_client::EVENT_LIWETUN_TRAFFIC_DELTA, &delta);\n'
         '            });')
    client_h = 'trusttunnel/include/vpn/trusttunnel/client.h'
    client_cpp = 'trusttunnel/src/client.cpp'
    edit(client_h, '    std::function<void(VpnConnectionInfoEvent *)> connection_info_handler;',
         '    std::function<void(VpnConnectionInfoEvent *)> connection_info_handler;\n'
         '    std::function<void(uint64_t, uint64_t)> aggregate_traffic_handler;')
    edit(client_cpp, '    case VPN_EVENT_ENDPOINT_CONNECTION_STATS:',
         '    case VPN_EVENT_LIWETUN_TRAFFIC_DELTA: {\n'
         '        const auto *event = static_cast<const VpnLiWeTunTrafficDelta *>(data);\n'
         '        if (m_callbacks.aggregate_traffic_handler) {\n'
         '            m_callbacks.aggregate_traffic_handler(event->upload, event->download);\n'
         '        }\n        break;\n    }\n    case VPN_EVENT_ENDPOINT_CONNECTION_STATS:')
    windows = 'platform/windows/src/trusttunnel.cpp'
    edit(windows, '#include "vpn/trusttunnel/client.h"',
         '#include "vpn/trusttunnel/client.h"\n#include "liwetun_traffic_counter.h"')
    edit(windows, '    std::unique_ptr<ag::AutoNetworkMonitor> network_monitor;\n};',
         '    std::unique_ptr<ag::AutoNetworkMonitor> network_monitor;\n'
         '    std::shared_ptr<liwetun::traffic::Counter> traffic;\n};\n\n'
         'extern "C" __declspec(dllexport) uint32_t liwetun_traffic_snapshot_v1(\n'
         '        trusttunnel_t *vpn, uint32_t size, liwetun::traffic::Snapshot *output) noexcept {\n'
         '    if (!vpn || !output || size != sizeof(*output) || !vpn->traffic) return 0;\n'
         '    *output = vpn->traffic->Read();\n    return 1;\n}')
    edit(windows, '    ag::VpnCallbacks callbacks;',
         '    auto traffic = std::make_shared<liwetun::traffic::Counter>();\n'
         '    ag::VpnCallbacks callbacks;\n'
         '    callbacks.aggregate_traffic_handler = [traffic](uint64_t tx, uint64_t rx) { traffic->Add(tx, rx); };')
    edit(windows, '[state_changed_cb, state_changed_cb_arg](ag::VpnStateChangedEvent *event) {',
         '[state_changed_cb, state_changed_cb_arg, traffic](ag::VpnStateChangedEvent *event) {\n'
         '        traffic->State(event->state);')
    edit(windows, '    auto vpn = std::make_unique<trusttunnel_t>();',
         '    auto vpn = std::make_unique<trusttunnel_t>();\n    vpn->traffic = std::move(traffic);')
    return {relative: HEADER + text for relative, text in result.items()}


def prepare(source, output):
    manifest_file = ROOT / 'native/sdk/traffic-inputs.json'
    manifest = json.loads(manifest_file.read_text())
    baseline = verify_inputs(source, manifest)
    files = transform(baseline)
    additions = {}
    for relative, destination in manifest['added_files'].items():
        data = safe_file(ROOT, relative).read_bytes()
        if digest(data) != manifest['added_input_sha256'][relative]:
            raise ValueError('traffic_added_input_digest_mismatch')
        if '\r' in destination or Path(destination).is_absolute() or '..' in Path(destination).parts:
            raise ValueError('unsafe_traffic_output_path')
        target = source / destination
        current = source
        for part in Path(destination).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('redirected_traffic_source_path')
        if target.exists():
            raise ValueError('traffic_output_already_exists')
        if not target.parent.is_dir():
            raise ValueError('missing_traffic_output_parent')
        additions[destination] = data
    # All guards/anchors pass before the first vendor mutation.
    for relative, text in files.items():
        (source / relative).write_bytes(text.encode('utf-8'))
    for relative, data in additions.items():
        (source / relative).write_bytes(data)
    report = dict(sdk_commit=manifest['sdk_commit'], traffic_abi=1,
                  privacy_policy_version=1, source_pinned_candidate=True,
                  manifest_sha256=digest(manifest_file.read_bytes()),
                  patcher_sha256=digest(Path(__file__).read_bytes()),
                  baseline_newlines='lf', written_newlines='lf',
                  baseline_files=manifest['baseline_files'],
                  patched_files={relative: digest(text.encode('utf-8')) for relative, text in files.items()},
                  added_files={relative: digest(data) for relative, data in additions.items()},
                  distribution_qualified=False, network_requalified=False, release_ready=False)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'traffic-profile.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, ValueError, KeyError):
        raise SystemExit('traffic_profile_preparation_failed') from None
