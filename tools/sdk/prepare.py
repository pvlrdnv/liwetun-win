"""Apply the reviewed LiWeTun privacy profile to an exact upstream SDK tree.

Changes instrumentation only: raw logger sinks become no-ops, connection-info
generation is disabled, and a profile marker is exported. No routing/TLS/core
algorithm is replaced. Fails on changed upstream input or unsafe bootstrap paths.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('upstream_anchor_mismatch')
    return text.replace(old, new, 1)


def prepare(source, bootstrap, output):
    lock = json.loads((ROOT / 'native/sdk/inputs.json').read_text())
    if hashlib.sha256(bootstrap.read_bytes()).hexdigest() != lock['bootstrap']['sha256']:
        raise ValueError('bootstrap_digest_mismatch')
    for relative, digest in lock['patched_inputs'].items():
        if hashlib.sha256((source / relative).read_bytes().replace(b'\r\n', b'\n')).hexdigest() != digest:
            raise ValueError('sdk_source_digest_mismatch')

    conan = source / 'conan'
    conan.mkdir(exist_ok=True)
    with tarfile.open(bootstrap) as archive:
        for entry in archive.getmembers():
            name = Path(entry.name)
            if name.is_absolute() or '..' in name.parts or entry.issym() or entry.islnk() or not (entry.isfile() or entry.isdir()):
                raise ValueError('unsafe_bootstrap_archive')
        archive.extractall(conan, filter='data')
    provider = conan / 'conan_provider.cmake'
    text = provider.read_text()
    text = replace_once(text,
        'set(CONAN_ARGS ${CONAN_ARGS} -of=${CONAN_OUTPUT_FOLDER})',
        'set(CONAN_ARGS ${CONAN_ARGS} -of=${CONAN_OUTPUT_FOLDER} --lockfile-out=${CMAKE_BINARY_DIR}/liwetun-conan.lock)')
    text = replace_once(text,
        'string(JSON CONAN_GENERATORS_FOLDER GET ${conan_stdout} graph nodes 0 generators_folder)',
        'file(WRITE "${CMAKE_BINARY_DIR}/liwetun-conan-graph.json" "${conan_stdout}")\n'
        '        string(JSON CONAN_GENERATORS_FOLDER GET ${conan_stdout} graph nodes 0 generators_folder)')
    (source / 'cmake/conan_provider.cmake').write_text(text)
    provider.unlink()

    cpp = source / 'platform/windows/src/trusttunnel.cpp'
    text = cpp.read_text()
    marker = ('extern "C" __declspec(dllexport) int32_t liwetun_core_policy_version() {\n'
              '    ag::Logger::set_callback([](ag::LogLevel, std::string_view) {});\n'
              '    return 1;\n}\n')
    text = replace_once(text, 'static ag::Logger g_logger{"TRUSTTUNNEL"};',
                        'static ag::Logger g_logger{"TRUSTTUNNEL"};\n\n' + marker)
    text = replace_once(text,
        '    toml::parse_result parsed_config = toml::parse(toml_config);',
        '    liwetun_core_policy_version();\n    toml::parse_result parsed_config = toml::parse(toml_config);'
    ) if text.count('    toml::parse_result parsed_config = toml::parse(toml_config);') == 1 else text
    # The same parsing line appears in service_start too; replace only the first
    # occurrence, which belongs to trusttunnel_start_ex in the pinned source.
    if '    liwetun_core_policy_version();\n    toml::parse_result' not in text:
        start = text.index('trusttunnel_t *trusttunnel_start_ex(')
        line = text.index('    toml::parse_result parsed_config', start)
        text = text[:line] + '    liwetun_core_policy_version();\n' + text[line:]
    start = text.index('void trusttunnel_log_init(')
    text = text[:start] + '''// LiWeTun never enables the upstream raw file logger/exporter.
void trusttunnel_log_init(const wchar_t *logs_dir) { (void)logs_dir; }
void trusttunnel_log_export(const wchar_t *dest_dir, on_log_path_t path_cb, void *path_cb_arg) {
    (void)dest_dir; (void)path_cb; (void)path_cb_arg;
}
void trusttunnel_log_clear() {}
'''
    cpp.write_text(text)

    tunnel = source / 'core/src/tunnel.cpp'
    text = tunnel.read_text()
    start = text.index('static void report_connection_info(')
    end = text.index('static std::optional<DnsHandlerParameters> make_dns_handler_parameters', start)
    text = text[:start] + '''// LiWeTun does not create per-destination diagnostic events.
static void report_connection_info(const Tunnel *self, VpnConnection *conn, const char *domain) {
    (void)self; (void)conn; (void)domain;
}

''' + text[end:]
    tunnel.write_text(text)
    output.mkdir(parents=True, exist_ok=True)
    report = {
        'sdk_commit': lock['sdk_commit'], 'policy_version': 1,
        'bootstrap_sha256': lock['bootstrap']['sha256'],
        'prepare_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'patched_files': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                          for name in lock['patched_inputs']},
        'release_qualified': False,
    }
    (output / 'source-profile.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.source, args.bootstrap, args.output)
