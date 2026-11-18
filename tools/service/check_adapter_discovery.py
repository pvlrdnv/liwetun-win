"""Read-only observer binding on a clean disposable Windows host; no SDK/TUN."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from adapter_discovery import FRESH_PATTERN
from network import tun, adapter_absent, ps


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('disposable_windows_required')
    for mode in ['false', 'true']:
        os.environ['FRESH_ADAPTER'] = mode
        for name in ['SOURCE_PINNED', 'TRAFFIC_METRICS', 'ATTACHED_TUN', 'OWNED_PROBE']:
            os.environ[name] = 'true'
        if tun() is not None or not adapter_absent():
            raise ValueError('clean_host_observer_not_absent')
    # Exercise the actual .NET regex, including its strict newline boundary.
    result = ps("""
    $name = 'LiWeTun-' + ('0123456789abcdef' * 2) + ('x' * 87)
    $pattern = '""" + FRESH_PATTERN + """'
    $valid = $name -cmatch $pattern
    $invalid = @('LiWeTun', $name.Substring(0,126), ($name + 'x'), ($name + ' 1'),
      $name.ToUpperInvariant(), ($name + "`n"))
    $bad = @($invalid | Where-Object { $_ -cmatch $pattern }).Count
    @{passed=($valid -and $bad -eq 0)} | ConvertTo-Json -Compress
    """)
    if result != {'passed': True} or type(result['passed']) is not bool:
        raise ValueError('observer_pattern_boundary_failed')
    args.output.write_text(json.dumps(dict(legacy_clean_host_binding_passed=True,
        fresh_clean_host_binding_passed=True, actual_dotnet_pattern_boundary_passed=True,
        network_configuration_changed=False, tunnel_started=False, identifiers_exported=False,
        adapter_ownership_qualified=False, release_ready=False), indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('adapter_discovery_binding_failed') from None
