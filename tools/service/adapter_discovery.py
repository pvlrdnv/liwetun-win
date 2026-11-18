"""Private CI observer selection; a matching name never proves SDK ownership."""
import os

FRESH_PATTERN = r'\ALiWeTun-[0-9a-f]{32}x{87}(?![\s\S])'


def selector():
    mode = os.environ.get('FRESH_ADAPTER', '')
    if mode not in ('', 'false', 'true'):
        raise ValueError('invalid_fresh_adapter_fixture_mode')
    if mode == 'true':
        if (os.environ.get('GITHUB_ACTIONS') != 'true'
                or any(os.environ.get(name) != 'true'
                       for name in ['SOURCE_PINNED', 'TRAFFIC_METRICS', 'ATTACHED_TUN', 'OWNED_PROBE'])):
            raise ValueError('fresh_adapter_fixture_requires_pinned_owned_context')
        return "Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -cmatch '" + FRESH_PATTERN + "' }"
    return "Get-NetAdapter -IncludeHidden | Where-Object Name -eq 'LiWeTun'"
