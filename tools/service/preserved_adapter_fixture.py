"""Retained CI-created foreign adapter preservation; private OS facts never logged."""
import ipaddress
import json
import subprocess
import time
from adapter_ownership_fixture import pristine, validate_sample, validate_cleanup


def capture(ps):
    value = ps("""
    $name = 'LiWeTun.CI.PreservedOwner'.PadRight(127, [char]'x')
    $adapter = @(Get-NetAdapter -IncludeHidden | Where-Object Name -eq $name)
    if ($adapter.Count -ne 1) { throw 'Missing or ambiguous retained fixture adapter' }
    $index = $adapter[0].ifIndex
    $dns = @(Get-DnsClientServerAddress | Where-Object InterfaceIndex -eq $index | Sort-Object AddressFamily |
      ForEach-Object { [string]$_.AddressFamily + ':' + [string]::Join(',', @($_.ServerAddresses)) })
    $routes = @(Get-NetRoute | Where-Object InterfaceIndex -eq $index | Select-Object @{N='destination';E={$_.DestinationPrefix}},
      @{N='next_hop';E={$_.NextHop}}, @{N='metric';E={$_.RouteMetric}})
    @{index=$index;guid=[string]$adapter[0].InterfaceGuid;dns=$dns;routes=$routes} | ConvertTo-Json -Depth 5 -Compress
    """)
    if (not isinstance(value, dict) or set(value) != {'index','guid','dns','routes'}
            or type(value['index']) is not int or not 1 <= value['index'] <= 2**32-1
            or not isinstance(value['guid'], str) or not 1 <= len(value['guid']) <= 64
            or not isinstance(value['dns'], list) or len(value['dns']) > 16
            or any(not isinstance(v,str) or len(v)>4096 for v in value['dns'])
            or not isinstance(value['routes'], list) or len(value['routes']) > 256):
        raise RuntimeError('foreign_adapter_observation_unavailable')
    routes=[]
    for row in value['routes']:
        if (not isinstance(row,dict) or set(row) != {'destination','next_hop','metric'}
                or not isinstance(row['destination'],str) or len(row['destination']) > 64
                or not isinstance(row['next_hop'],str) or len(row['next_hop']) > 64
                or type(row['metric']) is not int or not 0 <= row['metric'] <= 2**32-1):
            raise RuntimeError('foreign_adapter_observation_unavailable')
        try:
            network=ipaddress.ip_network(row['destination'],strict=False)
        except ValueError:
            raise RuntimeError('foreign_adapter_observation_unavailable') from None
        address=network.network_address
        # Windows may create link-local/multicast routes asynchronously. Do not
        # attribute its own autoconfiguration to SDK writes; scope stays explicit.
        if address.is_link_local or address.is_multicast or str(address)=='255.255.255.255':
            continue
        routes.append((row['destination'],row['next_hop'],row['metric']))
    if any(':' not in item for item in value['dns']):
        raise RuntimeError('foreign_adapter_observation_unavailable')
    dns=sorted(item for item in value['dns'] if item.split(':',1)[1])
    return dict(index=value['index'],guid=value['guid'],dns=dns,routes=sorted(routes))


def observe(owner, baseline, ps, diagnostic):
    sample=validate_sample(owner.command('sample'))
    unchanged=capture(ps)==baseline
    diagnostic.update(retained_sample=sample,dns_nonlink_routes_unchanged=unchanged)
    if not pristine(sample) or not unchanged:
        raise RuntimeError('foreign_adapter_preservation_failed')
    return dict(retained_markers_unchanged=True,dns_nonlink_routes_unchanged=True,
                scope='retained_ipv4_mtu_metric_alias_dns_nonlink_routes_only',
                os_link_local_multicast_routes_qualified=False,identifiers_exported=False,
                adapter_ownership_qualified=False,release_ready=False)


def wait_stopped(client, settled):
    stable=0
    for _ in range(40):
        result=subprocess.run([str(client),'--query'],capture_output=True,text=True,timeout=10)
        if result.returncode or len(result.stdout)>2048:
            raise RuntimeError('foreign_adapter_stop_not_confirmed')
        state=json.loads(result.stdout)
        if (type(state.get('code')) is int and state['code']==0
                and type(state.get('state')) is int and state['state']==0 and settled()):
            stable+=1
            if stable==2:
                return
        else:
            stable=0
        time.sleep(.1)
    raise RuntimeError('foreign_adapter_stop_not_confirmed')


def close_owned_fixture(owner):
    cleanup=validate_cleanup(owner.command('close'))
    if owner.process.wait(timeout=10)!=0:
        raise RuntimeError('adapter_owner_fixture_cleanup_failed')
    owner.close()
    return cleanup


def wait_crashed_resources(settled):
    # The service no longer exists: use its pre-retained process/WFP observer,
    # not a new service admission or fabricated idle response.
    stable=0
    for _ in range(40):
        stable=stable+1 if settled() is True else 0
        if stable==2:
            return
        time.sleep(.1)
    raise RuntimeError('foreign_adapter_stop_not_confirmed')
