"""Disposable signed-service refusal with a retained disabled fixture node."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from adapter_ownership_fixture import validate_idle_reply
from network import Child, ROOT, ps, snapshot, wait_clean


def exact(value, expected):
    if (not isinstance(value,dict) or set(value)!=set(expected)
            or any(type(value[k]) is not type(v) or value[k]!=v for k,v in expected.items())):
        raise ValueError('invalid_problem_node_fixture_observation')
    return value


def sample(owner):
    return exact(owner.command('sample'),dict(retained_node_present=True,disabled_state_unchanged=True))


def adapters():
    return ps("@(Get-NetAdapter -IncludeHidden | Sort-Object InterfaceGuid | Select-Object InterfaceGuid,Name,InterfaceDescription) | ConvertTo-Json -Compress")


def main():
    parser=argparse.ArgumentParser()
    for name in ['client','helper','driver','uri-file']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();run=os.environ.get('GITHUB_RUN_ID','')
    if sys.platform!='win32' or os.environ.get('GITHUB_ACTIONS')!='true' or not re.fullmatch(r'[0-9]{1,20}',run):
        raise ValueError('disposable_windows_required')
    client=args.client.resolve();helper=args.helper.resolve();driver=args.driver.resolve()
    expected=Path(os.environ['ProgramFiles'])/('LiWeTun-CI-'+run)
    if (client!=expected/'liwetun.exe' or driver!=expected/'wintun.dll'
            or helper!=ROOT/'build/service/Release/liwetun_problem_probe.exe'
            or args.uri_file.resolve()!=ROOT/'build/service-local-uri.txt'):
        raise ValueError('invalid_problem_node_fixture_path')
    if hashlib.sha256(driver.read_bytes()).hexdigest()!='e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce':
        raise ValueError('invalid_problem_node_fixture_driver')
    report=ROOT/'build/service-evidence/problem-node-service.json';report.parent.mkdir(parents=True,exist_ok=True)
    result=dict(passed=False,preexisting_problem_node_refusal_only=True,identifiers_exported=False,
                later_problem_state_race_qualified=False,adapter_ownership_qualified=False,release_ready=False)
    baseline=snapshot();adapter_baseline=adapters();owner=session=None;stage='retained_problem_node_ready'
    try:
        owner=Child([str(helper),str(driver),'--hold'])
        exact(json.loads(owner.receive()),dict(ready=True,retained_creation_handle=True,problem_disabled_observed=True,identifiers_exported=False))
        held_snapshot=snapshot();held_adapters=adapters()
        result['before_start']=sample(owner)
        stage='signed_service_start_refusal'
        session=Child([str(client),'--network-session',str(args.uri_file)])
        started=json.loads(session.receive());validate_idle_reply(started,10)
        result['start_response']=started
        validate_idle_reply(session.command('query'),0)
        result['after_refused_start']=sample(owner)
        stage='signed_service_stop'
        stopped=session.command('stop');validate_idle_reply(stopped,0)
        session.close();session=None
        for _ in range(20):
            query=subprocess.run([str(client),'--query'],capture_output=True,text=True,timeout=10)
            if query.returncode or len(query.stdout)>2048:raise ValueError('invalid_problem_node_service_query')
            value=json.loads(query.stdout)
            if value.get('state')==0:
                validate_idle_reply(value,0);break
            time.sleep(.1)
        else:raise ValueError('problem_node_service_not_stopped')
        result['after_stop']=sample(owner)
        if snapshot()!=held_snapshot or adapters()!=held_adapters:
            raise ValueError('problem_node_configuration_changed')
        result['held_configuration_unchanged']=True
        stage='fixture_creator_cleanup'
        result['creator_cleanup']=exact(owner.command('close'),dict(creator_restored_own_node=True,
            creator_closed_own_handle=True,released_node_absent=True,adapter_ownership_qualified=False,release_ready=False))
        if owner.process.wait(timeout=10)!=0:raise ValueError('problem_node_creator_failed')
        owner.close();owner=None
        stage='final_baseline'
        result['passed']=True
    except Exception:
        result['failed_stage']=stage
    finally:
        try:
            if session:session.close('stop')
            if owner:owner.close('close')
            result['routes_dns_restored']=wait_clean(baseline)
            result['adapter_baseline_restored']=adapters()==adapter_baseline
            result['passed']=result['passed'] and result['routes_dns_restored'] and result['adapter_baseline_restored']
        except Exception:
            result['passed']=False;result['cleanup_unavailable']=True
        report.write_text(json.dumps(result,indent=2)+'\n')
    return 0 if result['passed'] else 2


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:raise SystemExit('problem_node_service_fixture_failed') from None
