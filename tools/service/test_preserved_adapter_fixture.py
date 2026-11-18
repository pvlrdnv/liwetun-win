import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from preserved_adapter_fixture import capture, observe, wait_stopped, close_owned_fixture


def sample():
    return dict(available=True,alias_unchanged=True,ipv4_changed=False,mtu_changed=False,
                metric_changed=False,fixture_marker_present=True,nonlink_ipv4_count=0)


def configuration():
    return dict(index=71,guid='synthetic-private-guid',dns=['IPv4:','IPv6:'],routes=[
        dict(destination='169.254.0.0/16',next_hop='0.0.0.0',metric=256),
        dict(destination='fe80::/64',next_hop='::',metric=256),
        dict(destination='224.0.0.0/4',next_hop='0.0.0.0',metric=256),
        dict(destination='198.18.0.0/15',next_hop='0.0.0.0',metric=427)])


class PreservedAdapterTests(unittest.TestCase):
    def test_success_keeps_identifiers_and_configuration_out_of_diagnostics(self):
        baseline=capture(lambda _:configuration())
        diagnostic={}
        result=observe(SimpleNamespace(command=lambda _:sample()),baseline,lambda _:configuration(),diagnostic)
        self.assertTrue(result['retained_markers_unchanged'])
        text=json.dumps(dict(result=result,diagnostic=diagnostic))
        for private in ['synthetic-private-guid','198.18.0.0','IPv4:']:
            self.assertNotIn(private,text)
        self.assertFalse(result['adapter_ownership_qualified'])
        self.assertEqual(len(baseline['routes']),1)

    def test_mtu_ipv4_dns_route_or_identity_mutations_cannot_be_hidden_by_final_cleanup(self):
        baseline=capture(lambda _:configuration())
        for changes in [dict(mtu_changed=True),dict(ipv4_changed=True),dict(alias_unchanged=False),dict(available=False,
                alias_unchanged=None,ipv4_changed=None,mtu_changed=None,metric_changed=None,fixture_marker_present=None,nonlink_ipv4_count=None)]:
            with self.assertRaises(RuntimeError):
                observe(SimpleNamespace(command=lambda _,c=changes:dict(sample(),**c)),baseline,lambda _:configuration(),{})
        for key,value in [('index',72),('guid','different-private-guid'),('dns',['IPv4:192.0.2.53']),
                          ('routes',[dict(destination='198.18.0.0/15',next_hop='0.0.0.0',metric=0)])]:
            changed=configuration();changed[key]=value
            with self.assertRaises(RuntimeError):
                observe(SimpleNamespace(command=lambda _:sample()),baseline,lambda _,c=changed:c,{})

    def test_unknown_or_unbounded_os_observation_refuses(self):
        for key,value in [('index',True),('guid',''),('dns',['x'*4097]),('routes',[{}]),
                          ('routes',[dict(destination='invalid',next_hop='::',metric=0)])]:
            changed=configuration();changed[key]=value
            with self.assertRaises(RuntimeError): capture(lambda _:changed)

    def test_confirm_stop_uses_a_fresh_client_and_rejects_fabricated_boolean_state(self):
        ready=SimpleNamespace(returncode=0,stdout=json.dumps(dict(code=0,state=0)))
        with patch('preserved_adapter_fixture.subprocess.run',return_value=ready) as run:
            with patch('preserved_adapter_fixture.time.sleep'):
                wait_stopped('synthetic-client',lambda:True)
            self.assertEqual(run.call_args.args[0],['synthetic-client','--query'])
        false_state=SimpleNamespace(returncode=0,stdout=json.dumps(dict(code=0,state=False)))
        with patch('preserved_adapter_fixture.subprocess.run',return_value=false_state),patch('preserved_adapter_fixture.time.sleep'):
            with self.assertRaises(RuntimeError): wait_stopped('synthetic-client',lambda:True)
        with patch('preserved_adapter_fixture.subprocess.run',return_value=ready),patch('preserved_adapter_fixture.time.sleep'):
            with self.assertRaises(RuntimeError): wait_stopped('synthetic-client',lambda:False)

    def test_creator_close_requires_typed_removal_and_successful_own_process_exit(self):
        commands=[]
        owner=SimpleNamespace(command=lambda cmd:commands.append(cmd) or dict(fixture_adapter_removed=True,release_ready=False),
                              process=SimpleNamespace(wait=lambda **_:0),close=lambda:commands.append('reap'))
        close_owned_fixture(owner)
        self.assertEqual(commands,['close','reap'])


if __name__=='__main__': unittest.main()
