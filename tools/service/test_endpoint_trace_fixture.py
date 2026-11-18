import json
from pathlib import Path
import tempfile
import unittest
from endpoint_trace_fixture import read,validate,validate_raw,validate_restart


class ShutdownObservations(unittest.TestCase):
    def test_named_closed_counters_do_not_claim_delivery(self):
        value=validate_raw(dict(schema_version=1,counters=[2,1,1,1,0,10,0,0],release_ready=False))
        self.assertIs(validate(value),value)
        self.assertEqual(value['counters']['quic_close_errors'],1)
        self.assertFalse(value['proves_close_delivery'])

    def test_malformed_unbounded_unbalanced_or_free_fields_refuse(self):
        for counters in [[0]*7,[True]+[0]*7,[-1]+[0]*7,[2**64]+[0]*7,[1]+[0]*7,[1,1,0,0,0,0,0,0]]:
            with self.assertRaises(ValueError):validate_raw(dict(schema_version=1,counters=counters,release_ready=False))
        with self.assertRaises(ValueError):validate_raw(dict(schema_version=1,counters=[0]*8,release_ready=False,raw='forbidden'))

    def test_missing_oversized_malformed_or_redirected_file_stays_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);target=root/'liwetun-ci-shutdown.json'
            self.assertFalse(validate(read(root))['available'])
            for data in [b'x'*1025,b'not json']:
                target.write_bytes(data);self.assertFalse(validate(read(root))['available'])
            target.write_text(json.dumps(dict(schema_version=1,counters=[0]*8,release_ready=False)))
            self.assertTrue(validate(read(root))['available'])
            outside=root/'other';target.rename(outside);target.symlink_to(outside)
            self.assertFalse(validate(read(root))['available'])

    def test_restart_requires_literal_results_and_explicit_trace_context(self):
        base=dict(restarted=True,outage_seconds=2,graceful_shutdown=True)
        self.assertIs(validate_restart(base,False),base)
        observation=validate_raw(dict(schema_version=1,counters=[0]*8,release_ready=False))
        traced=dict(base,shutdown_observation=observation)
        validate_restart(traced,True)
        for value,enabled in [(traced,False),(base,True),(dict(base,restarted=1),False),
                              (dict(base,graceful_shutdown=1),False),(dict(base,outage_seconds=True),False)]:
            with self.assertRaises(ValueError):validate_restart(value,enabled)


if __name__=='__main__':unittest.main()
