import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch

from adapter_ownership_fixture import (validate_sample, pristine, interference, validate_ready, validate_cleanup,
                                       validate_idle_reply, observe_refusal)


def baseline():
    return dict(available=True, alias_unchanged=True, ipv4_changed=False, mtu_changed=False,
                metric_changed=False, fixture_marker_present=True, nonlink_ipv4_count=0)


class AdapterOwnershipFixtureTests(unittest.TestCase):
    def test_refusal_requires_no_sdk_core_observation_or_fabricated_reply(self):
        reply = dict(code=6, state=0, core_state=2**32 - 1)
        validate_idle_reply(reply, 6)
        for changes in [dict(code=0), dict(code=False), dict(state=True), dict(state=2),
                        dict(core_state=0), dict(core_state=None)]:
            with self.assertRaises(ValueError):
                validate_idle_reply(dict(reply, **changes), 6)

    def test_refused_start_preserves_retained_markers_and_does_not_admit_ownership(self):
        commands = []
        def command(value):
            commands.append(value)
            if value == 'query':
                return dict(code=0, state=0, core_state=2**32 - 1)
            self.assertEqual(value, 'stop')
            return dict(code=0)
        owner = SimpleNamespace(command=lambda _: baseline())
        queried = SimpleNamespace(returncode=0, stdout=json.dumps(dict(code=0, state=0, core_state=2**32 - 1)))
        with patch('adapter_ownership_fixture.subprocess.run', return_value=queried):
            result = observe_refusal(SimpleNamespace(command=command), owner, 'synthetic-client',
                                     dict(code=6, state=0, core_state=2**32 - 1), {})
        self.assertTrue(result['refusal_passed'])
        self.assertFalse(result['adapter_ownership_qualified'])
        self.assertFalse(result['release_ready'])
        self.assertEqual(commands, ['query', 'stop'])

    def test_refusal_cannot_hide_configuration_changes_after_stop(self):
        samples = iter([baseline(), dict(baseline(), metric_changed=True, fixture_marker_present=False)])
        owner = SimpleNamespace(command=lambda _: next(samples))
        session = SimpleNamespace(command=lambda value: dict(code=0, state=0, core_state=2**32 - 1))
        queried = SimpleNamespace(returncode=0, stdout=json.dumps(dict(code=0, state=0, core_state=2**32 - 1)))
        with patch('adapter_ownership_fixture.subprocess.run', return_value=queried):
            with self.assertRaises(ValueError):
                observe_refusal(session, owner, 'synthetic-client', dict(code=6, state=0, core_state=2**32 - 1), {})

    def test_missing_observation_never_proves_preservation_or_interference(self):
        unknown = {key: None for key in baseline()}
        unknown['available'] = False
        validate_sample(unknown)
        self.assertFalse(pristine(unknown))
        self.assertFalse(interference(unknown))

    def test_private_fixture_marker_required_before_start(self):
        value = baseline()
        self.assertTrue(pristine(value))
        self.assertFalse(interference(value))
        for changes in [dict(alias_unchanged=False), dict(fixture_marker_present=False), dict(mtu_changed=True),
                        dict(metric_changed=True), dict(ipv4_changed=True), dict(nonlink_ipv4_count=1)]:
            self.assertFalse(pristine(dict(value, **changes)))

    def test_reproduction_requires_actual_same_adapter_configuration_changes(self):
        value = dict(baseline(), ipv4_changed=True, mtu_changed=True, metric_changed=True,
                     fixture_marker_present=False, nonlink_ipv4_count=1)
        self.assertTrue(interference(value))
        for changes in [dict(alias_unchanged=False), dict(ipv4_changed=False), dict(mtu_changed=False),
                        dict(metric_changed=False), dict(fixture_marker_present=True), dict(nonlink_ipv4_count=0)]:
            self.assertFalse(interference(dict(value, **changes)))

    def test_identifiers_unbounded_values_and_ambiguous_types_are_rejected(self):
        for changes in [dict(luid=123), dict(address='synthetic-extra-field'), dict(raw='forbidden'),
                        dict(nonlink_ipv4_count=True), dict(nonlink_ipv4_count=33), dict(nonlink_ipv4_count=-1),
                        dict(mtu_changed=1), dict(available=1), dict(alias_unchanged=None)]:
            with self.assertRaises(ValueError):
                validate_sample(dict(baseline(), **changes))
        with self.assertRaises(ValueError):
            validate_sample(dict.fromkeys(baseline(), False))

    def test_creation_and_removal_receipts_are_exact_and_not_release_admission(self):
        ready = dict(ready=True, fixture_created_adapter=True, retained_creation_handle=True,
                     marker_verified=True, identifiers_exported=False, release_ready=False)
        validate_ready(ready)
        for changes in [dict(ready=1), dict(retained_creation_handle=False), dict(marker_verified=False),
                        dict(release_ready=True), dict(luid=123)]:
            with self.assertRaises(ValueError):
                validate_ready(dict(ready, **changes))
        validate_cleanup(dict(fixture_adapter_removed=True, release_ready=False))
        for value in [dict(fixture_adapter_removed=1, release_ready=False),
                      dict(fixture_adapter_removed=False, release_ready=False),
                      dict(fixture_adapter_removed=True, release_ready=True)]:
            with self.assertRaises(ValueError):
                validate_cleanup(value)


if __name__ == '__main__':
    unittest.main()
