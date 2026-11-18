import unittest

from adapter_ownership_fixture import validate_sample, pristine, interference, validate_ready, validate_cleanup


def baseline():
    return dict(available=True, alias_unchanged=True, ipv4_changed=False, mtu_changed=False,
                metric_changed=False, fixture_marker_present=True, nonlink_ipv4_count=0)


class AdapterOwnershipFixtureTests(unittest.TestCase):
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
