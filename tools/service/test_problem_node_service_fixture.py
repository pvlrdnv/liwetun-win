from types import SimpleNamespace
import unittest
from problem_node_service_fixture import exact,sample


class RetainedProblemObservations(unittest.TestCase):
    def test_missing_changed_or_extra_private_data_refuses(self):
        good=dict(retained_node_present=True,disabled_state_unchanged=True)
        self.assertEqual(sample(SimpleNamespace(command=lambda _:good)),good)
        for value in [dict(good,retained_node_present=False),dict(good,disabled_state_unchanged=False),
                      dict(good,retained_node_present=1),dict(good,private_identifier='synthetic'),{}]:
            with self.assertRaises(ValueError):sample(SimpleNamespace(command=lambda _,v=value:v))

    def test_cleanup_cannot_fabricate_boolean_or_hide_unavailable_node(self):
        expected=dict(creator_restored_own_node=True,creator_closed_own_handle=True,released_node_absent=True,
                      adapter_ownership_qualified=False,release_ready=False)
        for value in [dict(expected,released_node_absent=False),dict(expected,creator_closed_own_handle=1),
                      dict(expected,release_ready=0),dict(expected,raw_output='synthetic')]:
            with self.assertRaises(ValueError):exact(value,expected)


if __name__=='__main__':unittest.main()
