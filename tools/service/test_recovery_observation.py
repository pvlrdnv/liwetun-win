import unittest
from production_network import recovery_evidence_valid


class RecoveryObservationTests(unittest.TestCase):
    def evidence(self, **changes):
        fields = dict(protocol='http2', state=2, https_ok=True, https_tun=True,
                      dns_ok=True, dns_tun=True,
                      growth=dict(http1=0, http2=500, http3=0),
                      dns_growth=dict(synthetic_dns_requests=1, synthetic_dns_replies=1),
                      dns_transport_growth=dict(http1=0, http2=82, http3=0))
        fields.update(changes)
        return recovery_evidence_valid(**fields)

    def test_ready_without_delivered_or_tunnel_bound_probes_fails(self):
        self.assertTrue(self.evidence())
        for field in ['https_ok', 'https_tun', 'dns_ok', 'dns_tun']:
            with self.subTest(field=field):
                self.assertFalse(self.evidence(**{field: False}))
        self.assertFalse(self.evidence(state=3))

    def test_https_bytes_cannot_mask_missing_dns_transport(self):
        self.assertFalse(self.evidence(dns_transport_growth=dict(http1=0, http2=0, http3=0)))
        self.assertFalse(self.evidence(dns_transport_growth=dict(http1=0, http2=81, http3=0)))
        self.assertFalse(self.evidence(dns_growth=dict(synthetic_dns_requests=1, synthetic_dns_replies=0)))

    def test_wrong_protocol_or_reset_counters_fail(self):
        self.assertFalse(self.evidence(growth=dict(http1=0, http2=500, http3=1)))
        self.assertFalse(self.evidence(growth=dict(http1=0, http2=-500, http3=0)))
        self.assertFalse(self.evidence(dns_transport_growth=dict(http1=82, http2=82, http3=0)))
        self.assertFalse(self.evidence(dns_transport_growth=dict(http1=0, http2=-82, http3=0)))

    def test_h3_needs_its_own_transport_counters(self):
        self.assertFalse(self.evidence(protocol='http3'))
        self.assertTrue(self.evidence(protocol='http3', growth=dict(http1=0, http2=0, http3=500),
                                     dns_transport_growth=dict(http1=0, http2=0, http3=82)))


if __name__ == '__main__':
    unittest.main()
