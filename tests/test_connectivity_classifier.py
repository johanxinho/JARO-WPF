"""Pruebas del clasificador de conectividad (matriz T1-T16, rev. 2).

Todo el tráfico es simulado a través de MockTransport: estas pruebas validan
la lógica de clasificación, no la conectividad real.
"""

from __future__ import annotations

import socket
import unittest

from core.classifier.classifier import ConnectivityClassifier, UserProbeConfig
from core.classifier.models import (
    CaptivePortalStatus,
    DnsStatus,
    FamilyClassification,
    HttpsStatus,
    IpLayerStatus,
    VpnReport,
    VpnTunnelState,
)
from core.classifier.transport import ProbeTransport, RealTransport, _build_dns_query

AF4, AF6 = socket.AF_INET, socket.AF_INET6


class MockTransport(ProbeTransport):
    """Sonda simulada configurable; registra la familia usada en cada llamada."""

    def __init__(self, ip_layer=None, dns=None, https=None, portal=None):
        self.ip_layer = ip_layer or {}
        self.dns = dns or {}  # (resolver) -> DnsProbeOutcome-like dict
        self.https = https or {}  # (url, family) -> (HttpsStatus, evidence)
        self.portal = portal or {}  # (family) -> (CaptivePortalStatus, evidence)
        self.calls: list[tuple[str, int]] = []

    def ip_layer_probe(self, family):
        self.calls.append(("ip", family))
        return self.ip_layer.get(family, IpLayerStatus.NOT_PROBED)

    def dns_query(self, resolver_ip, name, family, timeout):
        self.calls.append(("dns", family))
        res = self.dns.get(resolver_ip, {"status": DnsStatus.FAILED, "evidence": ["mock_default"]})
        return type("O", (), {"status": res["status"], "evidence": res["evidence"]})()

    def https_request(self, url, family, timeout):
        self.calls.append(("https", family))
        status, ev = self.https.get((url, family), (HttpsStatus.DESTINATION_UNAVAILABLE, ["mock_default"]))
        return type("O", (), {"status": status, "evidence": ev, "http_code": None})()

    def portal_request(self, url, family, timeout, expected_body_marker):
        self.calls.append(("portal", family))
        status, ev = self.portal.get(family, (CaptivePortalStatus.NOT_SUSPECTED, ["mock_default"]))
        return type("O", (), {"status": status, "evidence": ev})()


def cfg(**kw) -> UserProbeConfig:
    base = dict(
        dns_resolvers=["10.66.66.1", "fd00:6:6::1"],
        dns_query_name="midominio.example",
        https_urls=["https://midominio.example/health"],
        portal_url="http://midominio.example/",
        timeout_s=0.2,
    )
    base.update(kw)
    return UserProbeConfig(**base)


def classify(mock, config=None, vpn=None):
    return ConnectivityClassifier(mock, config or cfg()).classify(vpn)


class ClassifierMatrixTests(unittest.TestCase):
    def test_T1_dual_stack_without_ip(self):
        m = MockTransport(ip_layer={AF4: IpLayerStatus.UNAVAILABLE, AF6: IpLayerStatus.UNAVAILABLE})
        r = classify(m)
        self.assertEqual(r.ipv4.classification, FamilyClassification.NO_CONNECTIVITY)
        self.assertEqual(r.ipv6.classification, FamilyClassification.NO_CONNECTIVITY)

    def test_T2_dual_stack_full_internet(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE, AF6: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]},
                 "fd00:6:6::1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.OK, ["http_code=200"]),
                   ("https://midominio.example/health", AF6): (HttpsStatus.OK, ["http_code=200"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.classification, FamilyClassification.FULL_INTERNET)
        self.assertEqual(r.ipv6.classification, FamilyClassification.FULL_INTERNET)
        self.assertEqual(r.ipv4.dns_status, DnsStatus.OK)
        self.assertEqual(r.ipv4.portal_status, CaptivePortalStatus.NOT_SUSPECTED)

    def test_T3_dns_total_failure_isolated(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.FAILED, "evidence": ["timeout"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.OK, ["http_code=200"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.dns_status, DnsStatus.FAILED)
        self.assertEqual(r.ipv4.classification, FamilyClassification.FULL_INTERNET)

    def test_T4_https_blocked_with_dns_ok(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.TIMEOUT, ["timeout"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.classification, FamilyClassification.LIMITED_ACCESS)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.TIMEOUT)

    def test_T5_ipv4_full_ipv6_absent(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE, AF6: IpLayerStatus.UNAVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.OK, ["http_code=200"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.classification, FamilyClassification.FULL_INTERNET)
        self.assertEqual(r.ipv6.classification, FamilyClassification.NO_CONNECTIVITY)

    def test_T6_captive_portal_redirect_302(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.OK, ["http_code=200"])},
            portal={AF4: (CaptivePortalStatus.PORTAL_DETECTED, ["redirect_30x_to_login=http://portal/login"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.portal_status, CaptivePortalStatus.PORTAL_DETECTED)
        self.assertEqual(r.ipv4.classification, FamilyClassification.FULL_INTERNET)

    def test_T7_http_500_limited_no_portal(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.HTTP_ERROR_SERVER, ["http_code=500"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.classification, FamilyClassification.LIMITED_ACCESS)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.HTTP_ERROR_SERVER)
        self.assertEqual(r.ipv4.portal_status, CaptivePortalStatus.NOT_SUSPECTED)

    def test_T8_https_timeout_with_dns_ok(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.TIMEOUT, ["timeout"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.TIMEOUT)
        self.assertEqual(r.ipv4.classification, FamilyClassification.LIMITED_ACCESS)

    def test_T9_tls_handshake_failure_no_portal(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.TLS_ERROR, ["tls_error: handshake"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.TLS_ERROR)
        self.assertEqual(r.ipv4.portal_status, CaptivePortalStatus.NOT_SUSPECTED)
        self.assertEqual(r.ipv4.classification, FamilyClassification.LIMITED_ACCESS)

    def test_T10_vpn_connected_while_base_network_down(self):
        m = MockTransport(ip_layer={AF4: IpLayerStatus.UNAVAILABLE, AF6: IpLayerStatus.UNAVAILABLE})
        vpn = VpnReport(state=VpnTunnelState.CONNECTED, handshake_age_s=12, rx_delta=512, tx_delta=256)
        r = classify(m, vpn=vpn)
        self.assertEqual(r.vpn.state, VpnTunnelState.CONNECTED)
        self.assertEqual(r.ipv4.classification, FamilyClassification.NO_CONNECTIVITY)
        self.assertEqual(r.ipv6.classification, FamilyClassification.NO_CONNECTIVITY)

    def test_T11_ipv6_full_ipv4_absent(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.UNAVAILABLE, AF6: IpLayerStatus.AVAILABLE},
            dns={"fd00:6:6::1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF6): (HttpsStatus.OK, ["http_code=200"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.classification, FamilyClassification.NO_CONNECTIVITY)
        self.assertEqual(r.ipv6.classification, FamilyClassification.FULL_INTERNET)

    def test_T12_dns_partial(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]},
                 "10.66.66.2": {"status": DnsStatus.FAILED, "evidence": ["timeout"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.OK, ["http_code=200"])},
        )
        r = classify(m, cfg(dns_resolvers=["10.66.66.1", "10.66.66.2"]))
        self.assertEqual(r.ipv4.dns_status, DnsStatus.PARTIAL)
        self.assertIn("resolvers_ok=1/2", r.ipv4.dns_evidence)

    def test_T13_destination_unavailable(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.DESTINATION_UNAVAILABLE, ["unreachable"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.DESTINATION_UNAVAILABLE)
        self.assertEqual(r.ipv4.classification, FamilyClassification.LIMITED_ACCESS)

    def test_T14_tls_protocol_error(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.TLS_ERROR, ["tls_error: protocol version"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.TLS_ERROR)
        self.assertEqual(r.ipv4.classification, FamilyClassification.LIMITED_ACCESS)

    def test_T15_http_5xx_does_not_touch_portal_heuristic(self):
        m = MockTransport(
            ip_layer={AF4: IpLayerStatus.AVAILABLE},
            dns={"10.66.66.1": {"status": DnsStatus.OK, "evidence": ["answers=1"]}},
            https={("https://midominio.example/health", AF4): (HttpsStatus.HTTP_ERROR_SERVER, ["http_code=503"])},
        )
        r = classify(m)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.HTTP_ERROR_SERVER)
        self.assertEqual(r.ipv4.portal_status, CaptivePortalStatus.NOT_SUSPECTED)

    def test_T16_no_user_targets_ip_only(self):
        m = MockTransport(ip_layer={AF4: IpLayerStatus.AVAILABLE, AF6: IpLayerStatus.AVAILABLE})
        r = classify(m, cfg(dns_resolvers=[], https_urls=[], portal_url=None))
        self.assertEqual(r.ipv4.dns_status, DnsStatus.NOT_PROBED)
        self.assertEqual(r.ipv4.https_status, HttpsStatus.NOT_PROBED)
        self.assertEqual(r.ipv4.classification, FamilyClassification.IP_ONLY)
        self.assertEqual(r.ipv6.classification, FamilyClassification.IP_ONLY)


class RealTransportUnitTests(unittest.TestCase):
    def test_family_binding_explicit(self):
        rt = RealTransport()
        with rt.open_socket(AF4) as s:
            self.assertEqual(s.family, AF4)
        with rt.open_socket(AF6) as s:
            self.assertEqual(s.family, AF6)

    def test_dns_query_build_valid_header(self):
        q = _build_dns_query("midominio.example", 1)
        self.assertEqual(len(q), 12 + len(b"\x0bmidominio\x07example\x00") + 4)
        self.assertEqual(q[2], 0x01)  # RD=1 (bit bajo de flags)
        self.assertEqual(q[4:6], b"\x00\x01")  # QDCOUNT=1


if __name__ == "__main__":
    unittest.main()
