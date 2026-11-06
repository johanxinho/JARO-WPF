"""Clasificador de conectividad (rev. 2).

Compone FamilyReport por familia (IPv4/IPv6) a partir de sondas con destinos
del usuario. El estado VPN se transporta sin alterar la clasificación.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .models import (
    CaptivePortalStatus,
    ClassifierResult,
    DnsStatus,
    FamilyReport,
    HttpsStatus,
    IpLayerStatus,
    VpnReport,
)
from .transport import DEFAULT_TIMEOUT_S, ProbeTransport, _family_of_ip


@dataclass
class UserProbeConfig:
    """Destinos configurados por el usuario. Sin valores por defecto externos."""

    dns_resolvers: list[str] = field(default_factory=list)  # IPs; familia por formato
    dns_query_name: str = ""  # nombre a consultar (del usuario)
    https_urls: list[str] = field(default_factory=list)
    portal_url: str | None = None
    expected_body_marker: str | None = None  # para detección de sustitución de payload
    timeout_s: float = DEFAULT_TIMEOUT_S


class ConnectivityClassifier:
    def __init__(self, transport: ProbeTransport, config: UserProbeConfig):
        self.transport = transport
        self.config = config

    # --- Dimensiones por familia ---

    def _dns_status(self, family: int) -> tuple[DnsStatus, list[str]]:
        resolvers = [r for r in self.config.dns_resolvers if _family_of_ip(r) == family]
        if not resolvers or not self.config.dns_query_name:
            return DnsStatus.NOT_PROBED, ["no_dns_targets_configured"]
        outcomes = [self.transport.dns_query(r, self.config.dns_query_name, family, self.config.timeout_s) for r in resolvers]
        evidence: list[str] = []
        ok = sum(1 for o in outcomes if o.status == DnsStatus.OK)
        for o in outcomes:
            evidence.extend(o.evidence)
        if ok == len(outcomes):
            return DnsStatus.OK, evidence
        if ok > 0:
            return DnsStatus.PARTIAL, evidence + [f"resolvers_ok={ok}/{len(outcomes)}"]
        return DnsStatus.FAILED, evidence

    def _https_status(self, family: int) -> tuple[HttpsStatus, list[str]]:
        urls = [u for u in self.config.https_urls if self._url_family(u) in (None, family)]
        if not urls:
            return HttpsStatus.NOT_PROBED, ["no_https_targets_configured"]
        evidence: list[str] = []
        best = HttpsStatus.DESTINATION_UNAVAILABLE
        for url in urls:
            outcome = self.transport.https_request(url, family, self.config.timeout_s)
            evidence.extend(outcome.evidence)
            if outcome.status == HttpsStatus.OK:
                return HttpsStatus.OK, evidence
            best = outcome.status
        return best, evidence

    @staticmethod
    def _url_family(url: str) -> int | None:
        host = urlparse(url).hostname or ""
        try:
            return _family_of_ip(host) if ipaddress.ip_address(host) else None
        except ValueError:
            return None  # nombre: se prueba en ambas familias

    def _portal_status(self, family: int) -> tuple[CaptivePortalStatus, list[str]]:
        if not self.config.portal_url:
            return CaptivePortalStatus.NOT_SUSPECTED, ["no_portal_target_configured"]
        url_family = self._url_family(self.config.portal_url)
        if url_family is not None and url_family != family:
            return CaptivePortalStatus.NOT_SUSPECTED, ["portal_target_other_family"]
        outcome = self.transport.portal_request(
            self.config.portal_url, family, self.config.timeout_s, self.config.expected_body_marker
        )
        return outcome.status, outcome.evidence

    # --- Clasificación ---

    def classify(self, vpn_report: VpnReport | None = None) -> ClassifierResult:
        """Clasifica la red subyacente. La VPN solo se transporta (T10)."""
        report = vpn_report or VpnReport()
        families: dict[str, FamilyReport] = {}
        for name, family in (("ipv4", socket.AF_INET), ("ipv6", socket.AF_INET6)):
            ip_layer = self.transport.ip_layer_probe(family)
            dns_status, dns_evidence = self._dns_status(family)
            https_status, https_evidence = self._https_status(family)
            portal_status, portal_evidence = self._portal_status(family)
            families[name] = FamilyReport(
                family=name,
                ip_layer=ip_layer,
                dns_status=dns_status,
                dns_evidence=dns_evidence,
                https_status=https_status,
                https_evidence=https_evidence,
                portal_status=portal_status,
                portal_evidence=portal_evidence,
            )
        return ClassifierResult(ipv4=families["ipv4"], ipv6=families["ipv6"], vpn=report)
