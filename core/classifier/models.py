"""Modelos del clasificador de conectividad (rev. 2).

Reglas de diseño aprobadas:
- IPv4 e IPv6 se clasifican por separado; una familia ausente no degrada la otra.
- IP, DNS, HTTPS y portal cautivo son dimensiones independientes.
- El estado VPN se reporta aparte y nunca altera la clasificación de la red.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class IpLayerStatus(Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_PROBED = "NOT_PROBED"


class DnsStatus(Enum):
    OK = "OK"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_PROBED = "NOT_PROBED"


class HttpsStatus(Enum):
    OK = "OK"
    DESTINATION_UNAVAILABLE = "DESTINATION_UNAVAILABLE"
    TLS_ERROR = "TLS_ERROR"
    HTTP_ERROR_SERVER = "HTTP_ERROR_SERVER"
    TIMEOUT = "TIMEOUT"
    NOT_PROBED = "NOT_PROBED"


class CaptivePortalStatus(Enum):
    NOT_SUSPECTED = "NOT_SUSPECTED"
    PORTAL_DETECTED = "PORTAL_DETECTED"


class FamilyClassification(Enum):
    FULL_INTERNET = "FULL_INTERNET"
    LIMITED_ACCESS = "LIMITED_ACCESS"
    IP_ONLY = "IP_ONLY"
    NO_CONNECTIVITY = "NO_CONNECTIVITY"


class VpnTunnelState(Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    ERROR = "ERROR"


def classification_for(report: "FamilyReport") -> FamilyClassification:
    """Clase de la familia: determinista y basada solo en sus dimensiones.

    - Sin capa IP -> NO_CONNECTIVITY.
    - HTTPS no probado (sin destinos del usuario) -> como maximo IP_ONLY.
    - HTTPS OK -> FULL_INTERNET (DNS no degrada la clase: es una dimension aparte).
    - Cualquier otro resultado HTTPS -> LIMITED_ACCESS con la taxonomia en evidencia.
    - El portal cautivo es solo evidencia; nunca cambia la clase.
    """
    if report.ip_layer != IpLayerStatus.AVAILABLE:
        return FamilyClassification.NO_CONNECTIVITY
    if report.https_status in (HttpsStatus.NOT_PROBED,):
        return FamilyClassification.IP_ONLY
    if report.https_status == HttpsStatus.OK:
        return FamilyClassification.FULL_INTERNET
    return FamilyClassification.LIMITED_ACCESS


@dataclass
class FamilyReport:
    family: str  # "ipv4" | "ipv6"
    ip_layer: IpLayerStatus = IpLayerStatus.NOT_PROBED
    dns_status: DnsStatus = DnsStatus.NOT_PROBED
    dns_evidence: list[str] = field(default_factory=list)
    https_status: HttpsStatus = HttpsStatus.NOT_PROBED
    https_evidence: list[str] = field(default_factory=list)
    portal_status: CaptivePortalStatus = CaptivePortalStatus.NOT_SUSPECTED
    portal_evidence: list[str] = field(default_factory=list)
    classification: FamilyClassification = FamilyClassification.NO_CONNECTIVITY

    def __post_init__(self) -> None:
        self.classification = classification_for(self)

    def to_dict(self) -> dict:
        return {
            "family": self.family,
            "ip_layer": self.ip_layer.value,
            "dns_status": self.dns_status.value,
            "dns_evidence": list(self.dns_evidence),
            "https_status": self.https_status.value,
            "https_evidence": list(self.https_evidence),
            "portal_status": self.portal_status.value,
            "portal_evidence": list(self.portal_evidence),
            "classification": self.classification.value,
        }


@dataclass
class VpnReport:
    """Estado de la VPN: INDEPENDIENTE de la red subyacente.

    Los campos de handshake/contadores provienen de diagnósticos reales del
    motor (UAPI en iOS, wg show en Linux). Aquí solo se transportan.
    """
    state: VpnTunnelState = VpnTunnelState.DISCONNECTED
    handshake_age_s: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_delta: int | None = None
    tx_delta: int | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "handshake_age_s": self.handshake_age_s,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "rx_delta": self.rx_delta,
            "tx_delta": self.tx_delta,
            "evidence": list(self.evidence),
        }


@dataclass
class ClassifierResult:
    ipv4: FamilyReport
    ipv6: FamilyReport
    vpn: VpnReport
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "ipv4": self.ipv4.to_dict(),
            "ipv6": self.ipv6.to_dict(),
            "vpn": self.vpn.to_dict(),
            "generated_at": self.generated_at,
        }
