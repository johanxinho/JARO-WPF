"""JARO WPF - Multi-Method Connection Manager & Categorized Route Selector."""
import json
from pathlib import Path
import statistics
from typing import Any, Dict, List, Optional

from core.connection.analyzer import get_interfaces
from core.connection.cost_manager import (
    CostManager,
    CostProfile,
    profile_to_cost_tier,
)
from core.network_tests.connectivity_prober import (
    evaluate_full_connectivity,
    probe_dot_dns,
    probe_https_egress,
    probe_tcp_dns,
    probe_tls_handshake,
    probe_udp_dns,
)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "servers.json"

CELLULAR_PREFIXES = ("wwan", "rmnet", "usb", "ppp", "pdp_ip", "ccmni", "enp0s20", "ipheth", "rndis")
WIFI_PREFIXES = ("wl", "wlan", "wifi", "en0")
ETHERNET_PREFIXES = ("eth", "enp", "eno", "ens", "enx")

DNS_PROTOCOLS = ("udp_dns", "tcp_dns", "dot", "doq")
ENCRYPTED_DNS_PROTOCOLS = ("dot", "doq")
TRANSPORT_PROTOCOLS = ("https",)


def _is_usb_tether_name(ifname: str) -> bool:
    lower = ifname.lower()
    if lower.startswith(("usb", "ipheth", "rndis")):
        return True
    if lower.startswith("enp") and "u" in lower[3:]:
        return True
    return False


def classify_interface_medium(
    ifname: str,
    cost_manager: Optional[CostManager] = None,
    os_metered_hint: Optional[bool] = None,
) -> Dict[str, Any]:
    """Classifies network interface medium and delegates cost classification to CostManager.

    Never assumes Wi-Fi or Ethernet is free unless explicitly configured in CostManager.
    """
    lower = ifname.lower()
    if lower == "lo":
        medium = "loopback"
    elif lower.startswith(CELLULAR_PREFIXES) or _is_usb_tether_name(lower):
        medium = "cellular" if lower.startswith(("wwan", "rmnet", "ppp", "pdp_ip", "ccmni")) else "ethernet"
        if os_metered_hint is None:
            os_metered_hint = True
    elif lower.startswith(WIFI_PREFIXES):
        medium = "wifi"
    elif lower.startswith(ETHERNET_PREFIXES):
        medium = "ethernet"
    else:
        medium = "unknown"

    cm = cost_manager or CostManager()
    profile = cm.classify_interface(
        ifname=ifname,
        medium=medium,
        os_metered_hint=os_metered_hint,
    )
    return {
        "medium": medium,
        "cost_profile": profile.value,
        "metered": profile == CostProfile.METERED,
        "base_cost_tier": profile_to_cost_tier(profile),
    }


def detect_active_media(cost_manager: Optional[CostManager] = None) -> List[Dict[str, Any]]:
    """Detects active network interfaces and evaluates cost profiles uniformly via CostManager."""
    cm = cost_manager or CostManager()
    raw_interfaces = get_interfaces()
    enriched: List[Dict[str, Any]] = []
    for iface in raw_interfaces:
        name = iface.get("name") or ""
        state = iface.get("state") or "UNKNOWN"
        addrs = iface.get("addresses") or []
        if name == "lo" or not addrs:
            continue
        if str(state).upper() not in ("UP", "UNKNOWN"):
            continue
        meta = classify_interface_medium(name, cost_manager=cm)
        enriched.append({
            "name": name,
            "state": state,
            "addresses": addrs,
            "medium": meta["medium"],
            "cost_profile": meta["cost_profile"],
            "metered": meta["metered"],
            "base_cost_tier": meta["base_cost_tier"],
        })
    return enriched


def compute_transport_score(
    available: bool,
    real_internet: bool,
    latency_ms: Optional[float],
    stability_ratio: float,
    jitter_ms: float,
    cost_tier: int,
) -> Dict[str, float]:
    """Computes comparable [0..100] score for general internet transport candidates.

    Weights:
      - verification_pts (0..40): 40 if verified real internet egress, 15 if endpoint-only, 0 if down
      - stability_pts    (0..25): linear on stability_ratio [0..1]
      - latency_pts      (0..25): normalized over 0..1000ms effective latency (latency + 1.5 * jitter)
      - cost_pts         (0..10): 10 for tier 0, 5 for tier 1, 0 for tier >= 2
    """
    if not available or latency_ms is None:
        return {
            "total": 0.0,
            "verification_pts": 0.0,
            "stability_pts": 0.0,
            "latency_pts": 0.0,
            "cost_pts": 0.0,
        }

    verification_pts = 40.0 if real_internet else 15.0
    stability_pts = round(max(0.0, min(1.0, stability_ratio)) * 25.0, 2)
    effective_latency = latency_ms + (jitter_ms * 1.5)
    latency_pts = round(max(0.0, 25.0 * (1.0 - min(effective_latency, 1000.0) / 1000.0)), 2)
    cost_pts = round(max(0.0, 10.0 - (cost_tier * 5.0)), 2)
    total = round(verification_pts + stability_pts + latency_pts + cost_pts, 2)

    return {
        "total": total,
        "verification_pts": verification_pts,
        "stability_pts": stability_pts,
        "latency_pts": latency_pts,
        "cost_pts": cost_pts,
    }


def compute_dns_score(
    available: bool,
    encrypted: bool,
    latency_ms: Optional[float],
    stability_ratio: float,
    jitter_ms: float,
    cost_tier: int,
) -> Dict[str, float]:
    """Computes comparable [0..100] score strictly for DNS resolution services.

    Weights:
      - protocol_security_pts (0..35): 35 for verified DoQ/DoT (encrypted), 25 for verified UDP/TCP DNS
      - stability_pts         (0..30): linear on stability_ratio [0..1]
      - latency_pts           (0..25): normalized over 0..500ms effective latency (latency + 1.5 * jitter)
      - cost_pts              (0..10): 10 for tier 0, 5 for tier 1, 0 for tier >= 2
    """
    if not available or latency_ms is None:
        return {
            "total": 0.0,
            "protocol_security_pts": 0.0,
            "stability_pts": 0.0,
            "latency_pts": 0.0,
            "cost_pts": 0.0,
        }

    protocol_security_pts = 35.0 if encrypted else 25.0
    stability_pts = round(max(0.0, min(1.0, stability_ratio)) * 30.0, 2)
    effective_latency = latency_ms + (jitter_ms * 1.5)
    latency_pts = round(max(0.0, 25.0 * (1.0 - min(effective_latency, 500.0) / 500.0)), 2)
    cost_pts = round(max(0.0, 10.0 - (cost_tier * 5.0)), 2)
    total = round(protocol_security_pts + stability_pts + latency_pts + cost_pts, 2)

    return {
        "total": total,
        "protocol_security_pts": protocol_security_pts,
        "stability_pts": stability_pts,
        "latency_pts": latency_pts,
        "cost_pts": cost_pts,
    }


def compute_candidate_score(
    available: bool,
    real_internet: bool,
    latency_ms: Optional[float],
    stability_ratio: float,
    jitter_ms: float,
    cost_tier: int,
) -> float:
    """Backward-compatible wrapper returning the total transport score [0..100]."""
    return compute_transport_score(
        available=available,
        real_internet=real_internet,
        latency_ms=latency_ms,
        stability_ratio=stability_ratio,
        jitter_ms=jitter_ms,
        cost_tier=cost_tier,
    )["total"]


class MultiMethodManager:
    """Evaluates authorized servers, strictly separating DNS services from general internet transports."""

    def __init__(
        self,
        config_path: Path = DEFAULT_CONFIG_PATH,
        allow_metered_probes: bool = False,
        samples_per_check: int = 2,
        cost_manager: Optional[CostManager] = None,
    ) -> None:
        self.config_path = config_path
        self.allow_metered_probes = allow_metered_probes
        self.samples_per_check = max(1, samples_per_check)
        self.cost_manager = cost_manager or CostManager(allow_metered=allow_metered_probes)
        self.catalog = self._load_catalog()

    def _load_catalog(self) -> Dict[str, Any]:
        with open(self.config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _normalize_media_with_cost_manager(
        self,
        active_media: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Ensures every interface entry uses CostManager rather than assuming Ethernet/Wi-Fi is free."""
        self.cost_manager.allow_metered = self.allow_metered_probes
        normalized: List[Dict[str, Any]] = []
        for item in active_media:
            entry = dict(item)
            name = str(entry.get("name") or "")
            medium = str(entry.get("medium") or "unknown")
            hint = True if entry.get("metered") is True else entry.get("os_metered_hint")
            prof_raw = entry.get("cost_profile")
            if isinstance(prof_raw, str):
                try:
                    prof = CostProfile(prof_raw.lower())
                except ValueError:
                    prof = self.cost_manager.classify_interface(name, medium=medium, os_metered_hint=hint)
            elif isinstance(prof_raw, CostProfile):
                prof = prof_raw
            else:
                prof = self.cost_manager.classify_interface(name, medium=medium, os_metered_hint=hint)

            entry["cost_profile"] = prof.value
            entry["metered"] = prof == CostProfile.METERED
            entry["base_cost_tier"] = profile_to_cost_tier(prof)
            normalized.append(entry)
        return normalized

    def _run_protocol_samples(
        self,
        protocol: str,
        host: str,
        sni: str,
        proto_cfg: Dict[str, Any],
    ) -> Dict[str, Any]:
        latencies: List[float] = []
        last_error: Optional[str] = None
        port = proto_cfg.get("port", 443)
        target_sni = proto_cfg.get("sni", sni)

        for _ in range(self.samples_per_check):
            if protocol == "udp_dns":
                res = probe_udp_dns(host, port=port)
                ok = res["protocol_verified"]
            elif protocol == "tcp_dns":
                res = probe_tcp_dns(host, port=port)
                ok = res["protocol_verified"]
            elif protocol in ("dot", "tls"):
                # If port 853 or category is dns_service, verify full RFC 7858 DoT DNS resolution
                if port == 853 or proto_cfg.get("category") == "dns_service":
                    res = probe_dot_dns(host, port=port, sni=target_sni)
                    ok = res["protocol_verified"]
                else:
                    res = probe_tls_handshake(host, port=port, sni=target_sni)
                    ok = res["server_verified"]
            elif protocol == "doq":
                # Lazy import aioquic DoQ engine only when needed to keep baseline RAM minimal
                from core.protocols.doq_engine import probe_doq
                res = probe_doq(host=host, port=port, sni=target_sni)
                ok = res["protocol_verified"]
            elif protocol == "https":
                path = proto_cfg.get("path", "/")
                expected_status = int(proto_cfg.get("expected_status", 200))
                expected_sub = str(proto_cfg.get("expected_substring", ""))
                url = f"https://{target_sni}{path}"
                res = probe_https_egress(
                    url=url,
                    expected_status=expected_status,
                    expected_substring=expected_sub,
                    connect_host=host,
                    sni_hostname=target_sni,
                )
                ok = res["real_internet"]
            elif protocol == "http3":
                from core.protocols.quic_engine import request_http3
                path = proto_cfg.get("path", "/")
                expected_status = int(proto_cfg.get("expected_status", 200))
                expected_sub = str(proto_cfg.get("expected_substring", ""))
                url = f"https://{target_sni}{path}"
                h3_res = request_http3(
                    url=url,
                    connect_host=host,
                    connect_port=port,
                    sni_hostname=target_sni,
                    expected_status=expected_status,
                    expected_substring=expected_sub,
                )
                res = {
                    "latency_ms": h3_res.get("total_latency_ms"),
                    "error": h3_res.get("error"),
                }
                ok = h3_res["http3_verified"]
            else:
                continue

            if ok and res.get("latency_ms") is not None:
                latencies.append(float(res["latency_ms"]))
            else:
                last_error = res.get("error")

        success_count = len(latencies)
        stability = round(success_count / self.samples_per_check, 2)
        avg_latency = round(statistics.mean(latencies), 2) if latencies else None
        jitter = round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0

        is_dns_category = (
            proto_cfg.get("category") == "dns_service"
            or protocol in DNS_PROTOCOLS
            or port in (53, 853)
        )

        return {
            "category": "dns_service" if is_dns_category else "internet_transport",
            "protocol": protocol,
            "port": port,
            "available": success_count > 0,
            "stability_ratio": stability,
            "avg_latency_ms": avg_latency,
            "jitter_ms": jitter,
            "encrypted": protocol in ("dot", "doq", "tls", "https", "http3"),
            "error": None if success_count > 0 else last_error,
        }

    def evaluate_all(self, include_dns: bool = True) -> Dict[str, Any]:
        """Evaluates active media via CostManager and ranks DNS vs Internet Transports separately."""
        raw_media = detect_active_media()
        active_media = self._normalize_media_with_cost_manager(raw_media)

        if active_media:
            gate = self.cost_manager.evaluate_network_gate(active_media)
            if not gate["allowed"]:
                return {
                    "status": "ABORTED_METERED_GUARD",
                    "reason": gate["reason"],
                    "active_media": active_media,
                    "effective_cost_profile": gate["effective_profile"],
                    "real_internet_verified": False,
                    "selected_internet_transport": None,
                    "selected_dns_resolver": None,
                    "selected_route": None,
                    "internet_transports": [],
                    "dns_resolvers": [],
                }
            medium_cost = int(gate["cost_tier"])
            effective_profile = gate["effective_profile"]
        else:
            medium_cost = profile_to_cost_tier(CostProfile.UNKNOWN)
            effective_profile = CostProfile.UNKNOWN.value

        egress_check = (
            evaluate_full_connectivity()
            if include_dns
            else evaluate_full_connectivity(include_dns=False)
        )
        real_internet_global = egress_check["real_internet_verified"]

        internet_transports: List[Dict[str, Any]] = []
        dns_resolvers: List[Dict[str, Any]] = []

        for server in self.catalog.get("servers", []):
            if not server.get("authorized", False):
                continue

            host = server["host"]
            sni = server.get("hostname", host)
            total_cost = int(server.get("cost_tier", 0)) + medium_cost
            protocols = server.get("protocols", {})

            for proto_name, proto_cfg in protocols.items():
                if not proto_cfg.get("enabled", False):
                    continue

                port = int(proto_cfg.get("port", 443))
                is_dns_proto = (
                    proto_cfg.get("category") == "dns_service"
                    or proto_name in DNS_PROTOCOLS
                    or port in (53, 853)
                )
                if is_dns_proto and not include_dns:
                    continue

                stats = self._run_protocol_samples(proto_name, host, sni, proto_cfg)
                category = stats["category"]

                if category == "dns_service":
                    breakdown = compute_dns_score(
                        available=stats["available"],
                        encrypted=stats["encrypted"],
                        latency_ms=stats["avg_latency_ms"],
                        stability_ratio=stats["stability_ratio"],
                        jitter_ms=stats["jitter_ms"],
                        cost_tier=total_cost,
                    )
                    dns_resolvers.append({
                        "category": "dns_service",
                        "server_id": server["id"],
                        "server_name": server["name"],
                        "host": host,
                        "protocol": proto_name,
                        "port": stats["port"],
                        "available": stats["available"],
                        "encrypted_dns": stats["encrypted"],
                        "real_internet_verified": False,  # DNS resolvers never imply general internet access
                        "avg_latency_ms": stats["avg_latency_ms"],
                        "jitter_ms": stats["jitter_ms"],
                        "stability_ratio": stats["stability_ratio"],
                        "cost_profile": effective_profile,
                        "cost_tier": total_cost,
                        "score": breakdown["total"],
                        "score_breakdown": breakdown,
                        "error": stats["error"],
                    })
                else:
                    verified_egress = real_internet_global and stats["available"]
                    breakdown = compute_transport_score(
                        available=stats["available"],
                        real_internet=verified_egress,
                        latency_ms=stats["avg_latency_ms"],
                        stability_ratio=stats["stability_ratio"],
                        jitter_ms=stats["jitter_ms"],
                        cost_tier=total_cost,
                    )
                    internet_transports.append({
                        "category": "internet_transport",
                        "server_id": server["id"],
                        "server_name": server["name"],
                        "host": host,
                        "sni": proto_cfg.get("sni", sni),
                        "path": proto_cfg.get("path", "/"),
                        "expected_status": int(proto_cfg.get("expected_status", 200)),
                        "expected_substring": str(proto_cfg.get("expected_substring", "")),
                        "protocol": proto_name,
                        "port": stats["port"],
                        "available": stats["available"],
                        "real_internet_verified": verified_egress,
                        "avg_latency_ms": stats["avg_latency_ms"],
                        "jitter_ms": stats["jitter_ms"],
                        "stability_ratio": stats["stability_ratio"],
                        "cost_profile": effective_profile,
                        "cost_tier": total_cost,
                        "score": breakdown["total"],
                        "score_breakdown": breakdown,
                        "error": stats["error"],
                    })

        internet_transports.sort(key=lambda c: (-c["score"], c["avg_latency_ms"] or 99999.0))
        dns_resolvers.sort(key=lambda c: (-c["score"], c["avg_latency_ms"] or 99999.0))

        best_transport = next((c for c in internet_transports if c["available"]), None)
        best_dns = next((c for c in dns_resolvers if c["available"]), None)

        return {
            "module": "JARO WPF MULTI-METHOD MANAGER",
            "status": "OK",
            "active_media": active_media,
            "effective_cost_profile": effective_profile,
            "connectivity_state": egress_check["state"],
            "real_internet_verified": real_internet_global,
            "non_dns_web_egress_verified": egress_check["summary"]["non_dns_web_egress_ok"],
            "selected_internet_transport": best_transport,
            "selected_dns_resolver": best_dns,
            "selected_route": best_transport,
            "internet_transports": internet_transports,
            "dns_resolvers": dns_resolvers,
        }


def main() -> None:
    manager = MultiMethodManager(samples_per_check=2)
    report = manager.evaluate_all()
    print(json.dumps(report, indent=4))


if __name__ == "__main__":
    main()
