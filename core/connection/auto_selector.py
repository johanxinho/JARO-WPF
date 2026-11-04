"""JARO WPF - Intelligent Transport Auto-Selector (Phase 3).

Compares ONLY general application/IP transports:
  - http3      (HTTP/3 over QUIC)
  - https      (HTTPS over TCP/TLS)
  - ssh_socks5 (SSH Dynamic SOCKS5 Tunnel)
  - wireguard  (WireGuard L3 IP Tunnel)

Invariants:
- Strictly rejects/excludes DNS services (udp_dns, tcp_dns, dot, doq).
- Evaluates 6 metrics: latency, jitter, packet_loss_pct, stability, speed (kbps), and cost_profile.
- Selects ONLY candidates whose end-to-end functionality has been verified.
"""
import math
from typing import Any, Dict, List, Optional

from core.connection.cost_manager import COST_PRIORITY_POINTS, CostProfile

ALLOWED_TRANSPORT_PROTOCOLS = frozenset({"http3", "https", "ssh_socks5", "wireguard"})
FORBIDDEN_DNS_PROTOCOLS = frozenset({"udp_dns", "tcp_dns", "dot", "doq"})


def score_verified_transport(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Computes a documented [0..100] composite score across 6 verified connectivity dimensions."""
    proto = str(candidate.get("protocol", "")).lower()
    if (
        proto in FORBIDDEN_DNS_PROTOCOLS
        or candidate.get("category") == "dns_service"
        or candidate.get("plane") == "dns_resolution"
    ):
        raise ValueError(f"DNS protocol '{proto}' cannot be evaluated as a general transport")

    if proto not in ALLOWED_TRANSPORT_PROTOCOLS:
        return {
            "selectable": False,
            "total": 0.0,
            "reason": f"Unsupported transport protocol: {proto}",
        }

    available = bool(candidate.get("available", False))
    verified = bool(
        candidate.get("functionality_verified")
        or candidate.get("real_internet_verified")
        or (proto == "wireguard" and candidate.get("handshake_verified") and candidate.get("real_internet_verified"))
    )
    latency_ms = candidate.get("avg_latency_ms")

    if not available or not verified or latency_ms is None:
        return {
            "selectable": False,
            "total": 0.0,
            "cost_pts": 0.0,
            "reliability_pts": 0.0,
            "latency_pts": 0.0,
            "jitter_pts": 0.0,
            "speed_pts": 0.0,
            "reason": "Transport functionality is not verified end-to-end",
        }

    # 1. Cost (0..25 pts)
    raw_prof = candidate.get("cost_profile", CostProfile.UNKNOWN.value)
    try:
        prof = raw_prof if isinstance(raw_prof, CostProfile) else CostProfile(str(raw_prof).lower())
    except ValueError:
        prof = CostProfile.UNKNOWN
    cost_pts = round(COST_PRIORITY_POINTS[prof], 2)

    # 2. Packet Loss & Stability (0..25 pts)
    loss_pct = max(0.0, min(100.0, float(candidate.get("packet_loss_pct", 0.0))))
    stability = max(0.0, min(1.0, float(candidate.get("stability_ratio", 1.0))))
    delivery_ratio = 1.0 - (loss_pct / 100.0)
    reliability_pts = round(delivery_ratio * stability * 25.0, 2)

    # 3. Latency (0..20 pts, normalized 0..1000ms)
    lat_f = max(0.0, float(latency_ms))
    latency_pts = round(max(0.0, 20.0 * (1.0 - min(lat_f, 1000.0) / 1000.0)), 2)

    # 4. Jitter (0..10 pts, normalized 0..250ms)
    jitter_f = max(0.0, float(candidate.get("jitter_ms", 0.0)))
    jitter_pts = round(max(0.0, 10.0 * (1.0 - min(jitter_f, 250.0) / 250.0)), 2)

    # 5. Speed / Throughput (0..20 pts)
    dl_kbps = candidate.get("download_kbps")
    ul_kbps = candidate.get("upload_kbps")
    if dl_kbps is not None and float(dl_kbps) > 0:
        effective_kbps = float(dl_kbps) * 0.75 + float(ul_kbps or dl_kbps) * 0.25
        # ~10 pts at 900 kbps, ~20 pts at >= 10 Mbps
        speed_pts = round(min(20.0, math.log10(1.0 + effective_kbps / 100.0) * 10.0), 2)
    else:
        # Neutral baseline when speed sampling is skipped to conserve data budget
        speed_pts = 10.0

    total = round(cost_pts + reliability_pts + latency_pts + jitter_pts + speed_pts, 2)
    return {
        "selectable": True,
        "total": total,
        "cost_pts": cost_pts,
        "reliability_pts": reliability_pts,
        "latency_pts": latency_pts,
        "jitter_pts": jitter_pts,
        "speed_pts": speed_pts,
        "reason": None,
    }


class AutoSelector:
    """Ranks and selects the optimal verified general transport."""

    def rank_transports(self, raw_candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Filters out any DNS entries, scores general transports, and returns the best verified route."""
        evaluated: List[Dict[str, Any]] = []
        excluded_dns_count = 0

        for cand in raw_candidates:
            proto = str(cand.get("protocol", "")).lower()
            if (
                proto in FORBIDDEN_DNS_PROTOCOLS
                or cand.get("category") == "dns_service"
                or cand.get("plane") == "dns_resolution"
            ):
                excluded_dns_count += 1
                continue

            entry = dict(cand)
            breakdown = score_verified_transport(entry)
            entry["selectable"] = breakdown["selectable"]
            entry["auto_score"] = breakdown["total"]
            entry["auto_score_breakdown"] = breakdown
            evaluated.append(entry)

        evaluated.sort(
            key=lambda item: (
                1 if item["selectable"] else 0,
                item["auto_score"],
                -(float(item.get("avg_latency_ms") or 99999.0)),
            ),
            reverse=True,
        )

        selected: Optional[Dict[str, Any]] = next(
            (item for item in evaluated if item["selectable"]),
            None,
        )

        return {
            "selected_transport": selected,
            "ranked_transports": evaluated,
            "excluded_dns_entries": excluded_dns_count,
        }
