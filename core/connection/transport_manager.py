"""JARO WPF - Unified Transport Manager (Phase 2).

Integrates MultiMethodManager with QUIC/HTTP3, SSH Dynamic SOCKS5, and WireGuard IP Tunnels,
strictly separating three distinct networking planes:
  1. dns_resolution        (UDP DNS, TCP DNS, DoT RFC 7858, DoQ RFC 9250)
  2. application_transport (HTTPS/TLS, HTTP/3 over QUIC, SSH local SOCKS5 proxy)
  3. ip_tunnel             (WireGuard L3 tunnel)

Invariants:
- Never considers a protocol available merely because a TCP/UDP port is open.
- Never claims free/unmetered internet access merely because QUIC, DNS, SSH, or VPN responds.
- Enforces metered cellular guard before executing any network probes.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.connection.cost_manager import (
    CostManager,
    CostProfile,
    profile_to_cost_tier,
)
from core.connection.multi_method_manager import (
    DEFAULT_CONFIG_PATH,
    MultiMethodManager,
    compute_transport_score,
    detect_active_media,
)
from core.connection.server_manager import ServerManager
from core.protocols.ssh_engine import SshSocksTunnel, SshTunnelConfig
from core.protocols.vpn_tunnel_engine import (
    WireGuardTunnelEngine,
    validate_wireguard_config_file,
)


class TransportManager:
    """Orchestrates and ranks DNS resolvers, Application Transports, and IP Tunnels."""

    def __init__(
        self,
        config_path: Path = DEFAULT_CONFIG_PATH,
        allow_metered_probes: bool = False,
        allow_global_routes: bool = False,
        samples_per_check: int = 2,
        ssh_tunnels: Optional[List[SshSocksTunnel]] = None,
        wireguard_engines: Optional[List[WireGuardTunnelEngine]] = None,
        cost_manager: Optional[CostManager] = None,
        server_manager: Optional[ServerManager] = None,
    ) -> None:
        self.config_path = config_path
        self.allow_metered_probes = allow_metered_probes
        self.allow_global_routes = allow_global_routes
        self.samples_per_check = max(1, samples_per_check)
        self.cost_manager = cost_manager or CostManager(allow_metered=allow_metered_probes)
        self.server_manager = server_manager or ServerManager(config_path=config_path)
        self.multi_manager = MultiMethodManager(
            config_path=config_path,
            allow_metered_probes=allow_metered_probes,
            samples_per_check=self.samples_per_check,
            cost_manager=self.cost_manager,
        )
        self._ssh_tunnels: List[SshSocksTunnel] = list(ssh_tunnels or [])
        self._wg_engines: List[WireGuardTunnelEngine] = list(wireguard_engines or [])
        self._ssh_by_id: Dict[str, SshSocksTunnel] = {}
        self._wg_by_id: Dict[str, WireGuardTunnelEngine] = {}
        self._load_configured_tunnels()
        self._rebuild_tunnel_index()

    def _rebuild_tunnel_index(self) -> None:
        self._ssh_by_id.clear()
        for idx, tunnel in enumerate(self._ssh_tunnels, start=1):
            self._ssh_by_id[f"ssh-tunnel-{idx}"] = tunnel
            if tunnel.config.host:
                self._ssh_by_id.setdefault(tunnel.config.host, tunnel)

        self._wg_by_id.clear()
        for idx, wg in enumerate(self._wg_engines, start=1):
            tid = f"wireguard-{wg.interface_name}-{idx}"
            self._wg_by_id[tid] = wg
            self._wg_by_id.setdefault(wg.interface_name, wg)

    def get_ssh_tunnel(self, identifier: str) -> Optional[SshSocksTunnel]:
        """Returns the live SshSocksTunnel object by server_id or host."""
        self._rebuild_tunnel_index()
        return self._ssh_by_id.get(identifier)

    def get_wireguard_engine(self, identifier: str) -> Optional[WireGuardTunnelEngine]:
        """Returns the live WireGuardTunnelEngine object by tunnel_id or interface name."""
        self._rebuild_tunnel_index()
        return self._wg_by_id.get(identifier)

    def _load_configured_tunnels(self) -> None:
        """Loads any explicitly authorized SSH or WireGuard entries from servers.json."""
        catalog = self.multi_manager.catalog
        for ssh_item in catalog.get("authorized_ssh_tunnels", []):
            if not ssh_item.get("authorized", False):
                continue
            cfg = SshTunnelConfig(
                host=ssh_item.get("host", ""),
                port=int(ssh_item.get("port", 22)),
                username=ssh_item.get("username", ""),
                identity_file=ssh_item.get("identity_file", ""),
                known_hosts_file=ssh_item.get("known_hosts_file", ""),
                local_bind_host=ssh_item.get("local_bind_host", "127.0.0.1"),
                local_socks_port=int(ssh_item.get("local_socks_port", 1080)),
                authorized=True,
            )
            self._ssh_tunnels.append(SshSocksTunnel(cfg))

        for wg_item in catalog.get("authorized_wireguard_tunnels", []):
            if not wg_item.get("authorized", False):
                continue
            self._wg_engines.append(
                WireGuardTunnelEngine(
                    interface_name=wg_item.get("interface", "wg0"),
                    config_path=wg_item.get("config_path"),
                    authorized=True,
                    allow_global_routes=self.allow_global_routes,
                )
            )

    def _evaluate_ssh_transports(
        self,
        medium_cost: int,
        effective_profile: str = CostProfile.UNKNOWN.value,
    ) -> List[Dict[str, Any]]:
        self._rebuild_tunnel_index()
        results: List[Dict[str, Any]] = []
        for idx, tunnel in enumerate(self._ssh_tunnels, start=1):
            sid = f"ssh-tunnel-{idx}"
            val = tunnel.config.validate()
            if not val["valid"]:
                results.append({
                    "plane": "application_transport",
                    "server_id": sid,
                    "server_name": f"SSH SOCKS5 ({tunnel.config.host or 'unconfigured'})",
                    "host": tunnel.config.host,
                    "protocol": "ssh_socks5",
                    "port": tunnel.config.port,
                    "process_alive": False,
                    "local_socks5_functional": False,
                    "local_ssh_tunnel_functional": False,
                    "remote_ssh_tunnel_functional": False,
                    "https_egress_verified": False,
                    "available": False,
                    "real_internet_verified": False,
                    "avg_latency_ms": None,
                    "jitter_ms": 0.0,
                    "stability_ratio": 0.0,
                    "cost_profile": effective_profile,
                    "cost_tier": medium_cost,
                    "score": 0.0,
                    "error": val["error"],
                })
                continue

            # Live check of process, local SOCKS5, remote SSH channel forwarding, and HTTPS egress
            health = tunnel.check_health(verify_https_egress=True)
            egress_ok = bool(health.get("https_egress_verified") and health.get("remote_ssh_tunnel_functional"))
            available = bool(health.get("healthy") and egress_ok)
            latency = health.get("latency_ms") if available else None
            breakdown = compute_transport_score(
                available=available,
                real_internet=egress_ok,
                latency_ms=latency,
                stability_ratio=1.0 if available else 0.0,
                jitter_ms=0.0,
                cost_tier=medium_cost,
            )
            results.append({
                "plane": "application_transport",
                "server_id": sid,
                "server_name": f"SSH SOCKS5 ({tunnel.config.host})",
                "host": tunnel.config.host,
                "protocol": "ssh_socks5",
                "port": tunnel.config.port,
                "local_socks_endpoint": f"{tunnel.config.local_bind_host}:{tunnel.config.local_socks_port}",
                "process_alive": bool(health.get("process_alive")),
                "local_socks5_functional": bool(health.get("local_socks5_functional")),
                "local_ssh_tunnel_functional": bool(health.get("local_ssh_tunnel_functional")),
                "remote_ssh_tunnel_functional": bool(health.get("remote_ssh_tunnel_functional")),
                "https_egress_verified": egress_ok,
                "available": available,
                "real_internet_verified": egress_ok,
                "avg_latency_ms": latency,
                "jitter_ms": 0.0,
                "stability_ratio": 1.0 if available else 0.0,
                "cost_profile": effective_profile,
                "cost_tier": medium_cost,
                "score": breakdown["total"],
                "score_breakdown": breakdown,
                "error": health.get("error"),
            })
        return results

    def _evaluate_wireguard_tunnels(
        self,
        medium_cost: int,
        effective_profile: str = CostProfile.UNKNOWN.value,
    ) -> List[Dict[str, Any]]:
        self._rebuild_tunnel_index()
        results: List[Dict[str, Any]] = []
        engines = self._wg_engines or [
            WireGuardTunnelEngine(
                interface_name="wg0",
                authorized=False,
                allow_global_routes=self.allow_global_routes,
            )
        ]

        for idx, wg in enumerate(engines, start=1):
            tid = f"wireguard-{wg.interface_name}-{idx}"
            config_valid: Optional[bool] = None
            config_err: Optional[str] = None
            if wg.config_path is not None:
                cval = validate_wireguard_config_file(
                    wg.config_path,
                    authorized=wg.authorized,
                    allow_global_routes=wg.allow_global_routes,
                )
                config_valid = cval["valid"]
                config_err = cval.get("error")

            should_verify_egress = bool(wg.authorized and (config_valid is not False))
            state = wg.inspect_state(verify_internet_egress=should_verify_egress)

            https_egress_ok = bool(state.get("https_egress_verified"))
            measured_latency = state.get("egress_latency_ms") if https_egress_ok else None
            available = bool(
                should_verify_egress
                and state["interface_exists"]
                and state["handshake_verified"]
                and https_egress_ok
                and measured_latency is not None
            )

            breakdown = compute_transport_score(
                available=available,
                real_internet=https_egress_ok,
                latency_ms=measured_latency,
                stability_ratio=1.0 if available else 0.0,
                jitter_ms=0.0,
                cost_tier=medium_cost,
            )
            results.append({
                "plane": "ip_tunnel",
                "tunnel_id": tid,
                "server_id": tid,
                "interface": wg.interface_name,
                "protocol": "wireguard",
                "authorized": wg.authorized,
                "cli_tooling_ready": state["tooling"]["cli_ready"],
                "interface_exists": state["interface_exists"],
                "handshake_verified": state["handshake_verified"],
                "data_transfer_verified": bool(state.get("data_transfer_verified")),
                "https_egress_verified": https_egress_ok,
                "available": available,
                "real_internet_verified": https_egress_ok,
                "avg_latency_ms": measured_latency,
                "jitter_ms": 0.0,
                "stability_ratio": 1.0 if available else 0.0,
                "config_valid": config_valid,
                "cost_profile": effective_profile,
                "cost_tier": medium_cost,
                "score": breakdown["total"],
                "score_breakdown": breakdown,
                "error": config_err or state.get("egress_error") or state.get("note"),
            })
        return results

    def evaluate_planes(self, include_dns_plane: bool = True) -> Dict[str, Any]:
        """Evaluates all authorized methods across the 3 strictly separated networking planes."""
        self.cost_manager.allow_metered = self.allow_metered_probes
        self.multi_manager.allow_metered_probes = self.allow_metered_probes

        raw_media = detect_active_media(cost_manager=self.cost_manager) if detect_active_media.__module__ == "core.connection.multi_method_manager" else detect_active_media()
        active_media = self.multi_manager._normalize_media_with_cost_manager(raw_media)

        if active_media:
            gate = self.cost_manager.evaluate_network_gate(active_media)
            if not gate["allowed"]:
                return {
                    "module": "JARO WPF UNIFIED TRANSPORT MANAGER",
                    "status": "ABORTED_METERED_GUARD",
                    "reason": gate["reason"],
                    "active_media": active_media,
                    "effective_cost_profile": gate["effective_profile"],
                    "real_internet_verified": False,
                    "planes": {
                        "dns_resolution": [],
                        "application_transport": [],
                        "ip_tunnel": [],
                    },
                    "selected": {
                        "dns_resolver": None,
                        "application_transport": None,
                        "ip_tunnel": None,
                    },
                }
            medium_cost = int(gate["cost_tier"])
            effective_profile = gate["effective_profile"]
        else:
            medium_cost = profile_to_cost_tier(CostProfile.UNKNOWN)
            effective_profile = CostProfile.UNKNOWN.value

        base_report = (
            self.multi_manager.evaluate_all()
            if include_dns_plane
            else self.multi_manager.evaluate_all(include_dns=False)
        )

        # Plane 1: DNS Resolution (UDP 53, TCP 53, DoT 853, DoQ 853)
        dns_plane: List[Dict[str, Any]] = []
        if include_dns_plane:
            for item in base_report.get("dns_resolvers", []):
                entry = dict(item)
                entry["plane"] = "dns_resolution"
                entry["provides_general_internet"] = False
                dns_plane.append(entry)

        # Plane 2: Application Transport (HTTPS, HTTP/3 over QUIC, SSH SOCKS5)
        app_plane: List[Dict[str, Any]] = []
        for item in base_report.get("internet_transports", []):
            entry = dict(item)
            entry["plane"] = "application_transport"
            app_plane.append(entry)

        app_plane.extend(
            self._evaluate_ssh_transports(
                medium_cost=medium_cost,
                effective_profile=effective_profile,
            )
        )
        app_plane.sort(key=lambda c: (-c["score"], c.get("avg_latency_ms") or 99999.0))

        # Plane 3: IP Tunnels (WireGuard)
        ip_tunnel_plane = self._evaluate_wireguard_tunnels(
            medium_cost=medium_cost,
            effective_profile=effective_profile,
        )
        ip_tunnel_plane.sort(key=lambda c: -c["score"])

        best_dns = next((c for c in dns_plane if c["available"]), None)
        best_app = next((c for c in app_plane if c["available"]), None)
        best_ip_tunnel = next((c for c in ip_tunnel_plane if c["available"]), None)

        remote_ssh = self.server_manager.evaluate_remote_tunnel_readiness("ssh_socks5")
        if remote_ssh["configured_remote_count"] == 0:
            live_remote_ssh = [t for t in self._ssh_tunnels if t.config.authorized and not t.config.is_loopback_target]
            if live_remote_ssh:
                verified_ssh = any(
                    c["protocol"] == "ssh_socks5" and c.get("remote_ssh_tunnel_functional") and c.get("https_egress_verified")
                    for c in app_plane
                )
                remote_ssh = {
                    "protocol": "ssh_socks5",
                    "status": "ONLINE_VERIFIED" if verified_ssh else "UNVERIFIED",
                    "ready": verified_ssh,
                    "verified_end_to_end": verified_ssh,
                    "configured_remote_count": len(live_remote_ssh),
                    "reason": None if verified_ssh else "Authorized remote SSH tunnel configured in memory, pending live verification",
                }

        remote_wg = self.server_manager.evaluate_remote_tunnel_readiness("wireguard")
        if remote_wg["configured_remote_count"] == 0:
            live_auth_wg = [w for w in self._wg_engines if w.authorized]
            if live_auth_wg:
                verified_wg = any(c.get("available") for c in ip_tunnel_plane)
                remote_wg = {
                    "protocol": "wireguard",
                    "status": "ONLINE_VERIFIED" if verified_wg else "UNVERIFIED",
                    "ready": verified_wg,
                    "verified_end_to_end": verified_wg,
                    "configured_remote_count": len(live_auth_wg),
                    "reason": None if verified_wg else "Authorized WireGuard tunnel configured in memory, pending live verification",
                }

        return {
            "module": "JARO WPF UNIFIED TRANSPORT MANAGER",
            "status": "OK",
            "active_media": active_media,
            "effective_cost_profile": effective_profile,
            "dns_plane_evaluated": include_dns_plane,
            "connectivity_state": base_report["connectivity_state"],
            "real_internet_verified": base_report["real_internet_verified"],
            "remote_tunnel_readiness": {
                "ssh_socks5": remote_ssh,
                "wireguard": remote_wg,
            },
            "policy_notice": (
                "Transport availability reflects verified protocol reachability on the current "
                "authorized network and never implies free/unbilled carrier bypass."
            ),
            "selected": {
                "dns_resolver": best_dns,
                "application_transport": best_app,
                "ip_tunnel": best_ip_tunnel,
            },
            "planes": {
                "dns_resolution": dns_plane,
                "application_transport": app_plane,
                "ip_tunnel": ip_tunnel_plane,
            },
        }


def main() -> None:
    mgr = TransportManager(samples_per_check=2)
    print(json.dumps(mgr.evaluate_planes(), indent=4))


if __name__ == "__main__":
    main()
