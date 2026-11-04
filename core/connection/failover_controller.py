"""JARO WPF - Autonomous Connectivity Core & Automatic Failover Controller (Phase 3).

Orchestrates:
- NetworkMonitor (interface transitions, disconnects/reconnects, metered detection)
- CostManager (FREE / UNKNOWN / METERED policy & byte consumption limits)
- AutoSelector (6-metric comparison across HTTP/3, HTTPS, SSH/SOCKS5, WireGuard; excludes DNS)
- BandwidthTester (micro-throughput, latency, jitter, packet loss)
- ConnectionSession (live session state, diagnostics, failover history)
- ExponentialBackoffReconnector (bounded retries & circuit breaker against infinite loops)
"""
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.connection.auto_selector import AutoSelector
from core.connection.connection_session import ConnectionSession, SessionState
from core.connection.cost_manager import CostManager
from core.connection.network_monitor import NetworkMonitor
from core.connection.reconnector import ExponentialBackoffReconnector
from core.connection.transport_manager import TransportManager
from core.network_tests.bandwidth_tester import BandwidthTester
from core.network_tests.connectivity_prober import probe_https_egress
from core.protocols.ssh_engine import probe_https_over_socks5, socks5_greeting_probe
from core.protocols.vpn_tunnel_engine import WireGuardTunnelEngine

DEFAULT_LOG_PATH = Path(__file__).resolve().parents[2] / "logs" / "failover_events.jsonl"


class FailoverController:
    """Autonomous supervisor managing initial selection, live health checks, and non-disruptive failover."""

    def __init__(
        self,
        cost_manager: Optional[CostManager] = None,
        network_monitor: Optional[NetworkMonitor] = None,
        transport_manager: Optional[TransportManager] = None,
        auto_selector: Optional[AutoSelector] = None,
        bandwidth_tester: Optional[BandwidthTester] = None,
        session: Optional[ConnectionSession] = None,
        reconnector: Optional[ExponentialBackoffReconnector] = None,
        candidate_provider: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        active_health_checker: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_log_path: Optional[Path] = DEFAULT_LOG_PATH,
    ) -> None:
        self.cost_manager = cost_manager or CostManager()
        self.network_monitor = network_monitor or NetworkMonitor(cost_manager=self.cost_manager)
        self.transport_manager = transport_manager or TransportManager(
            allow_metered_probes=self.cost_manager.allow_metered,
            samples_per_check=2,
            cost_manager=self.cost_manager,
        )
        self.auto_selector = auto_selector or AutoSelector()
        self.bandwidth_tester = bandwidth_tester or BandwidthTester(cost_manager=self.cost_manager)
        self.session = session or ConnectionSession()
        self.reconnector = reconnector or ExponentialBackoffReconnector(
            base_delay=0.5,
            max_delay=15.0,
            max_attempts=3,
            circuit_cooldown_s=20.0,
        )
        self._candidate_provider = candidate_provider
        self._active_health_checker = active_health_checker or self._default_active_health_check
        self.event_log_path = event_log_path
        self._active_transport_record: Optional[Dict[str, Any]] = None

    def _log_event(self, payload: Dict[str, Any]) -> None:
        if self.event_log_path is None:
            return
        try:
            self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.event_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except OSError:
            pass

    def _default_active_health_check(self, transport: Dict[str, Any]) -> Dict[str, Any]:
        """Performs a live verification of the active transport (never relies on cached booleans)."""
        budget = self.cost_manager.check_budget_for_transfer(1024)
        if not budget["allowed"]:
            return {"healthy": False, "error": budget["reason"]}

        proto = str(transport.get("protocol", "")).lower()
        host = str(transport.get("host", ""))
        port = int(transport.get("port") or 443)
        sni = str(transport.get("sni") or host)
        path = str(transport.get("path") or "/")

        if proto == "http3":
            from core.protocols.quic_engine import request_http3
            url = f"https://{sni}{path}"
            res = request_http3(
                url=url,
                connect_host=host,
                connect_port=port,
                sni_hostname=sni,
                expected_status=int(transport.get("expected_status", 200)),
                expected_substring=str(transport.get("expected_substring", "")),
                timeout=3.0,
            )
            self.cost_manager.record_consumption(int(res.get("response_bytes", 0)) + 512)
            return {
                "healthy": bool(res.get("http3_verified")),
                "latency_ms": res.get("total_latency_ms"),
                "error": res.get("error"),
            }

        if proto == "https":
            url = f"https://{sni}{path}"
            res = probe_https_egress(
                url=url,
                expected_status=int(transport.get("expected_status", 200)),
                expected_substring=str(transport.get("expected_substring", "")),
                connect_host=host,
                sni_hostname=sni,
                timeout=3.0,
                ssl_context=transport.get("ssl_context"),
            )
            self.cost_manager.record_consumption(int(res.get("bytes_estimated", 1024)))
            return {
                "healthy": bool(res.get("real_internet")),
                "latency_ms": res.get("latency_ms"),
                "error": res.get("error"),
            }

        if proto == "ssh_socks5":
            sid = str(transport.get("server_id") or host or "")
            tunnel = self.transport_manager.get_ssh_tunnel(sid)
            target_host = str(transport.get("egress_target_host") or "example.com")
            target_port = int(transport.get("egress_target_port") or 443)
            target_path = str(transport.get("egress_target_path") or "/")
            exp_status = int(transport.get("expected_status", 200))
            exp_sub = str(transport.get("expected_substring", "Example Domain"))
            ssl_ctx = transport.get("ssl_context")

            if tunnel is not None:
                live = tunnel.check_health(
                    verify_https_egress=True,
                    target_host=target_host,
                    target_port=target_port,
                    path=target_path,
                    expected_status=exp_status,
                    expected_substring=exp_sub,
                    timeout=3.5,
                    ssl_context=ssl_ctx,
                )
                self.cost_manager.record_consumption(int(live.get("bytes_estimated", 1024)))
                return {
                    "healthy": bool(
                        live.get("healthy")
                        and live.get("process_alive")
                        and live.get("remote_ssh_tunnel_functional")
                        and live.get("https_egress_verified")
                    ),
                    "process_alive": bool(live.get("process_alive")),
                    "local_socks5_functional": bool(live.get("local_socks5_functional")),
                    "remote_ssh_tunnel_functional": bool(live.get("remote_ssh_tunnel_functional")),
                    "https_egress_verified": bool(live.get("https_egress_verified")),
                    "latency_ms": live.get("latency_ms"),
                    "error": live.get("error"),
                }

            # Live check via explicit local_socks_endpoint when no SshSocksTunnel object is registered
            socks_ep = str(transport.get("local_socks_endpoint") or "")
            if ":" not in socks_ep:
                return {
                    "healthy": False,
                    "latency_ms": None,
                    "error": "Cannot verify SSH/SOCKS5 health: no live SshSocksTunnel or local_socks_endpoint",
                }
            socks_h, socks_p_str = socks_ep.rsplit(":", 1)
            if not socks_p_str.isdigit():
                return {
                    "healthy": False,
                    "latency_ms": None,
                    "error": f"Invalid local_socks_endpoint: {socks_ep}",
                }
            socks_p = int(socks_p_str)
            greet = socks5_greeting_probe(socks_h, socks_p, timeout=1.5)
            if not greet["socks5_ready"]:
                self.cost_manager.record_consumption(64)
                return {
                    "healthy": False,
                    "local_socks5_functional": False,
                    "https_egress_verified": False,
                    "latency_ms": None,
                    "error": greet["error"],
                }
            egress = probe_https_over_socks5(
                socks_host=socks_h,
                socks_port=socks_p,
                target_host=target_host,
                target_port=target_port,
                path=target_path,
                expected_status=exp_status,
                expected_substring=exp_sub,
                timeout=3.5,
                ssl_context=ssl_ctx,
            )
            self.cost_manager.record_consumption(int(egress.get("bytes_estimated", 1024)))
            return {
                "healthy": bool(egress.get("real_internet")),
                "local_socks5_functional": True,
                "remote_ssh_tunnel_functional": bool(egress.get("tunnel_stream_forwarded")),
                "https_egress_verified": bool(egress.get("real_internet")),
                "latency_ms": egress.get("latency_ms"),
                "error": egress.get("error"),
            }

        if proto == "wireguard":
            tid = str(transport.get("tunnel_id") or transport.get("server_id") or transport.get("interface") or "")
            wg_engine = self.transport_manager.get_wireguard_engine(tid)
            if wg_engine is None:
                ifname = str(transport.get("interface") or "")
                if not ifname or not transport.get("authorized", False):
                    return {
                        "healthy": False,
                        "latency_ms": None,
                        "error": "Cannot verify WireGuard health: no authorized WireGuardTunnelEngine configured",
                    }
                wg_engine = WireGuardTunnelEngine(
                    interface_name=ifname,
                    config_path=transport.get("config_path"),
                    authorized=True,
                )

            state = wg_engine.inspect_state(
                verify_internet_egress=True,
                egress_url=str(transport.get("egress_url") or "https://example.com/"),
                expected_status=int(transport.get("expected_status", 200)),
                expected_substring=str(transport.get("expected_substring", "Example Domain")),
                ssl_context=transport.get("ssl_context"),
            )
            self.cost_manager.record_consumption(int(state.get("bytes_estimated", 1024)))
            healthy = bool(
                state.get("interface_exists")
                and state.get("handshake_verified")
                and state.get("https_egress_verified")
            )
            return {
                "healthy": healthy,
                "handshake_verified": bool(state.get("handshake_verified")),
                "data_transfer_verified": bool(state.get("data_transfer_verified")),
                "https_egress_verified": bool(state.get("https_egress_verified")),
                "latency_ms": state.get("egress_latency_ms"),
                "error": state.get("egress_error") or state.get("note"),
            }

        return {
            "healthy": False,
            "latency_ms": None,
            "error": f"Unsupported protocol '{proto}' for live active health check",
        }

    def _try_recover_active_tunnel(self, transport: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Attempts bounded in-place recovery of an active SSH tunnel before failing over."""
        proto = str(transport.get("protocol", "")).lower()
        if proto != "ssh_socks5":
            return None

        sid = str(transport.get("server_id") or transport.get("host") or "")
        tunnel = self.transport_manager.get_ssh_tunnel(sid)
        if tunnel is None:
            return None

        reconn_res = tunnel.reconnect(reconnector=self.reconnector)
        if not reconn_res.get("connected"):
            return None

        post_health = self._active_health_checker(transport)
        if post_health.get("healthy"):
            return post_health
        return None

    def _gather_general_candidates(
        self,
        effective_cost_profile: str,
        exclude_signature: Optional[tuple[Optional[str], Optional[str]]] = None,
    ) -> List[Dict[str, Any]]:
        """Collects ONLY general application & IP tunnel candidates without running DNS probes."""
        if self._candidate_provider is not None:
            raw = self._candidate_provider()
        else:
            self.transport_manager.allow_metered_probes = self.cost_manager.allow_metered
            # Skip all DNS plane probes during transport selection and failover
            planes_report = self.transport_manager.evaluate_planes(include_dns_plane=False)
            if planes_report.get("status") == "ABORTED_METERED_GUARD":
                return []
            app_list = planes_report.get("planes", {}).get("application_transport", [])
            ip_list = planes_report.get("planes", {}).get("ip_tunnel", [])
            raw = list(app_list) + list(ip_list)
            # Record lightweight probe overhead in CostManager
            self.cost_manager.record_consumption(len(raw) * 768)

        enriched: List[Dict[str, Any]] = []
        for item in raw:
            sig = (item.get("protocol"), item.get("server_id") or item.get("tunnel_id"))
            if exclude_signature is not None and sig == exclude_signature:
                continue
            cand = dict(item)
            cand.setdefault("cost_profile", effective_cost_profile)
            # Compute packet_loss_pct from stability_ratio if not explicitly set
            if "packet_loss_pct" not in cand:
                stab = float(cand.get("stability_ratio", 0.0))
                cand["packet_loss_pct"] = round((1.0 - max(0.0, min(1.0, stab))) * 100.0, 2)
            enriched.append(cand)
        return enriched

    def _select_and_activate(
        self,
        effective_cost_profile: str,
        primary_ifname: Optional[str],
        reason: str,
        exclude_signature: Optional[tuple[Optional[str], Optional[str]]] = None,
    ) -> Dict[str, Any]:
        budget = self.cost_manager.check_budget_for_transfer(1536)
        if not budget["allowed"]:
            return {
                "connected": False,
                "aborted_budget": True,
                "error": budget["reason"],
            }

        candidates = self._gather_general_candidates(
            effective_cost_profile=effective_cost_profile,
            exclude_signature=exclude_signature,
        )
        ranking = self.auto_selector.rank_transports(candidates)
        chosen = ranking["selected_transport"]

        if chosen is None:
            return {
                "connected": False,
                "aborted_budget": False,
                "ranked_transports": ranking["ranked_transports"],
                "error": "No verified general transport candidates available",
            }

        self._active_transport_record = chosen
        change_ev = self.session.activate_transport(
            chosen,
            interface_name=primary_ifname,
            reason=reason,
        )
        self._log_event(change_ev)
        return {
            "connected": True,
            "selected_transport": chosen,
            "ranked_transports": ranking["ranked_transports"],
            "transition_event": change_ev,
            "error": None,
        }

    def connect_or_failover(
        self,
        reason: str = "initial_connect",
        exclude_failed_active: bool = False,
    ) -> Dict[str, Any]:
        """Connects or fails over to an alternative verified transport using bounded backoff."""
        net_scan = self.network_monitor.scan_interfaces()
        if not net_scan["online"]:
            self._active_transport_record = None
            self.session.mark_disconnected("NO_NETWORK", "No active network interfaces detected.")
            return {
                "status": "NO_NETWORK",
                "connected": False,
                "session": self.session.snapshot(),
                "network": net_scan,
            }

        gate = net_scan["cost_gate"]
        if not gate["allowed"]:
            self._active_transport_record = None
            self.session.mark_blocked_by_cost(gate["reason"], cost_profile=gate["effective_profile"])
            return {
                "status": "BLOCKED_COST_POLICY",
                "connected": False,
                "session": self.session.snapshot(),
                "network": net_scan,
            }

        primary_iface = net_scan["active_interfaces"][0]["name"]
        effective_prof = gate["effective_profile"]
        excluded_sig: Optional[tuple[Optional[str], Optional[str]]] = None
        if exclude_failed_active and self._active_transport_record is not None:
            excluded_sig = (
                self._active_transport_record.get("protocol"),
                self._active_transport_record.get("server_id")
                or self._active_transport_record.get("tunnel_id"),
            )

        # First immediate failover try excluding the failed active transport (zero artificial delay)
        if excluded_sig is not None:
            immediate = self._select_and_activate(
                effective_cost_profile=effective_prof,
                primary_ifname=primary_iface,
                reason=reason,
                exclude_signature=excluded_sig,
            )
            if immediate["connected"]:
                return {
                    "status": "FAILOVER_RECOVERED",
                    "connected": True,
                    "attempts_used": 1,
                    "selected_transport": immediate["selected_transport"],
                    "session": self.session.snapshot(),
                    "network": net_scan,
                }

        # Bounded retry across all candidates via ExponentialBackoffReconnector
        retry_outcome = self.reconnector.execute_with_retry(
            connect_fn=lambda: self._select_and_activate(
                effective_cost_profile=effective_prof,
                primary_ifname=primary_iface,
                reason=reason,
                exclude_signature=None,
            ),
            is_success_fn=lambda r: bool(r.get("connected")),
            should_abort_fn=lambda r: bool(r.get("aborted_budget")),
        )

        if retry_outcome["connected"]:
            return {
                "status": "CONNECTED",
                "connected": True,
                "attempts_used": retry_outcome["attempts_used"],
                "selected_transport": retry_outcome["final_result"]["selected_transport"],
                "session": self.session.snapshot(),
                "network": net_scan,
            }

        err_detail = (
            retry_outcome.get("final_result", {}).get("error")
            or "All transport candidates exhausted"
        )
        err_code = (
            "DATA_BUDGET_EXCEEDED"
            if retry_outcome.get("aborted_non_retryable")
            else "ALL_TRANSPORTS_FAILED"
        )
        self._active_transport_record = None
        self.session.mark_disconnected(err_code, err_detail)
        return {
            "status": err_code,
            "connected": False,
            "circuit_breaker_tripped": retry_outcome.get("circuit_breaker_tripped", False),
            "attempts_used": retry_outcome["attempts_used"],
            "session": self.session.snapshot(),
            "network": net_scan,
        }

    def supervise_step(self) -> Dict[str, Any]:
        """Executes one autonomous supervision cycle without disrupting healthy connections."""
        net_scan = self.network_monitor.scan_interfaces()
        if not net_scan["online"]:
            self._active_transport_record = None
            self.session.mark_disconnected("NO_NETWORK", "All network interfaces went offline.")
            return {
                "action": "DISCONNECTED_NO_NETWORK",
                "connected": False,
                "session": self.session.snapshot(),
                "network_events": net_scan["events"],
            }

        gate = net_scan["cost_gate"]
        if not gate["allowed"]:
            self._active_transport_record = None
            self.session.mark_blocked_by_cost(gate["reason"], cost_profile=gate["effective_profile"])
            return {
                "action": "BLOCKED_BY_COST_POLICY",
                "connected": False,
                "session": self.session.snapshot(),
                "network_events": net_scan["events"],
            }

        active_ifnames = {i["name"] for i in net_scan["active_interfaces"]}

        # If already connected on an interface that is still online, run live health check
        if (
            self.session.state == SessionState.CONNECTED
            and self._active_transport_record is not None
            and (self.session.active_interface in active_ifnames or self.session.active_interface is None)
        ):
            health = self._active_health_checker(self._active_transport_record)
            if health.get("healthy"):
                if health.get("latency_ms") is not None:
                    self.session.latency_ms = float(health["latency_ms"])
                self.session.cost_profile = gate["effective_profile"]
                return {
                    "action": "KEPT_HEALTHY_TRANSPORT",
                    "connected": True,
                    "session": self.session.snapshot(),
                    "network_events": net_scan["events"],
                }

            # Attempt in-place tunnel recovery (e.g., SSH reconnect) before switching transports
            recovered = self._try_recover_active_tunnel(self._active_transport_record)
            if recovered is not None:
                if recovered.get("latency_ms") is not None:
                    self.session.latency_ms = float(recovered["latency_ms"])
                self.session.cost_profile = gate["effective_profile"]
                self._log_event({
                    "event": "TUNNEL_SESSION_RECOVERED",
                    "protocol": self.session.active_protocol,
                    "server": self.session.active_server_id,
                })
                return {
                    "action": "RECOVERED_ACTIVE_TUNNEL",
                    "connected": True,
                    "session": self.session.snapshot(),
                    "network_events": net_scan["events"],
                }

            # Active transport degraded/dropped -> seamless failover!
            fail_reason = (
                f"Active {self.session.active_protocol} failed live health check "
                f"({health.get('error') or 'unreachable'}); failing over"
            )
            self.session.state = SessionState.FAILOVER_SWITCHING
            outcome = self.connect_or_failover(reason=fail_reason, exclude_failed_active=True)
            return {
                "action": "AUTOMATIC_FAILOVER" if outcome["connected"] else "FAILOVER_EXHAUSTED",
                "connected": outcome["connected"],
                "session": outcome["session"],
                "network_events": net_scan["events"],
            }

        # Interface changed or session was not connected -> establish best verified transport
        reason = (
            f"Interface roam ({self.session.active_interface} -> {net_scan['active_interfaces'][0]['name']})"
            if self.session.active_interface and self.session.active_interface not in active_ifnames
            else "autonomous_connect"
        )
        outcome = self.connect_or_failover(reason=reason, exclude_failed_active=False)
        return {
            "action": "ESTABLISHED_CONNECTION" if outcome["connected"] else outcome["status"],
            "connected": outcome["connected"],
            "session": outcome["session"],
            "network_events": net_scan["events"],
        }


def main() -> None:
    controller = FailoverController()
    result = controller.supervise_step()
    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()
