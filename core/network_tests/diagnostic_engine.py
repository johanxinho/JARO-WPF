"""JARO WPF - Granular Connectivity Diagnostic Engine & Capability Matrix (Phase 4).

Produces:
1. An independent capability_matrix differentiating:
   - Physical link & active medium (Wi-Fi, Ethernet, Cellular)
   - Cost policy gate (FREE, UNKNOWN, METERED, blocked)
   - DNS resolution (UDP, TCP, DoT, DoQ) strictly separated from general web access
   - DNS functional without web access (DNS_ONLY_NO_WEB)
   - General HTTPS functional (verified against non-DNS general web hosts)
   - HTTP/3 functional (verified over QUIC RFC 9114 + general web egress)
   - Local SOCKS5 functional vs Remote SSH tunnel functional vs Verified HTTPS egress via SSH
   - WireGuard handshake verified vs WireGuard data transfer verified vs Verified HTTPS egress via WireGuard
2. A deterministic overall primary_state and human-readable Spanish/English summary.
3. Full Section C traceability records for every executed or skipped diagnostic check.

Invariant:
- Never assumes functional DNS implies general internet access.
- Never marks an SSH or WireGuard tunnel functional merely because its process or OS interface is active.
"""
from datetime import datetime, timezone
from enum import Enum
import time
from typing import Any, Callable, Dict, List, Optional

from core.connection.cost_manager import CostManager
from core.connection.network_monitor import NetworkMonitor
from core.network_tests.connectivity_prober import (
    probe_dot_dns,
    probe_https_egress,
    probe_tcp_dns,
    probe_udp_dns,
)
from core.protocols.ssh_engine import (
    SshSocksTunnel,
    probe_https_over_socks5,
    socks5_greeting_probe,
)
from core.protocols.vpn_tunnel_engine import WireGuardTunnelEngine


class DiagnosticPrimaryState(str, Enum):
    """Authoritative overall network state produced by DiagnosticEngine."""
    NO_PHYSICAL_CONNECTION = "NO_PHYSICAL_CONNECTION"
    COST_POLICY_BLOCKED = "COST_POLICY_BLOCKED"
    WIFI_NO_INTERNET = "WIFI_NO_INTERNET"
    ETHERNET_NO_INTERNET = "ETHERNET_NO_INTERNET"
    CELLULAR_NO_INTERNET = "CELLULAR_NO_INTERNET"
    CAPTIVE_PORTAL_INTERCEPTED = "CAPTIVE_PORTAL_INTERCEPTED"
    DNS_ONLY_NO_WEB = "DNS_ONLY_NO_WEB"
    HTTPS_FUNCTIONAL = "HTTPS_FUNCTIONAL"
    HTTP3_FUNCTIONAL = "HTTP3_FUNCTIONAL"
    SSH_TUNNEL_FUNCTIONAL = "SSH_TUNNEL_FUNCTIONAL"
    WIREGUARD_TUNNEL_FUNCTIONAL = "WIREGUARD_TUNNEL_FUNCTIONAL"


STATE_DESCRIPTIONS_ES: Dict[DiagnosticPrimaryState, str] = {
    DiagnosticPrimaryState.NO_PHYSICAL_CONNECTION: "Sin conexión física activa en ninguna interfaz de red.",
    DiagnosticPrimaryState.COST_POLICY_BLOCKED: "Conexión limitada o bloqueada preventivamente por políticas de coste (CostManager).",
    DiagnosticPrimaryState.WIFI_NO_INTERNET: "Conectado a red Wi-Fi local sin salida verificada a internet ni resolución DNS.",
    DiagnosticPrimaryState.ETHERNET_NO_INTERNET: "Conectado por cable Ethernet local sin salida verificada a internet ni resolución DNS.",
    DiagnosticPrimaryState.CELLULAR_NO_INTERNET: "Interfaz móvil activa sin salida verificada a internet.",
    DiagnosticPrimaryState.CAPTIVE_PORTAL_INTERCEPTED: "Tráfico web interceptado o redirigido por un posible portal cautivo.",
    DiagnosticPrimaryState.DNS_ONLY_NO_WEB: "Resolución DNS funcional (o solo IPs de DNS accesibles), pero sin acceso web general.",
    DiagnosticPrimaryState.HTTPS_FUNCTIONAL: "Acceso general a internet verificado mediante HTTPS (TLS X.509 + contenido esperado).",
    DiagnosticPrimaryState.HTTP3_FUNCTIONAL: "Acceso a internet verificado mediante HTTP/3 sobre QUIC (además de salida web general).",
    DiagnosticPrimaryState.SSH_TUNNEL_FUNCTIONAL: "Túnel SSH remoto con proxy SOCKS5 local y salida HTTPS extremo a extremo verificada.",
    DiagnosticPrimaryState.WIREGUARD_TUNNEL_FUNCTIONAL: "Túnel IP WireGuard con handshake criptográfico reciente y salida HTTPS verificada.",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_trace_record(
    *,
    execution_scope: str,
    server: str,
    protocol: str,
    duration_ms: float,
    bytes_estimated: int,
    verified_real: bool,
    result: str,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "execution_scope": execution_scope,
        "server": server,
        "protocol": protocol,
        "timestamp_utc": _utc_now_iso(),
        "duration_ms": round(float(duration_ms), 2),
        "bytes_estimated": max(0, int(bytes_estimated)),
        "verified_real": bool(verified_real) if execution_scope in ("LOCAL_LOOPBACK", "EXTERNAL_REAL") else False,
        "result": result,
        "resultado": result,
        "reason": reason,
        "motivo": reason,
    }


class DiagnosticEngine:
    """Evaluates physical media, cost gates, DNS, HTTPS, HTTP/3, SSH/SOCKS5, and WireGuard independently."""

    def __init__(
        self,
        cost_manager: Optional[CostManager] = None,
        network_monitor: Optional[NetworkMonitor] = None,
        ssh_tunnels: Optional[List[SshSocksTunnel]] = None,
        local_socks5_endpoints: Optional[List[tuple[str, int]]] = None,
        wireguard_engines: Optional[List[WireGuardTunnelEngine]] = None,
        dns_probe_fn: Optional[Callable[[], Dict[str, Any]]] = None,
        web_https_probe_fn: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        http3_probe_fn: Optional[Callable[[], Dict[str, Any]]] = None,
        include_encrypted_dns: bool = False,
        execution_scope: str = "EXTERNAL_REAL",
    ) -> None:
        self.cost_manager = cost_manager or CostManager()
        self.network_monitor = network_monitor or NetworkMonitor(cost_manager=self.cost_manager)
        self.ssh_tunnels: List[SshSocksTunnel] = list(ssh_tunnels or [])
        self.local_socks5_endpoints: List[tuple[str, int]] = list(local_socks5_endpoints or [])
        self.wireguard_engines: List[WireGuardTunnelEngine] = list(wireguard_engines or [])
        self._dns_probe_fn = dns_probe_fn
        self._web_https_probe_fn = web_https_probe_fn
        self._http3_probe_fn = http3_probe_fn
        self.include_encrypted_dns = include_encrypted_dns
        self.execution_scope = execution_scope

    def _default_dns_probes(self) -> Dict[str, Any]:
        udp_res = probe_udp_dns("1.1.1.1", 53, domain="example.com", timeout=2.5)
        tcp_res = probe_tcp_dns("1.1.1.1", 53, domain="example.com", timeout=2.5)
        dot_res: Optional[Dict[str, Any]] = None
        doq_res: Optional[Dict[str, Any]] = None
        if self.include_encrypted_dns:
            dot_res = probe_dot_dns("1.1.1.1", 853, sni="one.one.one.one", timeout=3.0)
            from core.protocols.doq_engine import probe_doq
            doq_res = probe_doq("94.140.14.14", 853, sni="dns.adguard-dns.com", timeout=3.5)
        return {
            "udp_dns": udp_res,
            "tcp_dns": tcp_res,
            "dot": dot_res,
            "doq": doq_res,
        }

    @staticmethod
    def _default_web_https_probes() -> List[Dict[str, Any]]:
        endpoints = [
            {
                "url": "https://example.com/",
                "expected_status": 200,
                "expected_substring": "Example Domain",
                "is_dns_provider": False,
            },
            {
                "url": "https://connectivitycheck.gstatic.com/generate_204",
                "expected_status": 204,
                "expected_substring": "",
                "is_dns_provider": False,
            },
            {
                "url": "https://one.one.one.one/cdn-cgi/trace",
                "connect_host": "1.1.1.1",
                "sni_hostname": "one.one.one.one",
                "expected_status": 200,
                "expected_substring": "fl=",
                "is_dns_provider": True,
            },
        ]
        results: List[Dict[str, Any]] = []
        non_dns_ok = False
        for ep in endpoints:
            if ep["is_dns_provider"] and non_dns_ok:
                continue
            res = probe_https_egress(
                url=ep["url"],
                expected_status=ep["expected_status"],
                expected_substring=ep["expected_substring"],
                connect_host=ep.get("connect_host"),
                sni_hostname=ep.get("sni_hostname"),
                timeout=3.5,
            )
            res["is_dns_provider"] = ep["is_dns_provider"]
            results.append(res)
            if not ep["is_dns_provider"] and res["real_internet"]:
                non_dns_ok = True
        return results

    @staticmethod
    def _default_http3_probe() -> Dict[str, Any]:
        from core.protocols.quic_engine import request_http3
        return request_http3(
            url="https://one.one.one.one/cdn-cgi/trace",
            connect_host="1.1.1.1",
            connect_port=443,
            sni_hostname="one.one.one.one",
            expected_status=200,
            expected_substring="fl=",
            timeout=3.5,
        )

    def run_diagnostics(
        self,
        require_explicit_cost_authorization: bool = False,
        authorize_unknown_cost: Optional[bool] = None,
        authorize_metered_cost: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Executes full layered diagnostics and builds the independent capability matrix."""
        trace_records: List[Dict[str, Any]] = []
        scope = self.execution_scope
        is_real_scope = scope in ("LOCAL_LOOPBACK", "EXTERNAL_REAL")

        t0 = time.perf_counter()
        net_scan = self.network_monitor.scan_interfaces()
        active_ifaces = net_scan["active_interfaces"]

        wifi_connected = any(i["medium"] == "wifi" for i in active_ifaces)
        ethernet_connected = any(i["medium"] == "ethernet" for i in active_ifaces)
        cellular_connected = any(i["medium"] == "cellular" for i in active_ifaces)
        physical_connection = len(active_ifaces) > 0

        capability_matrix: Dict[str, bool] = {
            "physical_connection": physical_connection,
            "wifi_connected": wifi_connected,
            "ethernet_connected": ethernet_connected,
            "cellular_connected": cellular_connected,
            "cost_policy_blocked": False,
            "dns_udp_functional": False,
            "dns_tcp_functional": False,
            "dns_dot_functional": False,
            "dns_doq_functional": False,
            "dns_any_functional": False,
            "dns_functional_without_web": False,
            "https_general_functional": False,
            "http3_functional": False,
            "local_socks5_functional": False,
            "local_ssh_tunnel_functional": False,
            "remote_ssh_tunnel_functional": False,
            "ssh_https_egress_verified": False,
            "wireguard_handshake_verified": False,
            "wireguard_data_transfer_verified": False,
            "wireguard_https_egress_verified": False,
            "general_internet_functional": False,
        }

        if not physical_connection:
            trace_records.append(
                _make_trace_record(
                    execution_scope=scope,
                    server="local-nic",
                    protocol="link_layer",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    bytes_estimated=0,
                    verified_real=is_real_scope,
                    result="FAIL",
                    reason="No active non-loopback network interfaces detected",
                )
            )
            return self._finalize_report(
                primary_state=DiagnosticPrimaryState.NO_PHYSICAL_CONNECTION,
                capability_matrix=capability_matrix,
                functional_transports=[],
                net_scan=net_scan,
                trace_records=trace_records,
                details={
                    "reason": "No physical network interfaces online",
                    "remote_ssh_status": "REMOTE_SERVER_REQUIRED" if not self.ssh_tunnels else "UNVERIFIED",
                    "remote_wireguard_status": "REMOTE_SERVER_REQUIRED" if not self.wireguard_engines else "UNVERIFIED",
                },
            )

        # Evaluate CostManager gate
        if require_explicit_cost_authorization:
            gate = self.cost_manager.evaluate_external_lab_gate(
                active_ifaces,
                authorize_unknown=authorize_unknown_cost,
                authorize_metered=authorize_metered_cost,
            )
        else:
            gate = net_scan["cost_gate"]

        budget_gate = self.cost_manager.check_budget_for_transfer(4096)
        if not gate["allowed"] or not budget_gate["allowed"]:
            capability_matrix["cost_policy_blocked"] = True
            block_reason = gate.get("reason") or budget_gate.get("reason")
            trace_records.append(
                _make_trace_record(
                    execution_scope=scope,
                    server="cost-manager",
                    protocol="policy_gate",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=block_reason,
                )
            )
            return self._finalize_report(
                primary_state=DiagnosticPrimaryState.COST_POLICY_BLOCKED,
                capability_matrix=capability_matrix,
                functional_transports=[],
                net_scan=net_scan,
                trace_records=trace_records,
                details={
                    "cost_gate": gate,
                    "budget_gate": budget_gate,
                    "reason": block_reason,
                    "remote_ssh_status": "REMOTE_SERVER_REQUIRED" if not self.ssh_tunnels else "BLOCKED_COST_POLICY",
                    "remote_wireguard_status": "REMOTE_SERVER_REQUIRED" if not self.wireguard_engines else "BLOCKED_COST_POLICY",
                },
            )

        # 1. DNS Probes (strictly separated from web access)
        t_dns = time.perf_counter()
        dns_bundle = (
            self._dns_probe_fn()
            if self._dns_probe_fn is not None
            else self._default_dns_probes()
        )
        dns_dur = (time.perf_counter() - t_dns) * 1000

        udp_dns = dns_bundle.get("udp_dns") or {}
        tcp_dns = dns_bundle.get("tcp_dns") or {}
        dot_dns = dns_bundle.get("dot")
        doq_dns = dns_bundle.get("doq")

        capability_matrix["dns_udp_functional"] = bool(udp_dns.get("protocol_verified"))
        capability_matrix["dns_tcp_functional"] = bool(tcp_dns.get("protocol_verified"))
        capability_matrix["dns_dot_functional"] = bool(dot_dns and dot_dns.get("protocol_verified"))
        capability_matrix["dns_doq_functional"] = bool(doq_dns and doq_dns.get("protocol_verified"))
        capability_matrix["dns_any_functional"] = any([
            capability_matrix["dns_udp_functional"],
            capability_matrix["dns_tcp_functional"],
            capability_matrix["dns_dot_functional"],
            capability_matrix["dns_doq_functional"],
        ])

        dns_bytes = 256 + (1536 if dot_dns else 0) + (1536 if doq_dns else 0)
        self.cost_manager.record_consumption(dns_bytes)
        trace_records.append(
            _make_trace_record(
                execution_scope=scope,
                server=str(udp_dns.get("host") or "1.1.1.1"),
                protocol="dns_suite",
                duration_ms=dns_dur,
                bytes_estimated=dns_bytes,
                verified_real=is_real_scope and capability_matrix["dns_any_functional"],
                result="PASS" if capability_matrix["dns_any_functional"] else "FAIL",
                reason=None if capability_matrix["dns_any_functional"] else (udp_dns.get("error") or tcp_dns.get("error")),
            )
        )

        # 2. General HTTPS Web Egress Probes (requires non-DNS web host for https_general_functional)
        t_https = time.perf_counter()
        https_results = (
            self._web_https_probe_fn()
            if self._web_https_probe_fn is not None
            else self._default_web_https_probes()
        )
        https_dur = (time.perf_counter() - t_https) * 1000

        non_dns_checks = [r for r in https_results if not r.get("is_dns_provider", False)]
        dns_provider_checks = [r for r in https_results if r.get("is_dns_provider", False)]

        captive_portal_detected = any(bool(r.get("captive_portal_suspected")) for r in https_results)
        non_dns_web_ok = any(bool(r.get("real_internet")) for r in non_dns_checks) and not captive_portal_detected
        dns_provider_https_only = (
            not non_dns_web_ok
            and any(bool(r.get("real_internet")) for r in dns_provider_checks)
        )

        capability_matrix["https_general_functional"] = non_dns_web_ok
        https_bytes = sum(int(r.get("bytes_estimated", 1536)) for r in https_results)
        self.cost_manager.record_consumption(https_bytes)
        trace_records.append(
            _make_trace_record(
                execution_scope=scope,
                server="example.com/gstatic.com",
                protocol="https",
                duration_ms=https_dur,
                bytes_estimated=https_bytes,
                verified_real=is_real_scope and non_dns_web_ok,
                result="PASS" if non_dns_web_ok else "FAIL",
                reason=(
                    None
                    if non_dns_web_ok
                    else (
                        "Captive portal interception detected"
                        if captive_portal_detected
                        else "Non-DNS general web HTTPS hosts unreachable"
                    )
                ),
            )
        )

        # 3. HTTP/3 over QUIC Probe
        t_h3 = time.perf_counter()
        h3_res = (
            self._http3_probe_fn()
            if self._http3_probe_fn is not None
            else self._default_http3_probe()
        )
        h3_dur = (time.perf_counter() - t_h3) * 1000
        h3_proto_ok = bool(h3_res.get("http3_verified"))
        h3_target_is_general_web = not bool(h3_res.get("is_dns_provider", True))
        # HTTP/3 general internet requires both verified H3 response AND verified non-DNS general web reachability
        http3_functional = h3_proto_ok and (non_dns_web_ok or h3_target_is_general_web)
        capability_matrix["http3_functional"] = http3_functional
        h3_bytes = int(h3_res.get("response_bytes", 0)) + 1200 if h3_proto_ok else 600
        self.cost_manager.record_consumption(h3_bytes)
        trace_records.append(
            _make_trace_record(
                execution_scope=scope,
                server=str(h3_res.get("sni") or h3_res.get("host") or "one.one.one.one"),
                protocol="http3",
                duration_ms=h3_dur,
                bytes_estimated=h3_bytes,
                verified_real=is_real_scope and http3_functional,
                result="PASS" if http3_functional else "FAIL",
                reason=(
                    None
                    if http3_functional
                    else (
                        "HTTP/3 responded on DNS edge only; general non-DNS web unreachable"
                        if (h3_proto_ok and not non_dns_web_ok)
                        else str(h3_res.get("error") or "HTTP/3 probe failed")
                    )
                ),
            )
        )

        # 4. Standalone Local SOCKS5 Listeners & SSH Dynamic Tunnels (local SOCKS5 vs local SSH vs remote SSH!)
        for socks_host, socks_port in self.local_socks5_endpoints:
            t_s = time.perf_counter()
            greet = socks5_greeting_probe(socks_host, socks_port, timeout=1.5)
            s_dur = (time.perf_counter() - t_s) * 1000
            if greet["socks5_ready"]:
                capability_matrix["local_socks5_functional"] = True
            s_scope = "LOCAL_LOOPBACK" if socks_host in ("127.0.0.1", "::1", "localhost") and is_real_scope else scope
            trace_records.append(
                _make_trace_record(
                    execution_scope=s_scope,
                    server=f"{socks_host}:{socks_port}",
                    protocol="socks5_local",
                    duration_ms=s_dur,
                    bytes_estimated=64,
                    verified_real=(s_scope in ("LOCAL_LOOPBACK", "EXTERNAL_REAL")) and bool(greet["socks5_ready"]),
                    result="PASS" if greet["socks5_ready"] else "FAIL",
                    reason=greet.get("error"),
                )
            )

        has_remote_ssh_cfg = any(not t.config.is_loopback_target for t in self.ssh_tunnels)
        if not self.ssh_tunnels:
            trace_records.append(
                _make_trace_record(
                    execution_scope="SKIPPED_MISSING_PREREQUISITE",
                    server="unconfigured",
                    protocol="ssh_socks5",
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason="REMOTE_SERVER_REQUIRED: No authorized SSH tunnels configured",
                )
            )
        else:
            for tunnel in self.ssh_tunnels:
                t_ssh = time.perf_counter()
                val = tunnel.config.validate()
                if not val["valid"]:
                    trace_records.append(
                        _make_trace_record(
                            execution_scope="SKIPPED_MISSING_PREREQUISITE",
                            server=tunnel.config.host or "unconfigured",
                            protocol="ssh_socks5",
                            duration_ms=(time.perf_counter() - t_ssh) * 1000,
                            bytes_estimated=0,
                            verified_real=False,
                            result="SKIPPED",
                            reason=val["error"],
                        )
                    )
                    continue

                health = tunnel.check_health(verify_https_egress=True)
                ssh_dur = (time.perf_counter() - t_ssh) * 1000
                if health.get("local_socks5_functional"):
                    capability_matrix["local_socks5_functional"] = True
                if health.get("local_ssh_tunnel_functional"):
                    capability_matrix["local_ssh_tunnel_functional"] = True
                if health.get("remote_ssh_tunnel_functional"):
                    capability_matrix["remote_ssh_tunnel_functional"] = True
                if health.get("remote_ssh_tunnel_functional") and health.get("https_egress_verified"):
                    capability_matrix["ssh_https_egress_verified"] = True

                ssh_bytes = int(health.get("bytes_estimated", 0))
                self.cost_manager.record_consumption(ssh_bytes)
                full_ssh_ok = bool(
                    health.get("process_alive")
                    and health.get("remote_ssh_tunnel_functional")
                    and health.get("https_egress_verified")
                )
                trace_records.append(
                    _make_trace_record(
                        execution_scope="LOCAL_LOOPBACK" if tunnel.config.is_loopback_target and is_real_scope else scope,
                        server=tunnel.config.host,
                        protocol="ssh_socks5",
                        duration_ms=ssh_dur,
                        bytes_estimated=ssh_bytes,
                        verified_real=is_real_scope and (
                            bool(health.get("local_ssh_tunnel_functional") and health.get("https_egress_verified"))
                            if tunnel.config.is_loopback_target
                            else full_ssh_ok
                        ),
                        result=(
                            "PASS"
                            if (
                                bool(health.get("local_ssh_tunnel_functional") and health.get("https_egress_verified"))
                                if tunnel.config.is_loopback_target
                                else full_ssh_ok
                            )
                            else "FAIL"
                        ),
                        reason=(
                            None
                            if (
                                bool(health.get("local_ssh_tunnel_functional") and health.get("https_egress_verified"))
                                if tunnel.config.is_loopback_target
                                else full_ssh_ok
                            )
                            else str(health.get("error") or "SSH HTTPS egress not verified")
                        ),
                    )
                )

        # 5. WireGuard IP Tunnels (3 distinct layers: handshake, data_transfer, https_egress)
        if not self.wireguard_engines:
            trace_records.append(
                _make_trace_record(
                    execution_scope="SKIPPED_MISSING_PREREQUISITE",
                    server="unconfigured",
                    protocol="wireguard",
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason="REMOTE_SERVER_REQUIRED: No authorized WireGuard tunnels configured",
                )
            )
        else:
            for wg in self.wireguard_engines:
                t_wg = time.perf_counter()
                if not wg.authorized:
                    trace_records.append(
                        _make_trace_record(
                            execution_scope="SKIPPED_MISSING_PREREQUISITE",
                            server=wg.interface_name,
                            protocol="wireguard",
                            duration_ms=(time.perf_counter() - t_wg) * 1000,
                            bytes_estimated=0,
                            verified_real=False,
                            result="SKIPPED",
                            reason="WireGuard profile is not marked as authorized",
                        )
                    )
                    continue

                wg_state = wg.inspect_state(verify_internet_egress=True)
                wg_dur = (time.perf_counter() - t_wg) * 1000
                if wg_state.get("handshake_verified"):
                    capability_matrix["wireguard_handshake_verified"] = True
                if wg_state.get("data_transfer_verified"):
                    capability_matrix["wireguard_data_transfer_verified"] = True
                if wg_state.get("handshake_verified") and wg_state.get("https_egress_verified"):
                    capability_matrix["wireguard_https_egress_verified"] = True

                wg_bytes = int(wg_state.get("bytes_estimated", 0))
                self.cost_manager.record_consumption(wg_bytes)
                full_wg_ok = bool(
                    wg_state.get("interface_exists")
                    and wg_state.get("handshake_verified")
                    and wg_state.get("https_egress_verified")
                )
                wg_scope = (
                    "SKIPPED_MISSING_PREREQUISITE"
                    if not wg_state["tooling"]["wg_binary"] and not wg_state["interface_exists"]
                    else scope
                )
                trace_records.append(
                    _make_trace_record(
                        execution_scope=wg_scope,
                        server=wg.interface_name,
                        protocol="wireguard",
                        duration_ms=wg_dur,
                        bytes_estimated=wg_bytes,
                        verified_real=(wg_scope in ("LOCAL_LOOPBACK", "EXTERNAL_REAL")) and full_wg_ok,
                        result=(
                            "SKIPPED"
                            if wg_scope == "SKIPPED_MISSING_PREREQUISITE"
                            else ("PASS" if full_wg_ok else "FAIL")
                        ),
                        reason=None if full_wg_ok else str(wg_state.get("note") or "WireGuard tunnel not verified"),
                    )
                )

        # Finalize derived capability flags & primary_state
        any_verified_web_egress = any([
            capability_matrix["https_general_functional"],
            capability_matrix["http3_functional"],
            capability_matrix["ssh_https_egress_verified"],
            capability_matrix["wireguard_https_egress_verified"],
        ])
        capability_matrix["general_internet_functional"] = any_verified_web_egress
        capability_matrix["dns_functional_without_web"] = bool(
            (capability_matrix["dns_any_functional"] or dns_provider_https_only)
            and not any_verified_web_egress
        )

        functional_transports: List[str] = []
        if capability_matrix["wireguard_https_egress_verified"]:
            functional_transports.append(DiagnosticPrimaryState.WIREGUARD_TUNNEL_FUNCTIONAL.value)
        if capability_matrix["ssh_https_egress_verified"]:
            functional_transports.append(DiagnosticPrimaryState.SSH_TUNNEL_FUNCTIONAL.value)
        if capability_matrix["http3_functional"]:
            functional_transports.append(DiagnosticPrimaryState.HTTP3_FUNCTIONAL.value)
        if capability_matrix["https_general_functional"]:
            functional_transports.append(DiagnosticPrimaryState.HTTPS_FUNCTIONAL.value)

        if capability_matrix["wireguard_https_egress_verified"]:
            primary = DiagnosticPrimaryState.WIREGUARD_TUNNEL_FUNCTIONAL
        elif capability_matrix["ssh_https_egress_verified"]:
            primary = DiagnosticPrimaryState.SSH_TUNNEL_FUNCTIONAL
        elif capability_matrix["http3_functional"]:
            primary = DiagnosticPrimaryState.HTTP3_FUNCTIONAL
        elif capability_matrix["https_general_functional"]:
            primary = DiagnosticPrimaryState.HTTPS_FUNCTIONAL
        elif captive_portal_detected:
            primary = DiagnosticPrimaryState.CAPTIVE_PORTAL_INTERCEPTED
        elif capability_matrix["dns_functional_without_web"]:
            primary = DiagnosticPrimaryState.DNS_ONLY_NO_WEB
        elif wifi_connected and not ethernet_connected:
            primary = DiagnosticPrimaryState.WIFI_NO_INTERNET
        elif ethernet_connected:
            primary = DiagnosticPrimaryState.ETHERNET_NO_INTERNET
        elif cellular_connected:
            primary = DiagnosticPrimaryState.CELLULAR_NO_INTERNET
        else:
            primary = DiagnosticPrimaryState.WIFI_NO_INTERNET if wifi_connected else DiagnosticPrimaryState.NO_PHYSICAL_CONNECTION

        remote_ssh_status = (
            "ONLINE_VERIFIED"
            if capability_matrix["ssh_https_egress_verified"]
            else ("REMOTE_SERVER_REQUIRED" if not has_remote_ssh_cfg else "OFFLINE")
        )
        remote_wg_status = (
            "ONLINE_VERIFIED"
            if capability_matrix["wireguard_https_egress_verified"]
            else ("REMOTE_SERVER_REQUIRED" if not self.wireguard_engines else "OFFLINE")
        )

        return self._finalize_report(
            primary_state=primary,
            capability_matrix=capability_matrix,
            functional_transports=functional_transports,
            net_scan=net_scan,
            trace_records=trace_records,
            details={
                "dns_provider_https_only": dns_provider_https_only,
                "captive_portal_detected": captive_portal_detected,
                "http3_raw_verified": h3_proto_ok,
                "remote_ssh_status": remote_ssh_status,
                "remote_wireguard_status": remote_wg_status,
            },
        )

    def _finalize_report(
        self,
        *,
        primary_state: DiagnosticPrimaryState,
        capability_matrix: Dict[str, bool],
        functional_transports: List[str],
        net_scan: Dict[str, Any],
        trace_records: List[Dict[str, Any]],
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "module": "JARO WPF DIAGNOSTIC ENGINE",
            "timestamp_utc": _utc_now_iso(),
            "execution_scope": self.execution_scope,
            "primary_state": primary_state.value,
            "description_es": STATE_DESCRIPTIONS_ES[primary_state],
            "functional_transports": functional_transports,
            "capability_matrix": capability_matrix,
            "active_interfaces": net_scan["active_interfaces"],
            "effective_cost_profile": net_scan["cost_gate"].get("effective_profile"),
            "bytes_estimated_total": sum(r["bytes_estimated"] for r in trace_records),
            "trace_records": trace_records,
            "details": details,
        }
