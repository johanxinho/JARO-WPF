"""Automated behavioral, diagnostic, lab, and recovery tests for JARO WPF Phase 4."""
import base64
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from core.connection.connection_session import SessionState
from core.connection.cost_manager import CostManager, CostProfile
from core.connection.failover_controller import FailoverController
from core.connection.multi_method_manager import classify_interface_medium
from core.connection.network_monitor import NetworkMonitor
from core.connection.reconnector import ExponentialBackoffReconnector
from core.connection.transport_manager import TransportManager
from core.network_tests.diagnostic_engine import (
    DiagnosticEngine,
    DiagnosticPrimaryState,
)
from core.network_tests.network_lab import (
    ExecutionScope,
    LabTestRecord,
    NetworkLab,
    _generate_lab_pki,
)
from core.protocols.ssh_engine import SshSocksTunnel, SshTunnelConfig
from core.protocols.vpn_tunnel_engine import (
    WireGuardTunnelEngine,
    parse_wg_dump_output,
)


def _wg_key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


class TestPhase4PriorityIntegrationFixes(unittest.TestCase):
    """Verifies Conditions A.1, A.2, A.3, and A.4."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a4_unified_cost_classification_never_assumes_wifi_or_ethernet_is_free(self) -> None:
        cm = CostManager(allow_metered=False, allow_unknown=True)

        wifi_meta = classify_interface_medium("wlp2s0", cost_manager=cm)
        eth_meta = classify_interface_medium("enp1s0", cost_manager=cm)
        usb_eth_meta = classify_interface_medium("enx8eec7bc7ba0f", cost_manager=cm)
        cell_meta = classify_interface_medium("wwan0", cost_manager=cm)

        self.assertEqual(wifi_meta["cost_profile"], "unknown")
        self.assertEqual(wifi_meta["base_cost_tier"], 1)
        self.assertEqual(eth_meta["cost_profile"], "unknown")
        self.assertEqual(eth_meta["base_cost_tier"], 1)
        self.assertEqual(usb_eth_meta["medium"], "ethernet")
        self.assertEqual(usb_eth_meta["cost_profile"], "unknown")
        self.assertEqual(usb_eth_meta["base_cost_tier"], 1)
        self.assertEqual(cell_meta["cost_profile"], "metered")
        self.assertEqual(cell_meta["base_cost_tier"], 2)

        # Only when explicitly configured as FREE by the user does cost_tier become 0
        cm.set_interface_profile("wlp2s0", CostProfile.FREE)
        wifi_free = classify_interface_medium("wlp2s0", cost_manager=cm)
        self.assertEqual(wifi_free["cost_profile"], "free")
        self.assertEqual(wifi_free["base_cost_tier"], 0)

    def test_a1_live_ssh_and_wireguard_health_checks_reject_stale_cached_booleans(self) -> None:
        """Proves _default_active_health_check checks live tunnel state, never cached 'available': True."""
        id_file = self.tmpdir / "id_ed25519"
        id_file.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n", encoding="utf-8")
        id_file.chmod(0o600)
        kh_file = self.tmpdir / "known_hosts"
        kh_file.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...\n", encoding="utf-8")

        cfg = SshTunnelConfig(
            host="127.0.0.1",
            username="jaro",
            identity_file=str(id_file),
            known_hosts_file=str(kh_file),
            local_socks_port=19999,
            authorized=True,
        )
        dead_ssh_tunnel = SshSocksTunnel(cfg)  # Not started -> process_alive is False!

        wg_eng = WireGuardTunnelEngine(interface_name="wg_nonexistent0", authorized=True)

        cm = CostManager(allow_metered=False, allow_unknown=True)
        tm = TransportManager(
            ssh_tunnels=[dead_ssh_tunnel],
            wireguard_engines=[wg_eng],
            cost_manager=cm,
        )
        ctrl = FailoverController(cost_manager=cm, transport_manager=tm, event_log_path=None)

        # Even though the cached transport record claims available=True & real_internet_verified=True,
        # live health check MUST return healthy=False!
        stale_ssh_record = {
            "server_id": "ssh-tunnel-1",
            "protocol": "ssh_socks5",
            "host": "127.0.0.1",
            "available": True,
            "real_internet_verified": True,
            "avg_latency_ms": 25.0,
        }
        ssh_health = ctrl._default_active_health_check(stale_ssh_record)
        self.assertFalse(ssh_health["healthy"])
        self.assertFalse(ssh_health["process_alive"])

        stale_wg_record = {
            "tunnel_id": "wireguard-wg_nonexistent0-1",
            "interface": "wg_nonexistent0",
            "protocol": "wireguard",
            "authorized": True,
            "available": True,
            "real_internet_verified": True,
            "avg_latency_ms": 20.0,
        }
        wg_health = ctrl._default_active_health_check(stale_wg_record)
        self.assertFalse(wg_health["healthy"])
        self.assertFalse(wg_health["https_egress_verified"])

    def test_a2_wireguard_uses_real_measured_https_egress_latency_and_separates_data_transfer(self) -> None:
        now = 1_700_001_000
        priv = _wg_key(3)
        pub = _wg_key(4)

        # 1. Handshake-only (92 B RX, 148 B TX): handshake_verified=True, data_transfer_verified=False
        hs_only_dump = (
            f"{priv}\t{pub}\t51820\toff\n"
            f"{pub}\t(none)\t198.51.100.1:51820\t10.88.0.0/24\t{now - 10}\t92\t148\toff\n"
        )
        parsed_hs_only = parse_wg_dump_output(hs_only_dump, now_epoch=now)
        self.assertTrue(parsed_hs_only["handshake_verified"])
        self.assertFalse(parsed_hs_only["data_transfer_verified"])

        # 2. Handshake + payload data transfer (>180 B RX & TX): both True
        data_dump = (
            f"{priv}\t{pub}\t51820\toff\n"
            f"{pub}\t(none)\t198.51.100.1:51820\t10.88.0.0/24\t{now - 10}\t12400\t6200\toff\n"
        )
        parsed_data = parse_wg_dump_output(data_dump, now_epoch=now)
        self.assertTrue(parsed_data["handshake_verified"])
        self.assertTrue(parsed_data["data_transfer_verified"])

        # 3. TransportManager._evaluate_wireguard_tunnels uses real measured egress latency (not synthetic 20.0)
        conf_path = self.tmpdir / "wg_auth.conf"
        conf_path.write_text(
            f"[Interface]\nPrivateKey = {priv}\nAddress = 10.88.0.2/32\n\n"
            f"[Peer]\nPublicKey = {pub}\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 10.88.0.0/24\n",
            encoding="utf-8",
        )
        conf_path.chmod(0o600)

        wg_eng = WireGuardTunnelEngine(interface_name="wg_test0", config_path=conf_path, authorized=True)
        cm = CostManager(allow_metered=False, allow_unknown=True)
        tm = TransportManager(wireguard_engines=[wg_eng], cost_manager=cm)

        with patch.object(
            wg_eng,
            "inspect_state",
            return_value={
                "tooling": {"cli_ready": True},
                "interface_exists": True,
                "handshake_verified": True,
                "data_transfer_verified": True,
                "https_egress_verified": True,
                "real_internet_verified": True,
                "egress_latency_ms": 47.35,
                "bytes_estimated": 2100,
                "tunnel_verified": True,
                "egress_error": None,
                "note": None,
            },
        ) as mock_inspect:
            wg_list = tm._evaluate_wireguard_tunnels(medium_cost=0, effective_profile="free")
            mock_inspect.assert_called_once_with(verify_internet_egress=True)
            self.assertEqual(len(wg_list), 1)
            self.assertTrue(wg_list[0]["available"])
            self.assertTrue(wg_list[0]["https_egress_verified"])
            self.assertEqual(wg_list[0]["avg_latency_ms"], 47.35)
            self.assertNotEqual(wg_list[0]["avg_latency_ms"], 20.0)

    def test_a3_failover_eliminates_redundant_dns_probes(self) -> None:
        cm = CostManager(allow_metered=False, allow_unknown=True)
        cm.set_interface_profile("wlp2s0", CostProfile.FREE)
        mon = NetworkMonitor(
            cost_manager=cm,
            interface_provider=lambda: [{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.242"]}],
            metered_hint_provider=lambda _: False,
        )
        tm = TransportManager(samples_per_check=1, cost_manager=cm)
        ctrl = FailoverController(cost_manager=cm, network_monitor=mon, transport_manager=tm, event_log_path=None)

        with patch(
            "core.connection.multi_method_manager.detect_active_media",
            return_value=[{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.242"], "medium": "wifi"}],
        ), patch(
            "core.network_tests.connectivity_prober.probe_udp_dns",
            side_effect=AssertionError("Redundant UDP DNS probe should NOT run during transport failover!"),
        ), patch(
            "core.network_tests.connectivity_prober.probe_tcp_dns",
            side_effect=AssertionError("Redundant TCP DNS probe should NOT run during transport failover!"),
        ), patch(
            "core.connection.multi_method_manager.probe_udp_dns",
            side_effect=AssertionError("Catalog UDP DNS probe should NOT run during transport failover!"),
        ), patch(
            "core.connection.multi_method_manager.probe_dot_dns",
            side_effect=AssertionError("Catalog DoT DNS probe should NOT run during transport failover!"),
        ), patch(
            "core.network_tests.connectivity_prober.probe_tcp_socket",
            return_value={"socket_ok": True, "latency_ms": 10.0, "error": None},
        ), patch(
            "core.network_tests.connectivity_prober.probe_tls_handshake",
            return_value={"socket_ok": True, "server_verified": True, "latency_ms": 20.0, "error": None},
        ), patch(
            "core.network_tests.connectivity_prober.probe_https_egress",
            return_value={
                "real_internet": True,
                "tls_verified": True,
                "captive_portal_suspected": False,
                "latency_ms": 30.0,
                "bytes_estimated": 1200,
                "error": None,
            },
        ), patch(
            "core.connection.multi_method_manager.probe_https_egress",
            return_value={
                "real_internet": True,
                "tls_verified": True,
                "captive_portal_suspected": False,
                "latency_ms": 32.0,
                "bytes_estimated": 1200,
                "error": None,
            },
        ), patch(
            "core.protocols.quic_engine.request_http3",
            return_value={"http3_verified": True, "total_latency_ms": 25.0, "response_bytes": 120, "error": None},
        ):
            candidates = ctrl._gather_general_candidates(effective_cost_profile="free")
            self.assertGreater(len(candidates), 0)
            for c in candidates:
                self.assertIn(c["protocol"], ("https", "http3", "ssh_socks5", "wireguard"))


class TestPhase4DiagnosticPrecision(unittest.TestCase):
    """Verifies Section B: independent capability matrix and all primary diagnostic states."""

    def _make_monitor(self, interfaces, allow_metered: bool = False):
        cm = CostManager(allow_metered=allow_metered, allow_unknown=True)
        mon = NetworkMonitor(
            cost_manager=cm,
            interface_provider=lambda: interfaces,
            metered_hint_provider=lambda _: None,
        )
        return cm, mon

    def test_physical_wifi_ethernet_metered_and_dns_only_states(self) -> None:
        # 1. Sin conexión física
        cm0, mon0 = self._make_monitor([])
        rep0 = DiagnosticEngine(cost_manager=cm0, network_monitor=mon0, execution_scope="SIMULATED_FAULT_INJECTION").run_diagnostics()
        self.assertEqual(rep0["primary_state"], DiagnosticPrimaryState.NO_PHYSICAL_CONNECTION.value)
        self.assertFalse(rep0["capability_matrix"]["physical_connection"])

        # 2. Bloqueado por política de coste (celular medido sin autorización)
        cm1, mon1 = self._make_monitor([{"name": "wwan0", "state": "UP", "addresses": ["10.1.1.2"]}], allow_metered=False)
        rep1 = DiagnosticEngine(cost_manager=cm1, network_monitor=mon1, execution_scope="SIMULATED_FAULT_INJECTION").run_diagnostics()
        self.assertEqual(rep1["primary_state"], DiagnosticPrimaryState.COST_POLICY_BLOCKED.value)
        self.assertTrue(rep1["capability_matrix"]["cost_policy_blocked"])

        # 3. Conectado a Wi-Fi sin salida a internet
        cm2, mon2 = self._make_monitor([{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.50"]}])
        rep2 = DiagnosticEngine(
            cost_manager=cm2,
            network_monitor=mon2,
            dns_probe_fn=lambda: {"udp_dns": {"protocol_verified": False}, "tcp_dns": {"protocol_verified": False}},
            web_https_probe_fn=lambda: [{"real_internet": False, "is_dns_provider": False}],
            http3_probe_fn=lambda: {"http3_verified": False},
            execution_scope="SIMULATED_FAULT_INJECTION",
        ).run_diagnostics()
        self.assertEqual(rep2["primary_state"], DiagnosticPrimaryState.WIFI_NO_INTERNET.value)
        self.assertTrue(rep2["capability_matrix"]["wifi_connected"])
        self.assertFalse(rep2["capability_matrix"]["general_internet_functional"])

        # 4. Conectado por Ethernet sin salida a internet
        cm3, mon3 = self._make_monitor([{"name": "enp1s0", "state": "UP", "addresses": ["192.168.1.51"]}])
        rep3 = DiagnosticEngine(
            cost_manager=cm3,
            network_monitor=mon3,
            dns_probe_fn=lambda: {"udp_dns": {"protocol_verified": False}, "tcp_dns": {"protocol_verified": False}},
            web_https_probe_fn=lambda: [{"real_internet": False, "is_dns_provider": False}],
            http3_probe_fn=lambda: {"http3_verified": False},
            execution_scope="SIMULATED_FAULT_INJECTION",
        ).run_diagnostics()
        self.assertEqual(rep3["primary_state"], DiagnosticPrimaryState.ETHERNET_NO_INTERNET.value)
        self.assertTrue(rep3["capability_matrix"]["ethernet_connected"])

        # 5. DNS funcional sin acceso web (nunca asumir que DNS funcional significa internet funcional)
        cm4, mon4 = self._make_monitor([{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.52"]}])
        rep4 = DiagnosticEngine(
            cost_manager=cm4,
            network_monitor=mon4,
            dns_probe_fn=lambda: {"udp_dns": {"protocol_verified": True}, "tcp_dns": {"protocol_verified": True}},
            web_https_probe_fn=lambda: [
                {"real_internet": False, "is_dns_provider": False},
                {"real_internet": True, "is_dns_provider": True},  # 1.1.1.1 responds, general web blocked!
            ],
            http3_probe_fn=lambda: {"http3_verified": True, "is_dns_provider": True},
            execution_scope="SIMULATED_FAULT_INJECTION",
        ).run_diagnostics()
        self.assertEqual(rep4["primary_state"], DiagnosticPrimaryState.DNS_ONLY_NO_WEB.value)
        self.assertTrue(rep4["capability_matrix"]["dns_any_functional"])
        self.assertTrue(rep4["capability_matrix"]["dns_functional_without_web"])
        self.assertFalse(rep4["capability_matrix"]["https_general_functional"])
        self.assertFalse(rep4["capability_matrix"]["http3_functional"])
        self.assertFalse(rep4["capability_matrix"]["general_internet_functional"])

    def test_ssh_and_wireguard_subcapabilities_strictly_differentiated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            id_f = tdir / "id_ed25519"
            id_f.write_text("key", encoding="utf-8")
            id_f.chmod(0o600)
            kh_f = tdir / "known_hosts"
            kh_f.write_text("127.0.0.1 ssh-ed25519 AAAA\n", encoding="utf-8")

            tun = SshSocksTunnel(
                SshTunnelConfig(
                    host="198.51.100.20",
                    username="jaro",
                    identity_file=str(id_f),
                    known_hosts_file=str(kh_f),
                    authorized=True,
                )
            )
            wg = WireGuardTunnelEngine(interface_name="wg0", authorized=True)

            # Case A: SSH process alive + local SOCKS5 ready + remote stream forwarded, BUT HTTPS egress FAILS,
            # and WireGuard has handshake + data transfer, BUT HTTPS egress FAILS -> NEITHER tunnel marked functional!
            cm, mon = self._make_monitor([{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.60"]}])
            with patch.object(
                tun,
                "check_health",
                return_value={
                    "healthy": False,
                    "process_alive": True,
                    "local_socks5_functional": True,
                    "remote_ssh_tunnel_functional": True,
                    "https_egress_verified": False,
                    "bytes_estimated": 500,
                    "error": "TLS handshake failed over SSH",
                },
            ), patch.object(
                wg,
                "inspect_state",
                return_value={
                    "tooling": {"wg_binary": "/usr/bin/wg"},
                    "interface_exists": True,
                    "handshake_verified": True,
                    "data_transfer_verified": True,
                    "https_egress_verified": False,
                    "bytes_estimated": 500,
                    "note": "HTTPS egress timeout over wg0",
                },
            ):
                rep_partial = DiagnosticEngine(
                    cost_manager=cm,
                    network_monitor=mon,
                    ssh_tunnels=[tun],
                    wireguard_engines=[wg],
                    dns_probe_fn=lambda: {"udp_dns": {"protocol_verified": True}},
                    web_https_probe_fn=lambda: [{"real_internet": True, "is_dns_provider": False}],
                    http3_probe_fn=lambda: {"http3_verified": True, "is_dns_provider": False},
                    execution_scope="SIMULATED_FAULT_INJECTION",
                ).run_diagnostics()

                mat = rep_partial["capability_matrix"]
                self.assertTrue(mat["local_socks5_functional"])
                self.assertTrue(mat["remote_ssh_tunnel_functional"])
                self.assertFalse(mat["ssh_https_egress_verified"])
                self.assertTrue(mat["wireguard_handshake_verified"])
                self.assertTrue(mat["wireguard_data_transfer_verified"])
                self.assertFalse(mat["wireguard_https_egress_verified"])
                self.assertTrue(mat["https_general_functional"])
                self.assertTrue(mat["http3_functional"])
                self.assertEqual(rep_partial["primary_state"], DiagnosticPrimaryState.HTTP3_FUNCTIONAL.value)
                self.assertNotIn("SSH_TUNNEL_FUNCTIONAL", rep_partial["functional_transports"])
                self.assertNotIn("WIREGUARD_TUNNEL_FUNCTIONAL", rep_partial["functional_transports"])


class TestPhase4TraceabilityAndNetworkLab(unittest.TestCase):
    """Verifies Sections C & D: mandatory traceability fields, local lab 0 B external, and cost gate."""

    def test_simulated_scope_never_allows_verified_real_true(self) -> None:
        rec = LabTestRecord(
            test_id="sim_test",
            execution_scope=ExecutionScope.SIMULATED_FAULT_INJECTION,
            server="mock:443",
            protocol="http3",
            timestamp_utc="2026-11-04T00:00:00+00:00",
            duration_ms=5.0,
            bytes_estimated=0,
            verified_real=True,  # Intentionally passed True -> must be coerced to False!
            result="PASS",
            reason="Simulated injection",
        )
        d = rec.to_dict()
        self.assertFalse(d["verified_real"])
        for mandatory_key in (
            "execution_scope",
            "server",
            "protocol",
            "timestamp_utc",
            "duration_ms",
            "bytes_estimated",
            "verified_real",
            "resultado",
            "motivo",
        ):
            self.assertIn(mandatory_key, d)

    def test_external_lab_requires_explicit_authorization_on_unknown_and_metered_profiles(self) -> None:
        # 1. UNKNOWN profile (unconfigured Wi-Fi) without authorize_unknown_cost=True -> SKIPPED with 0 B!
        cm_unk = CostManager(allow_metered=False, allow_unknown=True, allow_external_lab_unknown=False)
        mon_unk = NetworkMonitor(
            cost_manager=cm_unk,
            interface_provider=lambda: [{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.242"]}],
            metered_hint_provider=lambda _: False,
        )
        lab_unk = NetworkLab(cost_manager=cm_unk, network_monitor=mon_unk)
        ext_blocked = lab_unk.run_external_lab_suite(authorize_unknown_cost=False)
        self.assertFalse(ext_blocked["cost_gate"]["allowed"])
        self.assertEqual(ext_blocked["data_consumption"]["external_bytes_consumed"], 0)
        self.assertEqual(ext_blocked["counts"]["passed"], 0)
        self.assertEqual(ext_blocked["counts"]["skipped"], ext_blocked["counts"]["total"])

        # 2. METERED profile without authorize_metered_cost=True -> SKIPPED with 0 B!
        cm_met = CostManager(allow_metered=False, allow_unknown=True)
        mon_met = NetworkMonitor(
            cost_manager=cm_met,
            interface_provider=lambda: [{"name": "wwan0", "state": "UP", "addresses": ["10.20.30.40"]}],
            metered_hint_provider=lambda _: True,
        )
        lab_met = NetworkLab(cost_manager=cm_met, network_monitor=mon_met)
        ext_met_blocked = lab_met.run_external_lab_suite(authorize_unknown_cost=True, authorize_metered_cost=False)
        self.assertFalse(ext_met_blocked["cost_gate"]["allowed"])
        self.assertEqual(ext_met_blocked["data_consumption"]["external_bytes_consumed"], 0)

    def test_local_lab_suite_executes_against_loopback_with_zero_external_bytes(self) -> None:
        cm = CostManager(allow_metered=False, allow_unknown=False)
        lab = NetworkLab(cost_manager=cm)
        report = lab.run_local_lab_suite()

        self.assertEqual(report["data_consumption"]["external_bytes_consumed"], 0)
        self.assertEqual(report["counts"]["failed"], 0)
        self.assertGreaterEqual(report["counts"]["passed"], 10)

        by_id = {r["test_id"]: r for r in report["records"]}
        for must_pass in (
            "local_quic_handshake",
            "local_http3_client_server",
            "local_doq_rfc9250",
            "local_dns_udp",
            "local_dns_tcp",
            "local_dot_rfc7858",
            "local_cert_valid_chain",
            "local_cert_expired_rejected",
            "local_cert_untrusted_rejected",
            "local_cert_wrong_sni_rejected",
            "local_socks5_https_relay",
            "local_wireguard_config_validator",
        ):
            self.assertEqual(by_id[must_pass]["result"], "PASS", msg=f"{must_pass} failed: {by_id[must_pass]}")
            self.assertEqual(by_id[must_pass]["execution_scope"], ExecutionScope.LOCAL_LOOPBACK.value)
            self.assertTrue(by_id[must_pass]["verified_real"])

    def test_external_lab_authorized_execution_path_and_byte_cap(self) -> None:
        """Verifies run_external_lab_suite authorized execution path & BandwidthTester integration with 0 wire bytes."""
        async def fake_doq(**_kw):
            return {"protocol_verified": True, "quic_connected": True, "latency_ms": 18.0, "error": None}

        async def fake_h3(**_kw):
            return {
                "http3_verified": True,
                "tls_verified": True,
                "response_bytes": 160,
                "handshake_time_ms": 12.0,
                "response_time_ms": 4.0,
                "total_latency_ms": 16.0,
                "error": None,
            }

        cm = CostManager(allow_metered=False, allow_unknown=True, allow_external_lab_unknown=False, max_session_bytes=65536)
        mon = NetworkMonitor(
            cost_manager=cm,
            interface_provider=lambda: [{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.50"]}],
            metered_hint_provider=lambda _: False,
        )
        lab = NetworkLab(cost_manager=cm, network_monitor=mon)

        with (
            patch("core.network_tests.network_lab.probe_udp_dns", return_value={"protocol_verified": True, "latency_ms": 5.0, "answers": 1}),
            patch("core.network_tests.network_lab.probe_tcp_dns", return_value={"protocol_verified": True, "latency_ms": 8.0, "answers": 1}),
            patch("core.network_tests.network_lab.probe_dot_dns", return_value={"protocol_verified": True, "tls_verified": True, "latency_ms": 20.0}),
            patch("core.network_tests.network_lab.async_probe_doq", side_effect=fake_doq),
            patch("core.network_tests.network_lab.probe_https_egress", return_value={"real_internet": True, "latency_ms": 25.0, "bytes_estimated": 1800, "error": None}),
            patch("core.network_tests.network_lab.async_request_http3", side_effect=fake_h3),
            patch("core.network_tests.network_lab.probe_tls_handshake", return_value={"socket_ok": True, "server_verified": True, "error": None}),
            patch("core.network_tests.bandwidth_tester.BandwidthTester.measure_download_speed", return_value={"succeeded": True, "bytes_transferred": 8192, "download_kbps": 950.0, "error": None}),
            patch("core.network_tests.bandwidth_tester.BandwidthTester.measure_upload_speed", return_value={"succeeded": True, "bytes_transferred": 4096, "upload_kbps": 750.0, "error": None}),
        ):
            rep = lab.run_external_lab_suite(authorize_unknown_cost=True, max_suite_bytes=65536)

        self.assertEqual(rep["counts"]["passed"], 9)
        self.assertEqual(rep["counts"]["skipped"], 2)
        self.assertEqual(rep["counts"]["failed"], 0)
        by_id = {r["test_id"]: r for r in rep["records"]}
        self.assertEqual(by_id["external_latency_loss_stability"]["result"], "PASS")
        self.assertEqual(by_id["external_latency_loss_stability"]["details"]["samples_received"], 4)
        self.assertEqual(by_id["external_ssh_tunnel"]["result"], "SKIPPED")
        self.assertFalse(by_id["external_ssh_tunnel"]["verified_real"])


class TestPhase4RecoveryAndStability(unittest.TestCase):
    """Verifies Section E: simulated vs real local recovery across disconnects, roam, packet loss, and tunnel drops."""

    def test_simulated_disconnect_interface_roam_packet_loss_and_ssh_wireguard_recovery(self) -> None:
        """Explicitly tagged SIMULATED_FAULT_INJECTION scenarios testing state machine recovery."""
        iface_state = [{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.10"]}]
        wg_alive = True
        ssh_alive = True
        h3_loss_pct = 0.0

        id_dir = tempfile.TemporaryDirectory()
        self.addCleanup(id_dir.cleanup)
        tpath = Path(id_dir.name)
        id_f = tpath / "id_ed25519"
        id_f.write_text("k", encoding="utf-8")
        id_f.chmod(0o600)
        kh_f = tpath / "known_hosts"
        kh_f.write_text("198.51.100.5 ssh-ed25519 AAAA\n", encoding="utf-8")

        ssh_tun = SshSocksTunnel(
            SshTunnelConfig(
                host="198.51.100.5",
                username="jaro",
                identity_file=str(id_f),
                known_hosts_file=str(kh_f),
                authorized=True,
            )
        )
        wg_eng = WireGuardTunnelEngine(interface_name="wg_sim0", authorized=True)

        cm = CostManager(allow_metered=False, allow_unknown=True)
        cm.set_interface_profile("wlp2s0", CostProfile.FREE)
        cm.set_interface_profile("enp1s0", CostProfile.FREE)
        mon = NetworkMonitor(cost_manager=cm, interface_provider=lambda: iface_state, metered_hint_provider=lambda _: False)
        tm = TransportManager(ssh_tunnels=[ssh_tun], wireguard_engines=[wg_eng], cost_manager=cm)

        def sim_candidates():
            return [
                {
                    "tunnel_id": "wireguard-wg_sim0-1",
                    "server_id": "wireguard-wg_sim0-1",
                    "interface": "wg_sim0",
                    "protocol": "wireguard",
                    "authorized": True,
                    "available": wg_alive,
                    "handshake_verified": wg_alive,
                    "https_egress_verified": wg_alive,
                    "real_internet_verified": wg_alive,
                    "avg_latency_ms": 22.0 if wg_alive else None,
                    "jitter_ms": 1.0,
                    "stability_ratio": 1.0 if wg_alive else 0.0,
                },
                {
                    "server_id": "ssh-tunnel-1",
                    "host": "198.51.100.5",
                    "protocol": "ssh_socks5",
                    "available": ssh_alive,
                    "real_internet_verified": ssh_alive,
                    "avg_latency_ms": 38.0 if ssh_alive else None,
                    "jitter_ms": 2.0,
                    "stability_ratio": 1.0 if ssh_alive else 0.0,
                },
                {
                    "server_id": "cf-h3",
                    "host": "1.1.1.1",
                    "protocol": "http3",
                    "available": h3_loss_pct < 100.0,
                    "real_internet_verified": h3_loss_pct < 100.0,
                    "avg_latency_ms": 30.0 if h3_loss_pct < 100.0 else None,
                    "jitter_ms": 18.0 if h3_loss_pct > 0 else 1.5,
                    "packet_loss_pct": h3_loss_pct,
                    "stability_ratio": max(0.0, 1.0 - h3_loss_pct / 100.0),
                },
                {
                    "server_id": "cf-https",
                    "host": "1.1.1.1",
                    "protocol": "https",
                    "available": True,
                    "real_internet_verified": True,
                    "avg_latency_ms": 48.0,
                    "jitter_ms": 2.0,
                    "packet_loss_pct": 0.0,
                    "stability_ratio": 1.0,
                },
            ]

        def sim_health(active):
            p = active["protocol"]
            if p == "wireguard":
                return {"healthy": wg_alive, "latency_ms": 22.0 if wg_alive else None, "error": None if wg_alive else "WG handshake expired"}
            if p == "ssh_socks5":
                return {"healthy": ssh_alive, "latency_ms": 38.0 if ssh_alive else None, "error": None if ssh_alive else "SSH channel closed"}
            if p == "http3":
                return {"healthy": h3_loss_pct < 50.0, "latency_ms": 30.0, "error": None if h3_loss_pct < 50.0 else "Severe packet loss / QUIC timeout"}
            return {"healthy": True, "latency_ms": 48.0, "error": None}

        reconn = ExponentialBackoffReconnector(base_delay=0.05, max_attempts=3, jitter_ratio=0.0, sleep_fn=lambda _: None)
        ctrl = FailoverController(
            cost_manager=cm,
            network_monitor=mon,
            transport_manager=tm,
            reconnector=reconn,
            candidate_provider=sim_candidates,
            active_health_checker=sim_health,
            event_log_path=None,
        )

        # 1. Initial connect selects lowest-latency verified WireGuard
        s1 = ctrl.supervise_step()
        self.assertEqual(s1["action"], "ESTABLISHED_CONNECTION")
        self.assertEqual(ctrl.session.active_protocol, "wireguard")

        # 2. WireGuard peer drops & HTTP/3 suffers 60% packet loss -> AutoSelector picks healthy HTTPS over lossy HTTP/3!
        wg_alive = False
        ssh_alive = False
        h3_loss_pct = 60.0
        s2 = ctrl.supervise_step()
        self.assertEqual(s2["action"], "AUTOMATIC_FAILOVER")
        self.assertEqual(ctrl.session.active_protocol, "https")

        # 3. Physical disconnect -> DISCONNECTED_NO_NETWORK
        iface_state = []
        s3 = ctrl.supervise_step()
        self.assertEqual(s3["action"], "DISCONNECTED_NO_NETWORK")
        self.assertEqual(ctrl.session.state, SessionState.DISCONNECTED)

        # 4. Interface roam onto Ethernet with SSH active -> connects to SSH, then recovers SSH in-place on transient drop!
        iface_state = [{"name": "enp1s0", "state": "UP", "addresses": ["192.168.1.77"]}]
        ssh_alive = True
        h3_loss_pct = 100.0
        ctrl._candidate_provider = lambda: [c for c in sim_candidates() if c["protocol"] in ("ssh_socks5", "https")]
        # Make SSH beat HTTPS on latency (38ms < 48ms)
        s4 = ctrl.supervise_step()
        self.assertEqual(s4["action"], "ESTABLISHED_CONNECTION")
        self.assertEqual(ctrl.session.active_protocol, "ssh_socks5")
        self.assertEqual(ctrl.session.active_interface, "enp1s0")

        # Simulate transient SSH drop where SshSocksTunnel.reconnect() restores ssh_alive=True
        ssh_alive = False

        def restore_ssh(*_a, **_kw):
            nonlocal ssh_alive
            ssh_alive = True
            return {"connected": True, "attempts_used": 1}

        with patch.object(ssh_tun, "reconnect", side_effect=restore_ssh):
            s5 = ctrl.supervise_step()
            self.assertEqual(s5["action"], "RECOVERED_ACTIVE_TUNNEL")
            self.assertEqual(ctrl.session.active_protocol, "ssh_socks5")

    def test_real_local_loopback_socket_failure_and_failover_between_live_servers(self) -> None:
        """LOCAL_LOOPBACK real recovery: starts 2 real TLS HTTPS servers on 127.0.0.1, kills primary, verifies real failover."""
        with tempfile.TemporaryDirectory() as tmp:
            pki = _generate_lab_pki(Path(tmp))
            srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            srv_ctx.load_cert_chain(str(pki["valid_cert"]), str(pki["valid_key"]))

            client_ctx = ssl.create_default_context(cafile=str(pki["ca"]))
            client_ctx.check_hostname = True
            client_ctx.verify_mode = ssl.CERT_REQUIRED

            stop_srv1 = threading.Event()
            stop_srv2 = threading.Event()

            def start_https_loopback(stop_ev: threading.Event, tag: str) -> tuple[socket.socket, int, threading.Thread]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", 0))
                sock.listen(5)
                sock.settimeout(0.2)
                port = sock.getsockname()[1]

                def loop() -> None:
                    while not stop_ev.is_set():
                        try:
                            conn, _ = sock.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        try:
                            with srv_ctx.wrap_socket(conn, server_side=True) as tls_c:
                                tls_c.recv(1024)
                                body = f"LIVE-{tag}".encode("ascii")
                                tls_c.sendall(
                                    b"HTTP/1.1 200 OK\r\n"
                                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                                    + body
                                )
                        except Exception:
                            pass
                    try:
                        sock.close()
                    except OSError:
                        pass

                th = threading.Thread(target=loop, daemon=True)
                th.start()
                return sock, port, th

            sock1, port1, th1 = start_https_loopback(stop_srv1, "PRIMARY")
            sock2, port2, th2 = start_https_loopback(stop_srv2, "BACKUP")
            try:
                cm = CostManager(allow_metered=False, allow_unknown=True)
                cm.set_interface_profile("lo_virt0", CostProfile.FREE)
                mon = NetworkMonitor(
                    cost_manager=cm,
                    interface_provider=lambda: [{"name": "lo_virt0", "state": "UP", "addresses": ["127.0.0.1"]}],
                    metered_hint_provider=lambda _: False,
                )

                from core.network_tests.connectivity_prober import probe_https_egress

                def live_loopback_candidates():
                    cands = []
                    for sid, prt, tag, base_lat in (("local-primary", port1, "PRIMARY", 5.0), ("local-backup", port2, "BACKUP", 25.0)):
                        res = probe_https_egress(
                            url=f"https://localhost:{prt}/",
                            connect_host="127.0.0.1",
                            sni_hostname="localhost",
                            expected_status=200,
                            expected_substring=f"LIVE-{tag}",
                            timeout=1.0,
                            ssl_context=client_ctx,
                        )
                        cands.append({
                            "server_id": sid,
                            "server_name": sid,
                            "host": "127.0.0.1",
                            "port": prt,
                            "sni": f"localhost:{prt}",
                            "path": "/",
                            "expected_status": 200,
                            "expected_substring": f"LIVE-{tag}",
                            "ssl_context": client_ctx,
                            "protocol": "https",
                            "available": res["real_internet"],
                            "real_internet_verified": res["real_internet"],
                            "avg_latency_ms": base_lat if res["real_internet"] else None,
                            "jitter_ms": 0.5,
                            "stability_ratio": 1.0 if res["real_internet"] else 0.0,
                        })
                    return cands

                # Note: in _default_active_health_check, url is f"https://{sni}{path}" and sni_hostname is "localhost"
                def real_loopback_health_check(transport):
                    prt = transport["port"]
                    res = probe_https_egress(
                        url=f"https://localhost:{prt}/",
                        connect_host="127.0.0.1",
                        sni_hostname="localhost",
                        expected_status=200,
                        expected_substring=transport["expected_substring"],
                        timeout=1.0,
                        ssl_context=client_ctx,
                    )
                    return {
                        "healthy": res["real_internet"],
                        "latency_ms": res["latency_ms"],
                        "error": res["error"],
                    }

                reconn = ExponentialBackoffReconnector(base_delay=0.05, max_attempts=2, jitter_ratio=0.0, sleep_fn=lambda _: None)
                ctrl = FailoverController(
                    cost_manager=cm,
                    network_monitor=mon,
                    reconnector=reconn,
                    candidate_provider=live_loopback_candidates,
                    active_health_checker=real_loopback_health_check,
                    event_log_path=None,
                )

                # Step 1: Connects to live PRIMARY TLS server on 127.0.0.1
                r1 = ctrl.supervise_step()
                self.assertEqual(r1["action"], "ESTABLISHED_CONNECTION")
                self.assertEqual(ctrl.session.active_server_id, "local-primary")

                # Step 2: Healthy check passes over real TLS socket
                r2 = ctrl.supervise_step()
                self.assertEqual(r2["action"], "KEPT_HEALTHY_TRANSPORT")

                # Step 3: Shut down PRIMARY TLS socket -> real ConnectionRefusedError -> automatic failover to BACKUP!
                stop_srv1.set()
                sock1.close()
                th1.join(timeout=1.5)

                r3 = ctrl.supervise_step()
                self.assertEqual(r3["action"], "AUTOMATIC_FAILOVER")
                self.assertTrue(r3["connected"])
                self.assertEqual(ctrl.session.active_server_id, "local-backup")
            finally:
                stop_srv1.set()
                stop_srv2.set()
                th1.join(timeout=1.5)
                th2.join(timeout=1.5)


if __name__ == "__main__":
    unittest.main()
