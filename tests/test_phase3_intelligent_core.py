"""Automated behavioral tests for JARO WPF Phase 3: Intelligent Connectivity Core."""
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from core.connection.auto_selector import AutoSelector, score_verified_transport
from core.connection.connection_session import ConnectionSession, SessionState
from core.connection.cost_manager import CostManager, CostProfile
from core.connection.failover_controller import FailoverController
from core.connection.network_monitor import NetworkMonitor
from core.connection.reconnector import ExponentialBackoffReconnector
from core.network_tests.bandwidth_tester import BandwidthTester


class TestAutoSelectorAndCostManager(unittest.TestCase):
    """Tests 6-factor AutoSelector ranking, DNS exclusion, and CostManager Ethernet safety."""

    def test_ethernet_is_not_assumed_free_by_default(self) -> None:
        cm = CostManager(allow_metered=False, allow_unknown=True)
        # Unconfigured Ethernet must be UNKNOWN, never blindly FREE
        self.assertEqual(cm.classify_interface("enp1s0", medium="ethernet"), CostProfile.UNKNOWN)
        # Cellular must be METERED
        self.assertEqual(cm.classify_interface("wwan0", medium="cellular"), CostProfile.METERED)

        # User can manually configure enp1s0 as FREE or METERED
        cm.set_interface_profile("enp1s0", CostProfile.FREE)
        self.assertEqual(cm.classify_interface("enp1s0", medium="ethernet"), CostProfile.FREE)
        cm.set_interface_profile("enp1s0", CostProfile.METERED)
        self.assertEqual(cm.classify_interface("enp1s0", medium="ethernet"), CostProfile.METERED)

    def test_auto_selector_excludes_dns_and_compares_all_four_transports(self) -> None:
        selector = AutoSelector()
        # Direct call with DNS must raise ValueError
        with self.assertRaises(ValueError):
            score_verified_transport({"protocol": "doq", "category": "dns_service"})

        candidates = [
            {"protocol": "udp_dns", "category": "dns_service", "available": True},
            {"protocol": "dot", "plane": "dns_resolution", "available": True},
            {
                "server_id": "wg-unverified",
                "protocol": "wireguard",
                "available": True,
                "handshake_verified": False,
                "real_internet_verified": False,
                "avg_latency_ms": 15.0,
            },
            {
                "server_id": "cf-http3",
                "protocol": "http3",
                "available": True,
                "real_internet_verified": True,
                "cost_profile": "free",
                "avg_latency_ms": 35.0,
                "jitter_ms": 2.0,
                "packet_loss_pct": 0.0,
                "stability_ratio": 1.0,
                "download_kbps": 12000.0,
                "upload_kbps": 6000.0,
            },
            {
                "server_id": "cf-https",
                "protocol": "https",
                "available": True,
                "real_internet_verified": True,
                "cost_profile": "free",
                "avg_latency_ms": 65.0,
                "jitter_ms": 5.0,
                "packet_loss_pct": 0.0,
                "stability_ratio": 1.0,
                "download_kbps": 8000.0,
                "upload_kbps": 4000.0,
            },
            {
                "server_id": "own-ssh",
                "protocol": "ssh_socks5",
                "available": True,
                "real_internet_verified": True,
                "cost_profile": "unknown",
                "avg_latency_ms": 110.0,
                "jitter_ms": 12.0,
                "packet_loss_pct": 25.0,
                "stability_ratio": 0.75,
                "download_kbps": 2500.0,
            },
        ]

        res = selector.rank_transports(candidates)
        self.assertEqual(res["excluded_dns_entries"], 2)
        self.assertIsNotNone(res["selected_transport"])
        self.assertEqual(res["selected_transport"]["protocol"], "http3")

        # Unverified WireGuard must not be selectable
        wg_entry = next(c for c in res["ranked_transports"] if c["protocol"] == "wireguard")
        self.assertFalse(wg_entry["selectable"])
        self.assertEqual(wg_entry["auto_score"], 0.0)


class TestNetworkMonitorTransitions(unittest.TestCase):
    """Tests interface disconnections, reconnections, USB tether detection, and metered blocks."""

    def test_interface_disconnect_reconnect_and_usb_tether_detection(self) -> None:
        snapshots = [
            [{"name": "enp1s0", "state": "UP", "addresses": ["192.168.1.10"]}],
            [{"name": "enp1s0", "state": "DOWN", "addresses": []}],
            [
                {"name": "enp1s0", "state": "DOWN", "addresses": []},
                {"name": "enp0s20f0u1", "state": "UP", "addresses": ["172.20.10.2"]},  # iPhone USB tether
            ],
            [{"name": "enp1s0", "state": "UP", "addresses": ["192.168.1.11"]}],
        ]
        idx = 0

        def provider():
            nonlocal idx
            val = snapshots[idx]
            idx = min(idx + 1, len(snapshots) - 1)
            return val

        cm = CostManager(allow_metered=False, allow_unknown=True)
        mon = NetworkMonitor(cost_manager=cm, interface_provider=provider, metered_hint_provider=lambda _: None)

        # Scan 1: enp1s0 added (UNKNOWN cost, allowed)
        s1 = mon.scan_interfaces()
        self.assertTrue(s1["online"])
        self.assertTrue(s1["cost_gate"]["allowed"])
        self.assertEqual(s1["active_interfaces"][0]["cost_profile"], "unknown")

        # Scan 2: enp1s0 disconnected -> offline!
        s2 = mon.scan_interfaces()
        self.assertFalse(s2["online"])
        ev_names_2 = [e["event"] for e in s2["events"]]
        self.assertIn("LINK_DISCONNECTED", ev_names_2)
        self.assertIn("ALL_NETWORKS_DISCONNECTED", ev_names_2)

        # Scan 3: iPhone USB tether enp0s20f0u1 appears -> detected as METERED & BLOCKED!
        s3 = mon.scan_interfaces()
        self.assertTrue(s3["online"])
        self.assertEqual(s3["active_interfaces"][0]["cost_profile"], "metered")
        self.assertFalse(s3["cost_gate"]["allowed"])

        # Scan 4: enp1s0 reconnects with new IP -> LINK_RECONNECTED
        s4 = mon.scan_interfaces()
        self.assertTrue(s4["online"])
        self.assertTrue(s4["cost_gate"]["allowed"])
        ev_names_4 = [e["event"] for e in s4["events"]]
        self.assertIn("LINK_RECONNECTED", ev_names_4)
        self.assertIn("INTERFACE_REMOVED", ev_names_4)


class TestHttp3FailoverAndMeteredGuard(unittest.TestCase):
    """Simulates HTTP/3 outage, seamless recovery via HTTPS, and metered connection blocking."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.log_file = Path(self._tmp.name) / "failover.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_http3_drop_automatically_recovers_via_https_without_unneeded_switches(self) -> None:
        http3_alive = True

        def fake_interfaces():
            return [{"name": "wlp2s0", "state": "UP", "addresses": ["10.0.0.15"]}]

        def fake_candidates():
            return [
                {
                    "server_id": "cloudflare-anycast",
                    "server_name": "Cloudflare Anycast",
                    "host": "1.1.1.1",
                    "port": 443,
                    "protocol": "http3",
                    "available": http3_alive,
                    "real_internet_verified": http3_alive,
                    "avg_latency_ms": 34.0 if http3_alive else None,
                    "jitter_ms": 1.5,
                    "stability_ratio": 1.0 if http3_alive else 0.0,
                },
                {
                    "server_id": "cloudflare-anycast",
                    "server_name": "Cloudflare Anycast",
                    "host": "1.1.1.1",
                    "port": 443,
                    "protocol": "https",
                    "available": True,
                    "real_internet_verified": True,
                    "avg_latency_ms": 62.0,
                    "jitter_ms": 2.0,
                    "stability_ratio": 1.0,
                },
            ]

        def fake_health_check(active_transport):
            if active_transport["protocol"] == "http3":
                return {
                    "healthy": http3_alive,
                    "latency_ms": 33.5 if http3_alive else None,
                    "error": None if http3_alive else "QUIC UDP 443 blocked mid-session",
                }
            return {"healthy": True, "latency_ms": 61.0, "error": None}

        cm = CostManager(allow_metered=False, allow_unknown=True)
        cm.set_interface_profile("wlp2s0", CostProfile.FREE)
        mon = NetworkMonitor(cost_manager=cm, interface_provider=fake_interfaces, metered_hint_provider=lambda _: False)
        reconn = ExponentialBackoffReconnector(base_delay=0.1, max_attempts=3, jitter_ratio=0.0, sleep_fn=lambda _: None)

        ctrl = FailoverController(
            cost_manager=cm,
            network_monitor=mon,
            reconnector=reconn,
            candidate_provider=fake_candidates,
            active_health_checker=fake_health_check,
            event_log_path=self.log_file,
        )

        # Step 1: Initial autonomous connection -> selects HTTP/3 (lowest latency)
        step1 = ctrl.supervise_step()
        self.assertEqual(step1["action"], "ESTABLISHED_CONNECTION")
        self.assertEqual(ctrl.session.state, SessionState.CONNECTED)
        self.assertEqual(ctrl.session.active_protocol, "http3")
        self.assertEqual(ctrl.session.failover_count, 0)

        # Step 2: HTTP/3 still healthy -> keeps current session without interruption
        step2 = ctrl.supervise_step()
        self.assertEqual(step2["action"], "KEPT_HEALTHY_TRANSPORT")
        self.assertEqual(ctrl.session.active_protocol, "http3")
        self.assertEqual(ctrl.session.failover_count, 0)

        # Step 3: Simulate HTTP/3 outage -> automatic failover to HTTPS!
        http3_alive = False
        step3 = ctrl.supervise_step()
        self.assertEqual(step3["action"], "AUTOMATIC_FAILOVER")
        self.assertTrue(step3["connected"])
        self.assertEqual(ctrl.session.state, SessionState.CONNECTED)
        self.assertEqual(ctrl.session.active_protocol, "https")
        self.assertEqual(ctrl.session.failover_count, 1)

        # Verify failover event was logged both in session and on disk
        events = ctrl.session.snapshot()["transport_changes"]
        self.assertEqual(events[-1]["event"], "TRANSPORT_FAILOVER")
        self.assertEqual(events[-1]["from_protocol"], "http3")
        self.assertEqual(events[-1]["to_protocol"], "https")
        self.assertTrue(self.log_file.is_file())

    def test_metered_connection_blocks_controller_immediately(self) -> None:
        cm = CostManager(allow_metered=False)
        mon = NetworkMonitor(
            cost_manager=cm,
            interface_provider=lambda: [{"name": "wwan0", "state": "UP", "addresses": ["10.50.1.9"]}],
            metered_hint_provider=lambda _: True,
        )
        ctrl = FailoverController(cost_manager=cm, network_monitor=mon, event_log_path=None)
        res = ctrl.supervise_step()
        self.assertEqual(res["action"], "BLOCKED_BY_COST_POLICY")
        self.assertFalse(res["connected"])
        self.assertEqual(ctrl.session.state, SessionState.BLOCKED_COST_POLICY)
        self.assertEqual(cm.bytes_consumed_total, 0)


class TestBandwidthTesterAndByteCaps(unittest.TestCase):
    """Tests micro-download, micro-upload, packet loss, and strict byte consumption limits."""

    def test_local_download_upload_packet_loss_and_budget_enforcement(self) -> None:
        # Start local HTTP server handling GET /down and POST /up
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]

        def handle_requests() -> None:
            for _ in range(2):
                conn, _ = srv.accept()
                req_data = conn.recv(16384)
                if req_data.startswith(b"GET"):
                    payload = b"D" * 8192
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
                        + payload
                    )
                else:
                    # Read remaining upload bytes if needed
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                conn.close()
            srv.close()

        t = threading.Thread(target=handle_requests, daemon=True)
        t.start()

        # Configure strict session budget of 20,000 bytes and single-test cap of 12,000 bytes
        cm = CostManager(
            allow_metered=False,
            allow_unknown=True,
            max_session_bytes=20000,
            max_single_test_bytes=12000,
        )
        tester = BandwidthTester(cost_manager=cm)

        # 1. Unauthorized endpoint must be rejected
        unauth = tester.measure_download_speed(f"http://127.0.0.1:{port}/down", authorized=False)
        self.assertFalse(unauth["succeeded"])

        # 2. Request exceeding single-test limit (16 KB > 12 KB) must be blocked before transfer!
        too_big = tester.measure_download_speed(
            f"http://127.0.0.1:{port}/down",
            authorized=True,
            max_bytes=16384,
        )
        self.assertFalse(too_big["succeeded"])
        self.assertEqual(cm.bytes_consumed_total, 0)

        # 3. Authorized 4 KB download succeeds and records consumption
        dl = tester.measure_download_speed(
            f"http://127.0.0.1:{port}/down",
            authorized=True,
            max_bytes=4096,
            interface_name="enp1s0",
        )
        self.assertTrue(dl["succeeded"])
        self.assertEqual(dl["bytes_transferred"], 4096)
        self.assertGreater(dl["download_kbps"], 0.0)

        # 4. Authorized 2 KB upload succeeds
        ul = tester.measure_upload_speed(
            f"http://127.0.0.1:{port}/up",
            authorized=True,
            payload_bytes=2048,
            interface_name="enp1s0",
        )
        self.assertTrue(ul["succeeded"])
        self.assertEqual(ul["bytes_transferred"], 2048)
        self.assertGreater(ul["upload_kbps"], 0.0)
        t.join(timeout=2.0)

        # 5. Quality sample test with 1 lost packet out of 4 -> 25% packet loss
        sample_seq = [
            {"verified": True, "latency_ms": 20.0, "bytes_transferred": 500},
            {"verified": False, "latency_ms": None, "bytes_transferred": 500, "error": "Timeout"},
            {"verified": True, "latency_ms": 24.0, "bytes_transferred": 500},
            {"verified": True, "latency_ms": 22.0, "bytes_transferred": 500},
        ]
        s_idx = 0

        def mock_probe():
            nonlocal s_idx
            item = sample_seq[s_idx]
            s_idx += 1
            return item

        qual = tester.measure_quality_samples(mock_probe, samples=4, estimated_bytes_per_sample=500)
        self.assertTrue(qual["allowed"])
        self.assertEqual(qual["packet_loss_pct"], 25.0)
        self.assertEqual(qual["stability_ratio"], 0.75)
        self.assertEqual(qual["avg_latency_ms"], 22.0)

        # 6. Exhaust remaining session budget -> next test is blocked!
        cm.record_consumption(15000)
        exhausted = tester.measure_quality_samples(lambda: {"verified": True, "latency_ms": 10.0}, samples=2)
        self.assertFalse(exhausted["allowed"])
        self.assertIn("exceeds remaining session byte budget", exhausted["error"] or "")


if __name__ == "__main__":
    unittest.main()
