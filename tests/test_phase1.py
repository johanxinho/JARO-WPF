"""Automated unit and behavioral integration tests for JARO WPF Phase 1 Audit."""
import asyncio
import socket
import struct
import threading
import unittest
from unittest.mock import patch

from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset

from core.connection.multi_method_manager import (
    MultiMethodManager,
    classify_interface_medium,
    compute_dns_score,
    compute_transport_score,
)
from core.connection.reconnector import ExponentialBackoffReconnector
from core.network_tests.connectivity_prober import (
    ConnectivityState,
    classify_connectivity,
    parse_dns_response_ips,
    probe_https_egress,
    probe_tcp_dns,
    probe_tls_handshake,
)
from core.protocols.doq_engine import DoQClientProtocol, DoQProtocolError
from core.protocols.udp_engine import create_dns_query


class TestConnectivityProberBehavior(unittest.TestCase):
    """Verifies real socket/HTTP/TLS behavior and strict separation of connectivity states."""

    def test_dns_response_validation(self) -> None:
        txid, _ = create_dns_query("example.com")
        valid_pkt = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
        parsed = parse_dns_response_ips(valid_pkt, txid)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["answers"], 1)

        bad_txid = parse_dns_response_ips(valid_pkt, (txid + 1) % 65536)
        self.assertFalse(bad_txid["valid"])

        nxdomain_pkt = struct.pack("!HHHHHH", txid, 0x8183, 1, 0, 0, 0)
        self.assertFalse(parse_dns_response_ips(nxdomain_pkt, txid)["valid"])

    def test_tcp_syn_ack_without_dns_payload_detected_as_socket_only(self) -> None:
        """Simulates a firewall/middlebox that accepts TCP SYN-ACK on port 53 but closes immediately."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def accept_and_close() -> None:
            conn, _ = srv.accept()
            conn.close()
            srv.close()

        t = threading.Thread(target=accept_and_close, daemon=True)
        t.start()

        res = probe_tcp_dns("127.0.0.1", port=port, timeout=1.5)
        t.join(timeout=2.0)
        self.assertTrue(res["socket_ok"])
        self.assertFalse(res["protocol_verified"])

    def test_http_captive_portal_redirect_and_content_mismatch_behavior(self) -> None:
        """Verifies probe_https_egress against a real local HTTP server returning 302 or spoofed 200."""
        # Case 1: Captive portal 302 redirect
        srv1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv1.bind(("127.0.0.1", 0))
        srv1.listen(1)
        port1 = srv1.getsockname()[1]

        def serve_redirect() -> None:
            conn, _ = srv1.accept()
            conn.recv(1024)
            conn.sendall(
                b"HTTP/1.1 302 Found\r\n"
                b"Location: http://portal.carrier.local/login\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            conn.close()
            srv1.close()

        t1 = threading.Thread(target=serve_redirect, daemon=True)
        t1.start()
        res_redirect = probe_https_egress(
            url=f"http://127.0.0.1:{port1}/test",
            expected_status=200,
            expected_substring="Example Domain",
            timeout=2.0,
        )
        t1.join(timeout=2.0)
        self.assertFalse(res_redirect["real_internet"])
        self.assertTrue(res_redirect["captive_portal_suspected"])

        # Case 2: Captive portal returning HTTP 200 with billing HTML instead of expected payload
        srv2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv2.bind(("127.0.0.1", 0))
        srv2.listen(1)
        port2 = srv2.getsockname()[1]

        def serve_spoofed_200() -> None:
            conn, _ = srv2.accept()
            conn.recv(1024)
            body = b"<html><body>Please recharge your balance</body></html>"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                + body
            )
            conn.close()
            srv2.close()

        t2 = threading.Thread(target=serve_spoofed_200, daemon=True)
        t2.start()
        res_spoof = probe_https_egress(
            url=f"http://127.0.0.1:{port2}/test",
            expected_status=200,
            expected_substring="Example Domain",
            timeout=2.0,
        )
        t2.join(timeout=2.0)
        self.assertFalse(res_spoof["real_internet"])
        self.assertTrue(res_spoof["captive_portal_suspected"])

    def test_tls_hostname_mismatch_rejected(self) -> None:
        """Verifies that connecting to a real TLS server with a mismatched SNI/hostname fails TLS verification."""
        from pathlib import Path
        import ssl
        import tempfile
        from tests.test_quic_engine import _generate_test_cert_files

        with tempfile.TemporaryDirectory() as tmp:
            certs = _generate_test_cert_files(Path(tmp), dns_name="localhost", expired=False)
            srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            srv_ctx.load_cert_chain(certs["cert"], certs["key"])

            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]

            def run_tls_srv() -> None:
                try:
                    conn, _ = srv.accept()
                    with srv_ctx.wrap_socket(conn, server_side=True):
                        pass
                except Exception:
                    pass
                finally:
                    srv.close()

            t = threading.Thread(target=run_tls_srv, daemon=True)
            t.start()

            client_ctx = ssl.create_default_context(cafile=certs["cert"])
            client_ctx.check_hostname = True
            client_ctx.verify_mode = ssl.CERT_REQUIRED
            res = probe_tls_handshake(
                "127.0.0.1",
                port,
                sni="invalid.example.internal",
                timeout=2.0,
                ssl_context=client_ctx,
            )
            t.join(timeout=2.0)

        self.assertTrue(res["socket_ok"])
        self.assertFalse(res["server_verified"])
        self.assertIn("SSL verification failed", res["error"] or "")

    def test_dns_provider_https_alone_does_not_declare_real_internet(self) -> None:
        """Verifies Audit Point #2: if 1.1.1.1 HTTPS works but non-DNS web hosts fail, state is DNS_ONLY."""
        state = classify_connectivity(
            dns_udp={"protocol_verified": True},
            dns_tcp={"protocol_verified": True, "socket_ok": True},
            tcp_sock={"socket_ok": True},
            tls_check={"server_verified": True, "socket_ok": True},
            https_check={"real_internet": True, "captive_portal_suspected": False},
            non_dns_https_checks=[
                {"real_internet": False, "captive_portal_suspected": False},
                {"real_internet": False, "captive_portal_suspected": False},
            ],
        )
        self.assertEqual(state, ConnectivityState.DNS_ONLY)

    def test_real_internet_requires_non_dns_web_host_verification(self) -> None:
        state = classify_connectivity(
            dns_udp={"protocol_verified": True},
            dns_tcp={"protocol_verified": True, "socket_ok": True},
            tcp_sock={"socket_ok": True},
            tls_check={"server_verified": True, "socket_ok": True},
            https_check={"real_internet": True, "captive_portal_suspected": False},
            non_dns_https_checks=[
                {"real_internet": True, "captive_portal_suspected": False},
            ],
        )
        self.assertEqual(state, ConnectivityState.REAL_INTERNET)


class TestReconnectorSafety(unittest.TestCase):
    """Verifies exponential backoff, max_attempts bounds, non-retryable abort, and circuit breaker."""

    def test_rejects_excessive_max_attempts(self) -> None:
        with self.assertRaises(ValueError):
            ExponentialBackoffReconnector(max_attempts=25)

    def test_circuit_breaker_prevents_reconnection_loops(self) -> None:
        now = [100.0]
        sleeps = []

        def fake_clock() -> float:
            return now[0]

        def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        reconnector = ExponentialBackoffReconnector(
            base_delay=1.0,
            max_delay=10.0,
            factor=2.0,
            jitter_ratio=0.0,
            max_attempts=3,
            circuit_cooldown_s=30.0,
            sleep_fn=fake_sleep,
            clock_fn=fake_clock,
        )

        # First cycle fails all 3 attempts -> trips circuit breaker
        out1 = reconnector.execute_with_retry(
            connect_fn=lambda: {"ok": False, "error": "Network unreachable"},
            is_success_fn=lambda r: r.get("ok", False),
        )
        self.assertFalse(out1["connected"])
        self.assertTrue(out1["circuit_breaker_tripped"])
        self.assertEqual(out1["attempts_used"], 3)

        # Immediate second call in an outer loop is blocked with 0 attempts!
        out2 = reconnector.execute_with_retry(
            connect_fn=lambda: {"ok": True},
            is_success_fn=lambda r: r.get("ok", False),
        )
        self.assertFalse(out2["connected"])
        self.assertTrue(out2["circuit_breaker_tripped"])
        self.assertEqual(out2["attempts_used"], 0)

        # Advance clock past 30s cooldown -> circuit closes and allows reconnection
        now[0] += 31.0
        out3 = reconnector.execute_with_retry(
            connect_fn=lambda: {"ok": True},
            is_success_fn=lambda r: r.get("ok", False),
        )
        self.assertTrue(out3["connected"])
        self.assertEqual(out3["attempts_used"], 1)

    def test_non_retryable_abort_stops_immediately(self) -> None:
        reconnector = ExponentialBackoffReconnector(
            base_delay=1.0,
            max_attempts=5,
            sleep_fn=lambda _: None,
        )
        calls = 0

        def metered_blocked():
            nonlocal calls
            calls += 1
            return {"status": "ABORTED_METERED_GUARD"}

        out = reconnector.execute_with_retry(
            connect_fn=metered_blocked,
            is_success_fn=lambda r: r.get("status") == "OK",
            should_abort_fn=lambda r: r.get("status") == "ABORTED_METERED_GUARD",
        )
        self.assertFalse(out["connected"])
        self.assertTrue(out["aborted_non_retryable"])
        self.assertEqual(calls, 1)


class TestMultiMethodSeparationAndScoring(unittest.TestCase):
    """Verifies Audit Points #3 and #4: strict separation of DNS services vs Internet Transports."""

    def test_dns_and_transport_scores_are_categorized_and_documented(self) -> None:
        dns_Encrypted = compute_dns_score(
            available=True,
            encrypted=True,
            latency_ms=25.0,
            stability_ratio=1.0,
            jitter_ms=1.0,
            cost_tier=0,
        )
        dns_plain = compute_dns_score(
            available=True,
            encrypted=False,
            latency_ms=25.0,
            stability_ratio=1.0,
            jitter_ms=1.0,
            cost_tier=0,
        )
        self.assertGreater(dns_Encrypted["total"], dns_plain["total"])
        self.assertIn("protocol_security_pts", dns_Encrypted)

        trans_verified = compute_transport_score(
            available=True,
            real_internet=True,
            latency_ms=40.0,
            stability_ratio=1.0,
            jitter_ms=2.0,
            cost_tier=0,
        )
        trans_unverified = compute_transport_score(
            available=True,
            real_internet=False,
            latency_ms=40.0,
            stability_ratio=1.0,
            jitter_ms=2.0,
            cost_tier=0,
        )
        self.assertGreater(trans_verified["total"], trans_unverified["total"])
        self.assertIn("verification_pts", trans_verified)

    def test_manager_separates_dns_resolvers_from_internet_transports(self) -> None:
        with patch(
            "core.connection.multi_method_manager.detect_active_media",
            return_value=[{
                "name": "enp1s0",
                "state": "UP",
                "addresses": ["192.168.1.10"],
                "medium": "ethernet",
                "metered": False,
                "base_cost_tier": 0,
            }],
        ), patch(
            "core.connection.multi_method_manager.evaluate_full_connectivity",
            return_value={
                "state": ConnectivityState.REAL_INTERNET.value,
                "real_internet_verified": True,
                "summary": {"non_dns_web_egress_ok": True},
            },
        ), patch.object(
            MultiMethodManager,
            "_run_protocol_samples",
            side_effect=lambda proto, host, sni, cfg: {
                "category": "dns_service" if proto in ("udp_dns", "tcp_dns", "dot", "doq") else "internet_transport",
                "protocol": proto,
                "port": cfg.get("port", 443),
                "available": True,
                "stability_ratio": 1.0,
                "avg_latency_ms": 15.0 if proto not in ("https", "http3") else 40.0,
                "jitter_ms": 1.0,
                "encrypted": proto in ("dot", "doq", "https", "http3"),
                "error": None,
            },
        ):
            mgr = MultiMethodManager(samples_per_check=1)
            report = mgr.evaluate_all()

            # Verify no DNS service appears in internet_transports and no DNS resolver claims real_internet_verified
            for item in report["internet_transports"]:
                self.assertEqual(item["category"], "internet_transport")
                self.assertIn(item["protocol"], ("https", "http3"))
                self.assertTrue(item["real_internet_verified"])

            for item in report["dns_resolvers"]:
                self.assertEqual(item["category"], "dns_service")
                self.assertIn(item["protocol"], ("udp_dns", "tcp_dns", "dot", "doq"))
                self.assertFalse(item["real_internet_verified"])

    def test_metered_interface_guard_blocks_unapproved_cellular_probes(self) -> None:
        meta = classify_interface_medium("wwan0")
        self.assertTrue(meta["metered"])

        with patch(
            "core.connection.multi_method_manager.detect_active_media",
            return_value=[{
                "name": "wwan0",
                "state": "UP",
                "addresses": ["10.100.1.2"],
                "medium": "cellular",
                "metered": True,
                "base_cost_tier": 2,
            }],
        ):
            mgr = MultiMethodManager(allow_metered_probes=False, samples_per_check=1)
            report = mgr.evaluate_all()
            self.assertEqual(report["status"], "ABORTED_METERED_GUARD")
            self.assertFalse(report["real_internet_verified"])


class TestDoQProtocolRFC9250Audit(unittest.IsolatedAsyncioTestCase):
    """Audits DoQClientProtocol against RFC 9250 Section 4.2 framing, stream reset, and trailing bytes."""

    def _make_protocol(self) -> DoQClientProtocol:
        class DummyQuic:
            def __init__(self) -> None:
                self.sent_payloads = []

            def get_next_available_stream_id(self) -> int:
                return 0

            def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
                self.sent_payloads.append((stream_id, data, end_stream))

        proto = DoQClientProtocol.__new__(DoQClientProtocol)
        proto._quic = DummyQuic()
        proto._responses = {}
        proto._buffers = {}
        proto.transmit = lambda: None
        return proto

    async def test_doq_rfc9250_valid_query_and_response(self) -> None:
        proto = self._make_protocol()
        _, raw_query = create_dns_query("example.com")
        fake_dns_resp = struct.pack("!HHHHHH", 0x0000, 0x8180, 1, 1, 0, 0) + raw_query[12:]
        framed_resp = struct.pack("!H", len(fake_dns_resp)) + fake_dns_resp

        asyncio.get_running_loop().call_soon(
            lambda: proto.quic_event_received(StreamDataReceived(stream_id=0, data=framed_resp, end_stream=True))
        )
        dns_msg = await proto.query(raw_query, timeout=1.5)

        sent_stream, sent_data, sent_fin = proto._quic.sent_payloads[0]
        self.assertEqual(sent_stream, 0)
        self.assertTrue(sent_fin)
        self.assertEqual(sent_data[2:4], b"\x00\x00")

        parsed = parse_dns_response_ips(dns_msg, expected_txid=0)
        self.assertTrue(parsed["valid"])

    async def test_doq_rejects_trailing_bytes_and_truncated_payload(self) -> None:
        proto = self._make_protocol()
        _, raw_query = create_dns_query("example.com")
        fake_dns_resp = struct.pack("!HHHHHH", 0x0000, 0x8180, 1, 1, 0, 0) + raw_query[12:]
        # Add 4 illegal trailing bytes after the length-prefixed DNS message
        framed_with_trailing = struct.pack("!H", len(fake_dns_resp)) + fake_dns_resp + b"JUNK"

        asyncio.get_running_loop().call_soon(
            lambda: proto.quic_event_received(
                StreamDataReceived(stream_id=0, data=framed_with_trailing, end_stream=True)
            )
        )
        with self.assertRaises(DoQProtocolError):
            await proto.query(raw_query, timeout=1.5)

    async def test_doq_handles_stream_reset_and_connection_terminated(self) -> None:
        proto = self._make_protocol()
        _, raw_query = create_dns_query("example.com")

        asyncio.get_running_loop().call_soon(
            lambda: proto.quic_event_received(StreamReset(stream_id=0, error_code=0x02))
        )
        with self.assertRaises(DoQProtocolError):
            await proto.query(raw_query, timeout=1.5)

        asyncio.get_running_loop().call_soon(
            lambda: proto.quic_event_received(
                ConnectionTerminated(error_code=0x01, frame_type=0, reason_phrase="Internal error")
            )
        )
        with self.assertRaises(DoQProtocolError):
            await proto.query(raw_query, timeout=1.5)


if __name__ == "__main__":
    unittest.main()
