"""Focused regression tests for security and truthfulness fixes."""
import struct
import socket
import socketserver
import threading
import time
import unittest

from core.connection.cost_manager import CostManager, CostProfile
from core.network_tests.connectivity_prober import parse_dns_response_ips, probe_https_egress
from core.protocols.vpn_tunnel_engine import verify_route_isolation
from core.protocols.dual_proxy_bridge import JaroDualProxyBridge


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(4096)
        if data:
            self.request.sendall(data)


class _ThreadingEchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TestHardeningRegressions(unittest.TestCase):
    def test_any_active_metered_path_blocks_unless_explicitly_authorized(self) -> None:
        interfaces = [
            {"name": "wlan0", "cost_profile": "free"},
            {"name": "wwan0", "cost_profile": "metered"},
        ]
        denied = CostManager(allow_metered=False).evaluate_network_gate(interfaces)
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["effective_profile"], CostProfile.METERED.value)

        allowed = CostManager(allow_metered=True).evaluate_network_gate(interfaces)
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["effective_profile"], CostProfile.METERED.value)

    def test_dns_header_only_packet_is_not_a_verified_response(self) -> None:
        txid = 0x1234
        header_only = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
        result = parse_dns_response_ips(header_only, txid)
        self.assertFalse(result["valid"])

    def test_complete_dns_a_response_is_verified(self) -> None:
        txid = 0x1234
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
        packet = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
        result = parse_dns_response_ips(packet, txid)
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["address_answers"], 1)
        self.assertFalse(parse_dns_response_ips(packet, txid, expected_question="attacker.invalid")["valid"])

    def test_dns_record_declaring_rdata_past_end_is_rejected(self) -> None:
        txid = 0x1234
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00"
        packet = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertFalse(parse_dns_response_ips(packet, txid)["valid"])

    def test_http_response_never_counts_as_real_internet_or_tls_verification(self) -> None:
        result = probe_https_egress(url="http://127.0.0.1:1/", timeout=0.1)
        self.assertFalse(result["real_internet"])
        self.assertFalse(result["tls_verified"])

    def test_unavailable_route_snapshots_fail_closed(self) -> None:
        empty = {"available": False, "default_routes": [], "interface_routes": [], "has_global_route_on_interface": False}
        result = verify_route_isolation(empty, empty, "wg-test0")
        self.assertFalse(result["routes_isolated_and_safe"])
        self.assertFalse(result["route_snapshots_available"])

    def test_http_connect_stream_survives_idle_period_and_bridge_stop_closes_it(self) -> None:
        echo = _ThreadingEchoServer(("127.0.0.1", 0), _EchoHandler)
        echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
        echo_thread.start()
        bridge = JaroDualProxyBridge(connect_timeout=0.05)
        bridge_port = bridge.start()
        client = socket.create_connection(("127.0.0.1", bridge_port), timeout=2)
        client.settimeout(2)
        try:
            request = f"CONNECT 127.0.0.1:{echo.server_address[1]} HTTP/1.1\r\nHost: local\r\n\r\n".encode()
            client.sendall(request)
            response = bytearray()
            while b"\r\n\r\n" not in response:
                response.extend(client.recv(1024))
            self.assertTrue(response.startswith(b"HTTP/1.1 200"), bytes(response))
            time.sleep(0.2)  # Longer than connect_timeout; a valid idle tunnel must remain usable.
            client.sendall(b"stream-test")
            self.assertEqual(client.recv(11), b"stream-test")
            self.assertEqual(bridge.stats_snapshot()["http_connect_connections"], 1)
            bridge.stop()
            self.assertEqual(client.recv(1), b"")
        finally:
            client.close()
            bridge.stop()
            echo.shutdown()
            echo.server_close()
            echo_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
