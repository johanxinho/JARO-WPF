"""Automated local behavioral tests for Phase 2: SSH/SOCKS5, WireGuard, and TransportManager."""
import base64
import os
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from core.connection.reconnector import ExponentialBackoffReconnector
from core.connection.transport_manager import TransportManager
from core.network_tests.connectivity_prober import ConnectivityState
from core.protocols.ssh_engine import (
    SshSocksTunnel,
    SshTunnelConfig,
    probe_https_over_socks5,
    socks5_greeting_probe,
    socks5_open_tunnel_socket,
)
from core.protocols.vpn_tunnel_engine import (
    WireGuardTunnelEngine,
    parse_wg_dump_output,
    validate_wireguard_config_file,
    validate_wireguard_config_text,
)
from tests.test_quic_engine import _generate_test_cert_files


def _valid_wg_b64_key(seed_byte: int) -> str:
    return base64.b64encode(bytes([seed_byte]) * 32).decode("ascii")


class TestSshAndSocks5Engine(unittest.TestCase):
    """Tests SSH security invariants, RFC 1928 SOCKS5 relay, TLS over SOCKS5, and reconnection."""

    def setUp(self) -> None:
        self._tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmpdir_obj.name)
        self.id_file = self.tmpdir / "id_ed25519"
        self.id_file.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n", encoding="utf-8")
        os.chmod(self.id_file, 0o600)

        self.kh_file = self.tmpdir / "known_hosts"
        self.kh_file.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir_obj.cleanup()

    def test_ssh_config_rejects_unauthorized_default_or_insecure_permissions(self) -> None:
        # 1. Unauthorized rejected
        cfg_unauth = SshTunnelConfig(
            host="127.0.0.1",
            username="jaro",
            identity_file=str(self.id_file),
            known_hosts_file=str(self.kh_file),
            authorized=False,
        )
        self.assertFalse(cfg_unauth.validate()["valid"])

        # 2. Non-loopback bind host rejected
        cfg_public_bind = SshTunnelConfig(
            host="127.0.0.1",
            username="jaro",
            identity_file=str(self.id_file),
            known_hosts_file=str(self.kh_file),
            local_bind_host="0.0.0.0",
            authorized=True,
        )
        self.assertFalse(cfg_public_bind.validate()["valid"])

        # 3. World-readable private key (0o644) rejected on POSIX
        os.chmod(self.id_file, 0o644)
        cfg_bad_perm = SshTunnelConfig(
            host="127.0.0.1",
            username="jaro",
            identity_file=str(self.id_file),
            known_hosts_file=str(self.kh_file),
            authorized=True,
        )
        val = cfg_bad_perm.validate()
        self.assertFalse(val["valid"])
        self.assertIn("Insecure IdentityFile permissions", val["error"] or "")

    def test_open_port_without_socks5_protocol_is_not_considered_available(self) -> None:
        """Proves a raw open TCP port (HTTP/junk banner) is rejected by socks5_greeting_probe."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def fake_non_socks() -> None:
            conn, _ = srv.accept()
            conn.recv(16)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            conn.close()
            srv.close()

        t = threading.Thread(target=fake_non_socks, daemon=True)
        t.start()
        res = socks5_greeting_probe("127.0.0.1", port, timeout=1.5)
        t.join(timeout=2.0)
        self.assertFalse(res["socks5_ready"])

    def test_local_socks5_relay_and_tls_validation_over_tunnel(self) -> None:
        """Spins up a local TLS target server AND a local RFC 1928 SOCKS5 proxy to test full relay."""
        certs = _generate_test_cert_files(self.tmpdir, dns_name="localhost", expired=False)

        # 1. Start local HTTPS server
        https_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        https_raw.bind(("127.0.0.1", 0))
        https_raw.listen(2)
        https_port = https_raw.getsockname()[1]

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(certs["cert"], certs["key"])

        def run_https_target() -> None:
            for _ in range(2):
                try:
                    conn, _ = https_raw.accept()
                    with server_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.recv(1024)
                        body = b"Example Domain via Local SOCKS5"
                        tls_conn.sendall(
                            b"HTTP/1.1 200 OK\r\n"
                            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                            + body
                        )
                except Exception:
                    pass
            https_raw.close()

        t_https = threading.Thread(target=run_https_target, daemon=True)
        t_https.start()

        # 2. Start local RFC 1928 SOCKS5 proxy forwarding to (target_host, target_port)
        socks_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socks_srv.bind(("127.0.0.1", 0))
        socks_srv.listen(2)
        socks_port = socks_srv.getsockname()[1]

        def handle_socks_client(client_sock: socket.socket) -> None:
            try:
                # Greeting
                hdr = client_sock.recv(3)
                if len(hdr) < 3 or hdr[0] != 0x05:
                    return
                client_sock.sendall(b"\x05\x00")
                # CONNECT request
                req_head = client_sock.recv(4)
                atyp = req_head[3]
                if atyp == 0x01:
                    dst_host = socket.inet_ntoa(client_sock.recv(4))
                elif atyp == 0x03:
                    dlen = client_sock.recv(1)[0]
                    dst_host = client_sock.recv(dlen).decode("ascii")
                    if dst_host == "localhost":
                        dst_host = "127.0.0.1"
                else:
                    return
                dst_port = struct.unpack("!H", client_sock.recv(2))[0]

                upstream = socket.create_connection((dst_host, dst_port), timeout=2.0)
                client_sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", dst_port))

                # Bidirectional relay
                def pipe(src: socket.socket, dst: socket.socket) -> None:
                    try:
                        while True:
                            data = src.recv(4096)
                            if not data:
                                break
                            dst.sendall(data)
                    except OSError:
                        pass
                    finally:
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass

                p1 = threading.Thread(target=pipe, args=(client_sock, upstream), daemon=True)
                p2 = threading.Thread(target=pipe, args=(upstream, client_sock), daemon=True)
                p1.start()
                p2.start()
                p1.join(timeout=2.0)
                p2.join(timeout=2.0)
                upstream.close()
            finally:
                client_sock.close()

        def run_socks_server() -> None:
            for _ in range(2):
                c, _ = socks_srv.accept()
                handle_socks_client(c)
            socks_srv.close()

        t_socks = threading.Thread(target=run_socks_server, daemon=True)
        t_socks.start()

        # Test A: Untrusted certificate over SOCKS5 MUST fail TLS verification!
        res_untrusted = probe_https_over_socks5(
            socks_host="127.0.0.1",
            socks_port=socks_port,
            target_host="localhost",
            target_port=https_port,
            expected_status=200,
            expected_substring="Example Domain",
            timeout=2.5,
        )
        self.assertFalse(res_untrusted["real_internet"])
        self.assertFalse(res_untrusted["tls_verified"])

        # Test B: Trusted CA certificate over SOCKS5 succeeds end-to-end!
        trusted_ctx = ssl.create_default_context(cafile=certs["cert"])
        with patch("core.protocols.ssh_engine._create_verified_ssl_context", return_value=trusted_ctx):
            res_trusted = probe_https_over_socks5(
                socks_host="127.0.0.1",
                socks_port=socks_port,
                target_host="localhost",
                target_port=https_port,
                expected_status=200,
                expected_substring="Example Domain",
                timeout=2.5,
            )
            self.assertTrue(res_trusted["tls_verified"])
            self.assertTrue(res_trusted["real_internet"])
            self.assertEqual(res_trusted["status_code"], 200)

        t_socks.join(timeout=2.0)
        t_https.join(timeout=2.0)

    def test_ssh_reconnect_and_safe_teardown(self) -> None:
        cfg = SshTunnelConfig(
            host="127.0.0.1",
            username="jaro",
            identity_file=str(self.id_file),
            known_hosts_file=str(self.kh_file),
            local_socks_port=19080,
            authorized=True,
        )
        tunnel = SshSocksTunnel(cfg)
        attempts = 0

        def simulated_start(startup_timeout_s: float = 7.0):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                return {"connected": False, "error": "Connection reset by peer"}
            return {"connected": True, "socks_port": 19080}

        reconnector = ExponentialBackoffReconnector(
            base_delay=0.1,
            max_attempts=3,
            jitter_ratio=0.0,
            sleep_fn=lambda _: None,
        )
        with patch.object(tunnel, "start", side_effect=simulated_start):
            outcome = tunnel.reconnect(reconnector=reconnector)
            self.assertTrue(outcome["connected"])
            self.assertEqual(outcome["attempts_used"], 2)
        tunnel.stop()


class TestWireGuardEngine(unittest.TestCase):
    """Tests WireGuard config security, global route protection, and handshake verification."""

    def setUp(self) -> None:
        self._tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmpdir_obj.name)
        self.priv = _valid_wg_b64_key(1)
        self.pub = _valid_wg_b64_key(2)

    def tearDown(self) -> None:
        self._tmpdir_obj.cleanup()

    def test_wireguard_blocks_unauthorized_global_route_modification(self) -> None:
        global_route_conf = (
            f"[Interface]\n"
            f"PrivateKey = {self.priv}\n"
            f"Address = 10.66.66.2/32\n\n"
            f"[Peer]\n"
            f"PublicKey = {self.pub}\n"
            f"Endpoint = 198.51.100.10:51820\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        )
        # Blocked by default when allow_global_routes=False
        blocked = validate_wireguard_config_text(global_route_conf, allow_global_routes=False)
        self.assertFalse(blocked["valid"])
        self.assertTrue(blocked["modifies_global_routes"])

        # Allowed only when explicitly authorized
        allowed = validate_wireguard_config_text(global_route_conf, allow_global_routes=True)
        self.assertTrue(allowed["valid"])

        # Split-tunnel subnet route works without modifying global default routes
        split_conf = global_route_conf.replace("0.0.0.0/0, ::/0", "10.66.66.0/24")
        split_ok = validate_wireguard_config_text(split_conf, allow_global_routes=False)
        self.assertTrue(split_ok["valid"])
        self.assertFalse(split_ok["modifies_global_routes"])

    def test_wireguard_rejects_postup_shell_hooks_and_bad_permissions(self) -> None:
        hook_conf = (
            f"[Interface]\n"
            f"PrivateKey = {self.priv}\n"
            f"Address = 10.66.66.2/32\n"
            f"PostUp = iptables -A FORWARD -j ACCEPT\n\n"
            f"[Peer]\n"
            f"PublicKey = {self.pub}\n"
            f"AllowedIPs = 10.66.66.0/24\n"
        )
        self.assertFalse(validate_wireguard_config_text(hook_conf)["valid"])

        conf_file = self.tmpdir / "wg0.conf"
        conf_file.write_text(
            hook_conf.replace("PostUp = iptables -A FORWARD -j ACCEPT\n", ""),
            encoding="utf-8",
        )
        os.chmod(conf_file, 0o644)
        bad_perm = validate_wireguard_config_file(conf_file, authorized=True)
        self.assertFalse(bad_perm["valid"])
        self.assertIn("Insecure permissions", bad_perm["error"] or "")

    def test_wg_dump_requires_fresh_cryptographic_handshake_and_rx_bytes(self) -> None:
        now = 1_700_000_500
        # Peer with 0 handshake epoch (never completed Noise_IKpsk2 handshake)
        unhandshaked_dump = (
            f"{self.priv}\t{self.pub}\t51820\toff\n"
            f"{self.pub}\t(none)\t198.51.100.10:51820\t10.66.66.0/24\t0\t0\t148\toff\n"
        )
        res_none = parse_wg_dump_output(unhandshaked_dump, now_epoch=now)
        self.assertFalse(res_none["handshake_verified"])

        # Peer with fresh handshake (30s ago) and received encrypted bytes
        fresh_dump = (
            f"{self.priv}\t{self.pub}\t51820\toff\n"
            f"{self.pub}\t(none)\t198.51.100.10:51820\t10.66.66.0/24\t{now - 30}\t4096\t2048\toff\n"
        )
        res_fresh = parse_wg_dump_output(fresh_dump, now_epoch=now)
        self.assertTrue(res_fresh["handshake_verified"])


class TestUnifiedTransportManager(unittest.TestCase):
    """Tests strict separation of DNS, Application Transport, and IP Tunnel planes."""

    def test_three_planes_strictly_separated_and_metered_guard_enforced(self) -> None:
        # 1. Metered cellular guard blocks unapproved mobile data probes
        with patch(
            "core.connection.transport_manager.detect_active_media",
            return_value=[{
                "name": "wwan0",
                "state": "UP",
                "addresses": ["10.99.1.5"],
                "medium": "cellular",
                "metered": True,
                "base_cost_tier": 2,
            }],
        ):
            tm_metered = TransportManager(allow_metered_probes=False, samples_per_check=1)
            rep_blocked = tm_metered.evaluate_planes()
            self.assertEqual(rep_blocked["status"], "ABORTED_METERED_GUARD")
            self.assertFalse(rep_blocked["real_internet_verified"])

        # 2. Normal evaluation separates dns_resolution, application_transport, and ip_tunnel
        with patch(
            "core.connection.transport_manager.detect_active_media",
            return_value=[{
                "name": "wlp2s0",
                "state": "UP",
                "addresses": ["192.168.1.20"],
                "medium": "wifi",
                "metered": False,
                "base_cost_tier": 0,
            }],
        ), patch.object(
            TransportManager,
            "_evaluate_wireguard_tunnels",
            return_value=[{
                "plane": "ip_tunnel",
                "tunnel_id": "wireguard-wg0-1",
                "interface": "wg0",
                "protocol": "wireguard",
                "available": False,
                "handshake_verified": False,
                "real_internet_verified": False,
                "score": 0.0,
            }],
        ), patch(
            "core.connection.multi_method_manager.MultiMethodManager.evaluate_all",
            return_value={
                "connectivity_state": ConnectivityState.REAL_INTERNET.value,
                "real_internet_verified": True,
                "dns_resolvers": [{
                    "category": "dns_service",
                    "server_id": "adguard-doq",
                    "server_name": "AdGuard",
                    "host": "94.140.14.14",
                    "protocol": "doq",
                    "port": 853,
                    "available": True,
                    "real_internet_verified": False,
                    "avg_latency_ms": 50.0,
                    "score": 96.0,
                }],
                "internet_transports": [{
                    "category": "internet_transport",
                    "server_id": "cloudflare-anycast",
                    "server_name": "Cloudflare",
                    "host": "1.1.1.1",
                    "protocol": "http3",
                    "port": 443,
                    "available": True,
                    "real_internet_verified": True,
                    "avg_latency_ms": 80.0,
                    "score": 97.5,
                }],
            },
        ):
            tm = TransportManager(samples_per_check=1)
            rep = tm.evaluate_planes()
            self.assertEqual(rep["status"], "OK")
            self.assertEqual(rep["selected"]["dns_resolver"]["plane"], "dns_resolution")
            self.assertFalse(rep["selected"]["dns_resolver"]["provides_general_internet"])
            self.assertEqual(rep["selected"]["application_transport"]["plane"], "application_transport")
            self.assertEqual(rep["selected"]["application_transport"]["protocol"], "http3")
            self.assertIsNone(rep["selected"]["ip_tunnel"])


if __name__ == "__main__":
    unittest.main()
