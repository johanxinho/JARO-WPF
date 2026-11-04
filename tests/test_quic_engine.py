"""Automated local QUIC & HTTP/3 server/client behavioral tests for JARO WPF Phase 2."""
import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import socket
import tempfile
import unittest
from typing import Any, Dict, Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, QuicEvent
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.protocols.quic_engine import (
    async_probe_quic_handshake,
    async_request_http3,
)


def _generate_test_cert_files(
    tmpdir: Path,
    dns_name: str = "localhost",
    expired: bool = False,
) -> Dict[str, str]:
    """Generates an ephemeral ECDSA P-256 X.509 certificate and key for local QUIC/HTTP3 testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])

    now = datetime.now(timezone.utc)
    if expired:
        valid_from = now - timedelta(days=10)
        valid_until = now - timedelta(days=1)
    else:
        valid_from = now - timedelta(hours=1)
        valid_until = now + timedelta(days=2)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(dns_name),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    prefix = "expired" if expired else "valid"
    cert_path = tmpdir / f"{prefix}_cert.pem"
    key_path = tmpdir / f"{prefix}_key.pem"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return {"cert": str(cert_path), "key": str(key_path)}


class LocalHttp3ServerProtocol(QuicConnectionProtocol):
    """Minimal real HTTP/3 server protocol for deterministic local loopback testing."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._req_paths: Dict[int, str] = {}
        self._req_methods: Dict[int, str] = {}
        self._req_bodies: Dict[int, bytearray] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            if event.alpn_protocol in H3_ALPN:
                self._h3 = H3Connection(self._quic)
            return

        if self._h3 is not None:
            for h3_event in self._h3.handle_event(event):
                self._handle_h3(h3_event)

    def _handle_h3(self, event: H3Event) -> None:
        assert self._h3 is not None
        if isinstance(event, HeadersReceived):
            hdr_map = {k.decode("latin1"): v.decode("latin1") for k, v in event.headers}
            self._req_paths[event.stream_id] = hdr_map.get(":path", "/")
            self._req_methods[event.stream_id] = hdr_map.get(":method", "GET")
            self._req_bodies.setdefault(event.stream_id, bytearray())
            if event.stream_ended:
                self._send_response(event.stream_id)
        elif isinstance(event, DataReceived):
            self._req_bodies.setdefault(event.stream_id, bytearray()).extend(event.data)
            if event.stream_ended:
                self._send_response(event.stream_id)

    def _send_response(self, stream_id: int) -> None:
        assert self._h3 is not None
        path = self._req_paths.pop(stream_id, "/")
        method = self._req_methods.pop(stream_id, "GET")
        req_body = bytes(self._req_bodies.pop(stream_id, bytearray()))

        if path == "/generate_204":
            self._h3.send_headers(
                stream_id=stream_id,
                headers=[(b":status", b"204"), (b"server", b"jaro-h3-test")],
                end_stream=True,
            )
        elif path == "/redirect":
            self._h3.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"302"),
                    (b"location", b"https://captive.local/login"),
                ],
                end_stream=True,
            )
        elif path == "/echo" and method == "POST":
            payload = b"ECHO:" + req_body
            self._h3.send_headers(
                stream_id=stream_id,
                headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
                end_stream=False,
            )
            self._h3.send_data(stream_id=stream_id, data=payload, end_stream=True)
        else:
            payload = b"JARO-WPF HTTP/3 VERIFIED OK"
            self._h3.send_headers(
                stream_id=stream_id,
                headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
                end_stream=False,
            )
            self._h3.send_data(stream_id=stream_id, data=payload, end_stream=True)
        self.transmit()


class TestQuicHttp3Engine(unittest.IsolatedAsyncioTestCase):
    """Tests generic QUIC handshake, HTTP/3 requests, TLS errors, and timeouts locally."""

    def setUp(self) -> None:
        self._tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmpdir_obj.name)
        self.valid_certs = _generate_test_cert_files(self.tmpdir, dns_name="localhost", expired=False)
        self.expired_certs = _generate_test_cert_files(self.tmpdir, dns_name="localhost", expired=True)

    def tearDown(self) -> None:
        self._tmpdir_obj.cleanup()

    async def _start_local_h3_server(self, cert_info: Dict[str, str], alpns: Optional[list[str]] = None):
        cfg = QuicConfiguration(
            is_client=False,
            alpn_protocols=alpns or list(H3_ALPN) + ["jaro-quic-v1"],
        )
        cfg.load_cert_chain(cert_info["cert"], cert_info["key"])
        server = await serve(
            host="127.0.0.1",
            port=0,
            configuration=cfg,
            create_protocol=LocalHttp3ServerProtocol,
        )
        port = server._transport.get_extra_info("sockname")[1]
        return server, port

    async def test_rejects_doq_alpn_in_generic_quic_engine(self) -> None:
        """Ensures generic QUIC engine strictly rejects DNS-over-QUIC ('doq') ALPN."""
        with self.assertRaises(ValueError):
            await async_probe_quic_handshake("127.0.0.1", port=443, alpn_protocols=["doq"])

    async def test_generic_quic_handshake_and_custom_alpn(self) -> None:
        server, port = await self._start_local_h3_server(self.valid_certs)
        try:
            res = await async_probe_quic_handshake(
                host="127.0.0.1",
                port=port,
                sni="localhost",
                alpn_protocols=["jaro-quic-v1"],
                cafile=self.valid_certs["cert"],
                timeout=2.5,
            )
            self.assertTrue(res["quic_connected"])
            self.assertTrue(res["tls_verified"])
            self.assertEqual(res["alpn_negotiated"], "jaro-quic-v1")
            self.assertIsNotNone(res["handshake_time_ms"])
            self.assertGreaterEqual(res["handshake_time_ms"], 0.0)
        finally:
            server.close()

    async def test_real_http3_get_200_post_and_204_telemetry(self) -> None:
        server, port = await self._start_local_h3_server(self.valid_certs)
        try:
            # 1. HTTP/3 GET 200 with payload verification
            res_get = await async_request_http3(
                url=f"https://localhost:{port}/status",
                connect_host="127.0.0.1",
                connect_port=port,
                sni_hostname="localhost",
                expected_status=200,
                expected_substring="JARO-WPF HTTP/3 VERIFIED OK",
                cafile=self.valid_certs["cert"],
                timeout=2.5,
            )
            self.assertTrue(res_get["quic_connected"])
            self.assertTrue(res_get["tls_verified"])
            self.assertTrue(res_get["http3_verified"])
            self.assertFalse(res_get["captive_portal_suspected"])
            self.assertEqual(res_get["status_code"], 200)
            self.assertIsNotNone(res_get["handshake_time_ms"])
            self.assertIsNotNone(res_get["response_time_ms"])
            self.assertIsNotNone(res_get["total_latency_ms"])

            # 2. HTTP/3 POST with request/response body
            res_post = await async_request_http3(
                url=f"https://localhost:{port}/echo",
                connect_host="127.0.0.1",
                connect_port=port,
                sni_hostname="localhost",
                method="POST",
                body=b"PING_PAYLOAD",
                expected_status=200,
                expected_substring="ECHO:PING_PAYLOAD",
                cafile=self.valid_certs["cert"],
                timeout=2.5,
            )
            self.assertTrue(res_post["http3_verified"])

            # 3. HTTP/3 204 No Content
            res_204 = await async_request_http3(
                url=f"https://localhost:{port}/generate_204",
                connect_host="127.0.0.1",
                connect_port=port,
                sni_hostname="localhost",
                expected_status=204,
                cafile=self.valid_certs["cert"],
                timeout=2.5,
            )
            self.assertTrue(res_204["http3_verified"])
            self.assertEqual(res_204["status_code"], 204)

            # 4. HTTP/3 302 Captive Portal detection
            res_redir = await async_request_http3(
                url=f"https://localhost:{port}/redirect",
                connect_host="127.0.0.1",
                connect_port=port,
                sni_hostname="localhost",
                expected_status=200,
                cafile=self.valid_certs["cert"],
                timeout=2.5,
            )
            self.assertFalse(res_redir["http3_verified"])
            self.assertTrue(res_redir["captive_portal_suspected"])
        finally:
            server.close()

    async def test_invalid_certificates_untrusted_wrong_sni_and_expired(self) -> None:
        # A. Untrusted self-signed cert (using default certifi store)
        server1, port1 = await self._start_local_h3_server(self.valid_certs)
        try:
            res_untrusted = await async_request_http3(
                url=f"https://localhost:{port1}/",
                connect_host="127.0.0.1",
                connect_port=port1,
                sni_hostname="localhost",
                timeout=2.0,
            )
            self.assertFalse(res_untrusted["quic_connected"])
            self.assertFalse(res_untrusted["tls_verified"])
            self.assertTrue(res_untrusted["tls_alert"])
            self.assertIn("TLSVerificationError", res_untrusted["error"] or "")

            # B. Wrong hostname/SNI against trusted CA
            res_wrong_sni = await async_request_http3(
                url=f"https://wrong.example.test:{port1}/",
                connect_host="127.0.0.1",
                connect_port=port1,
                sni_hostname="wrong.example.test",
                cafile=self.valid_certs["cert"],
                timeout=2.0,
            )
            self.assertFalse(res_wrong_sni["quic_connected"])
            self.assertFalse(res_wrong_sni["tls_verified"])
            self.assertTrue(res_wrong_sni["tls_alert"])
        finally:
            server1.close()

        # C. Expired certificate
        server2, port2 = await self._start_local_h3_server(self.expired_certs)
        try:
            res_expired = await async_probe_quic_handshake(
                host="127.0.0.1",
                port=port2,
                sni="localhost",
                cafile=self.expired_certs["cert"],
                timeout=2.0,
            )
            self.assertFalse(res_expired["quic_connected"])
            self.assertFalse(res_expired["tls_verified"])
            self.assertTrue(res_expired["tls_alert"])
        finally:
            server2.close()

    async def test_blackhole_udp_timeout_clean_closure(self) -> None:
        """Binds a silent UDP socket that drops packets and verifies clean TimeoutError."""
        silent_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent_sock.bind(("127.0.0.1", 0))
        port = silent_sock.getsockname()[1]
        try:
            res = await async_request_http3(
                url=f"https://localhost:{port}/",
                connect_host="127.0.0.1",
                connect_port=port,
                sni_hostname="localhost",
                cafile=self.valid_certs["cert"],
                timeout=0.4,
            )
            self.assertFalse(res["quic_connected"])
            self.assertFalse(res["http3_verified"])
            self.assertIn("TimeoutError", res["error"] or "")
        finally:
            silent_sock.close()


if __name__ == "__main__":
    unittest.main()
