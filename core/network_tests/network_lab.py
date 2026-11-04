"""JARO WPF - Connectivity Validation & Real Network Lab (Phase 4).

Implements two strictly separated validation suites with mandatory Section C traceability:
  A. Local Loopback Suite (`127.0.0.1`, 0 B external traffic):
     - Local QUIC handshake & HTTP/3 server/client (aioquic)
     - Local DoQ RFC 9250 server/client (aioquic)
     - Local UDP DNS, TCP DNS, and DoT RFC 7858 server/client
     - Local X.509 certificate validation matrix (valid CA chain, expired, untrusted self-signed, wrong SNI)
     - Local RFC 1928 SOCKS5 + TLS/HTTPS server relay (plus honest SKIPPED record if sshd is absent)
     - Local WireGuard configuration/route-safety validation (plus honest SKIPPED record if wg/authorized profile is absent)

  B. External Real Suite (strictly gated by CostManager & <= 64 KB suite byte cap):
     - Requires explicit authorization when active interface CostProfile is UNKNOWN or METERED.
     - Verifies endpoint protocol compatibility before declaring support.
     - Tests DNS UDP, DNS TCP, DoT, DoQ, general non-DNS HTTPS, HTTP/3, multi-sample latency/loss/stability,
       and bounded micro-download (<= 8 KB) + micro-upload (<= 4 KB).
     - Never invents free SSH or WireGuard servers (records SKIPPED_MISSING_PREREQUISITE when unconfigured).
"""
import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import ipaddress
import json
from pathlib import Path
import resource
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, QuicEvent, StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.connection.cost_manager import CostManager
from core.connection.network_monitor import NetworkMonitor
from core.network_tests.bandwidth_tester import BandwidthTester
from core.network_tests.connectivity_prober import (
    DEFAULT_SERVERS_CONFIG,
    probe_dot_dns,
    probe_https_egress,
    probe_tcp_dns,
    probe_tls_handshake,
    probe_udp_dns,
)
from core.protocols.doq_engine import DOQ_ALPN, async_probe_doq
from core.protocols.quic_engine import async_probe_quic_handshake, async_request_http3
from core.protocols.ssh_engine import (
    SshSocksTunnel,
    SshTunnelConfig,
    probe_https_over_socks5,
    socks5_greeting_probe,
)
from core.protocols.vpn_tunnel_engine import (
    WireGuardTunnelEngine,
    detect_wireguard_tooling,
    validate_wireguard_config_text,
)


class ExecutionScope(str, Enum):
    """Mandatory execution scopes distinguishing local, external, simulated, and skipped checks."""
    LOCAL_LOOPBACK = "LOCAL_LOOPBACK"
    EXTERNAL_REAL = "EXTERNAL_REAL"
    SIMULATED_FAULT_INJECTION = "SIMULATED_FAULT_INJECTION"
    SKIPPED_MISSING_PREREQUISITE = "SKIPPED_MISSING_PREREQUISITE"


@dataclass
class LabTestRecord:
    """Mandatory Section C audit record for every validation check."""
    test_id: str
    execution_scope: ExecutionScope
    server: str
    protocol: str
    timestamp_utc: str
    duration_ms: float
    bytes_estimated: int
    verified_real: bool
    result: str  # "PASS" | "FAIL" | "SKIPPED"
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.execution_scope, str):
            self.execution_scope = ExecutionScope(self.execution_scope)
        self.duration_ms = round(max(0.0, float(self.duration_ms)), 2)
        self.bytes_estimated = max(0, int(self.bytes_estimated))
        # Simulated or skipped checks can NEVER be marked verified_real=True
        if self.execution_scope in (
            ExecutionScope.SIMULATED_FAULT_INJECTION,
            ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
        ) or self.result != "PASS":
            self.verified_real = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "execution_scope": self.execution_scope.value,
            "server": self.server,
            "protocol": self.protocol,
            "timestamp_utc": self.timestamp_utc,
            "duration_ms": self.duration_ms,
            "bytes_estimated": self.bytes_estimated,
            "verified_real": self.verified_real,
            "result": self.result,
            "resultado": self.result,
            "reason": self.reason,
            "motivo": self.reason,
            "details": self.details,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def measure_process_resources() -> Dict[str, Any]:
    """Reads Linux /proc/self/status RSS/HWM memory and POSIX CPU user/system time."""
    vm_rss_kb: Optional[int] = None
    vm_hwm_kb: Optional[int] = None
    status_path = Path("/proc/self/status")
    if status_path.is_file():
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    vm_rss_kb = int(parts[1])
            elif line.startswith("VmHWM:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    vm_hwm_kb = int(parts[1])

    rusage = resource.getrusage(resource.RUSAGE_SELF)
    if vm_hwm_kb is None and rusage.ru_maxrss > 0:
        vm_hwm_kb = int(rusage.ru_maxrss)

    return {
        "vm_rss_kb": vm_rss_kb,
        "vm_rss_mb": round(vm_rss_kb / 1024.0, 2) if vm_rss_kb is not None else None,
        "vm_hwm_kb": vm_hwm_kb,
        "vm_hwm_mb": round(vm_hwm_kb / 1024.0, 2) if vm_hwm_kb is not None else None,
        "cpu_user_s": round(rusage.ru_utime, 4),
        "cpu_system_s": round(rusage.ru_stime, 4),
        "cpu_total_s": round(rusage.ru_utime + rusage.ru_stime, 4),
    }


def _generate_lab_pki(tmpdir: Path) -> Dict[str, Path]:
    """Generates an ephemeral local Root CA, valid leaf cert, expired leaf cert, and untrusted self-signed cert."""
    now = datetime.now(timezone.utc)

    # 1. Root CA
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "JARO WPF Local Lab Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=2))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    san_ext = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])

    # 2. Valid leaf signed by Root CA
    valid_key = ec.generate_private_key(ec.SECP256R1())
    valid_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    valid_cert = (
        x509.CertificateBuilder()
        .subject_name(valid_subject)
        .issuer_name(ca_subject)
        .public_key(valid_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(hours=24))
        .add_extension(san_ext, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # 3. Expired leaf signed by Root CA
    exp_key = ec.generate_private_key(ec.SECP256R1())
    exp_cert = (
        x509.CertificateBuilder()
        .subject_name(valid_subject)
        .issuer_name(ca_subject)
        .public_key(exp_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=48))
        .not_valid_after(now - timedelta(hours=24))
        .add_extension(san_ext, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # 4. Untrusted self-signed leaf (not signed by Root CA)
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_subject)
        .issuer_name(rogue_subject)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(hours=24))
        .add_extension(san_ext, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(rogue_key, hashes.SHA256())
    )

    def _write_pair(prefix: str, cert_obj: x509.Certificate, key_obj: ec.EllipticCurvePrivateKey) -> tuple[Path, Path]:
        c_path = tmpdir / f"{prefix}.pem"
        k_path = tmpdir / f"{prefix}.key"
        c_path.write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))
        k_path.write_bytes(
            key_obj.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        return c_path, k_path

    ca_pem = tmpdir / "ca.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    v_cert, v_key = _write_pair("valid_leaf", valid_cert, valid_key)
    e_cert, e_key = _write_pair("expired_leaf", exp_cert, exp_key)
    u_cert, u_key = _write_pair("untrusted_leaf", rogue_cert, rogue_key)

    return {
        "ca": ca_pem,
        "valid_cert": v_cert,
        "valid_key": v_key,
        "expired_cert": e_cert,
        "expired_key": e_key,
        "untrusted_cert": u_cert,
        "untrusted_key": u_key,
    }


def _build_dns_a_response(query: bytes, ip_str: str = "93.184.216.34") -> bytes:
    """Builds a minimal valid RFC 1035 DNS A response matching the query's TXID and question."""
    txid = query[:2]
    question = query[12:]
    header = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    # Name pointer 0xC00C, Type A (1), Class IN (1), TTL 60, RDLENGTH 4, IPv4 bytes
    answer = struct.pack("!HHHLH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip_str)
    return header + question + answer


class _LocalHttp3QuicServerProtocol(QuicConnectionProtocol):
    """Minimal local HTTP/3 + generic QUIC server on 127.0.0.1 for NetworkLab."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._req_headers: Dict[int, Dict[str, str]] = {}
        self._req_bodies: Dict[int, bytearray] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            if event.alpn_protocol in H3_ALPN:
                self._h3 = H3Connection(self._quic)
            return

        if self._h3 is None:
            return

        for h3_ev in self._h3.handle_event(event):
            if isinstance(h3_ev, HeadersReceived):
                hdr_map = {k.decode("utf-8", "replace"): v.decode("utf-8", "replace") for k, v in h3_ev.headers}
                self._req_headers[h3_ev.stream_id] = hdr_map
                self._req_bodies.setdefault(h3_ev.stream_id, bytearray())
                if h3_ev.stream_ended:
                    self._respond(h3_ev.stream_id)
            elif isinstance(h3_ev, DataReceived):
                self._req_bodies.setdefault(h3_ev.stream_id, bytearray()).extend(h3_ev.data)
                if h3_ev.stream_ended:
                    self._respond(h3_ev.stream_id)

    def _respond(self, stream_id: int) -> None:
        assert self._h3 is not None
        req_h = self._req_headers.pop(stream_id, {})
        req_b = bytes(self._req_bodies.pop(stream_id, bytearray()))
        path = req_h.get(":path", "/")
        method = req_h.get(":method", "GET")

        if path == "/generate_204":
            self._h3.send_headers(stream_id, [(b":status", b"204")], end_stream=True)
        elif method == "POST" and path == "/echo":
            payload = b"H3-ECHO:" + req_b
            self._h3.send_headers(
                stream_id,
                [(b":status", b"200"), (b"content-type", b"application/octet-stream")],
                end_stream=False,
            )
            self._h3.send_data(stream_id, payload, end_stream=True)
        else:
            payload = b"JARO-LOCAL-H3-OK"
            self._h3.send_headers(
                stream_id,
                [(b":status", b"200"), (b"content-type", b"text/plain")],
                end_stream=False,
            )
            self._h3.send_data(stream_id, payload, end_stream=True)
        self.transmit()


class _LocalDoQServerProtocol(QuicConnectionProtocol):
    """RFC 9250 compliant local DoQ test server verifying TXID=0 and 2-byte length framing."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._buffers: Dict[int, bytearray] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            buf = self._buffers.setdefault(event.stream_id, bytearray())
            buf.extend(event.data)
            if event.end_stream:
                raw = bytes(self._buffers.pop(event.stream_id))
                if len(raw) >= 14:
                    msg_len = struct.unpack("!H", raw[:2])[0]
                    dns_query = raw[2 : 2 + msg_len]
                    # RFC 9250 §4.2.1: TXID must be 0x0000
                    if len(dns_query) == msg_len and dns_query[:2] == b"\x00\x00":
                        dns_resp = _build_dns_a_response(dns_query)
                        framed_resp = struct.pack("!H", len(dns_resp)) + dns_resp
                        self._quic.send_stream_data(event.stream_id, framed_resp, end_stream=True)
                        self.transmit()


class NetworkLab:
    """Executes verifiable local and external connectivity lab suites with strict cost & byte controls."""

    def __init__(
        self,
        cost_manager: Optional[CostManager] = None,
        network_monitor: Optional[NetworkMonitor] = None,
        servers_config_path: Path = DEFAULT_SERVERS_CONFIG,
    ) -> None:
        self.cost_manager = cost_manager or CostManager()
        self.network_monitor = network_monitor or NetworkMonitor(cost_manager=self.cost_manager)
        self.servers_config_path = servers_config_path

    def _load_servers_catalog(self) -> Dict[str, Any]:
        if not self.servers_config_path.is_file():
            return {}
        with open(self.servers_config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    async def _run_local_quic_and_doq_checks(self, pki: Dict[str, Path]) -> List[LabTestRecord]:
        records: List[LabTestRecord] = []

        # 1 & 2: Local QUIC Handshake + HTTP/3 GET/POST Server on 127.0.0.1
        h3_srv_cfg = QuicConfiguration(
            is_client=False,
            alpn_protocols=list(H3_ALPN) + ["jaro-lab-v1"],
        )
        h3_srv_cfg.load_cert_chain(str(pki["valid_cert"]), str(pki["valid_key"]))

        h3_server = await serve(
            "127.0.0.1",
            0,
            configuration=h3_srv_cfg,
            create_protocol=_LocalHttp3QuicServerProtocol,
        )
        try:
            h3_port = int(h3_server._transport.get_extra_info("sockname")[1])  # type: ignore[attr-defined]

            t0 = time.perf_counter()
            q_hs = await async_probe_quic_handshake(
                host="127.0.0.1",
                port=h3_port,
                sni="localhost",
                alpn_protocols=["jaro-lab-v1"],
                cafile=str(pki["ca"]),
                timeout=2.5,
            )
            dur_q = (time.perf_counter() - t0) * 1000
            q_ok = bool(q_hs.get("quic_connected") and q_hs.get("tls_verified"))
            records.append(
                LabTestRecord(
                    test_id="local_quic_handshake",
                    execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                    server=f"127.0.0.1:{h3_port}",
                    protocol="quic",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur_q,
                    bytes_estimated=2400,
                    verified_real=q_ok,
                    result="PASS" if q_ok else "FAIL",
                    reason=q_hs.get("error"),
                    details={"alpn": q_hs.get("alpn_negotiated"), "handshake_ms": q_hs.get("handshake_time_ms")},
                )
            )

            t1 = time.perf_counter()
            h3_get = await async_request_http3(
                url=f"https://localhost:{h3_port}/health",
                connect_host="127.0.0.1",
                connect_port=h3_port,
                sni_hostname="localhost",
                expected_status=200,
                expected_substring="JARO-LOCAL-H3-OK",
                cafile=str(pki["ca"]),
                timeout=2.5,
            )
            h3_post = await async_request_http3(
                url=f"https://localhost:{h3_port}/echo",
                connect_host="127.0.0.1",
                connect_port=h3_port,
                sni_hostname="localhost",
                method="POST",
                body=b"PING",
                expected_status=200,
                expected_substring="H3-ECHO:PING",
                cafile=str(pki["ca"]),
                timeout=2.5,
            )
            dur_h3 = (time.perf_counter() - t1) * 1000
            h3_ok = bool(h3_get.get("http3_verified") and h3_post.get("http3_verified"))
            records.append(
                LabTestRecord(
                    test_id="local_http3_client_server",
                    execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                    server=f"127.0.0.1:{h3_port}",
                    protocol="http3",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur_h3,
                    bytes_estimated=4800,
                    verified_real=h3_ok,
                    result="PASS" if h3_ok else "FAIL",
                    reason=h3_get.get("error") or h3_post.get("error"),
                    details={
                        "get_status": h3_get.get("status_code"),
                        "post_status": h3_post.get("status_code"),
                        "total_latency_ms": h3_get.get("total_latency_ms"),
                    },
                )
            )
        finally:
            h3_server.close()

        # 3: Local DoQ RFC 9250 Server & Client on 127.0.0.1
        doq_srv_cfg = QuicConfiguration(is_client=False, alpn_protocols=list(DOQ_ALPN))
        doq_srv_cfg.load_cert_chain(str(pki["valid_cert"]), str(pki["valid_key"]))

        doq_server = await serve(
            "127.0.0.1",
            0,
            configuration=doq_srv_cfg,
            create_protocol=_LocalDoQServerProtocol,
        )
        try:
            doq_port = int(doq_server._transport.get_extra_info("sockname")[1])  # type: ignore[attr-defined]
            t2 = time.perf_counter()
            doq_res = await async_probe_doq(
                host="127.0.0.1",
                port=doq_port,
                sni="localhost",
                domain="example.com",
                timeout=2.5,
                cafile=str(pki["ca"]),
            )
            dur_doq = (time.perf_counter() - t2) * 1000
            doq_ok = bool(doq_res.get("protocol_verified") and doq_res.get("answers", 0) >= 1)
            records.append(
                LabTestRecord(
                    test_id="local_doq_rfc9250",
                    execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                    server=f"127.0.0.1:{doq_port}",
                    protocol="doq",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur_doq,
                    bytes_estimated=2200,
                    verified_real=doq_ok,
                    result="PASS" if doq_ok else "FAIL",
                    reason=doq_res.get("error"),
                    details={"answers": doq_res.get("answers"), "latency_ms": doq_res.get("latency_ms")},
                )
            )
        finally:
            doq_server.close()

        return records

    def _run_local_dns_checks(self, pki: Dict[str, Path], trusted_ctx: ssl.SSLContext) -> List[LabTestRecord]:
        records: List[LabTestRecord] = []

        # Local UDP DNS
        udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_srv.bind(("127.0.0.1", 0))
        udp_port = udp_srv.getsockname()[1]

        def serve_udp() -> None:
            try:
                udp_srv.settimeout(2.0)
                q, addr = udp_srv.recvfrom(2048)
                udp_srv.sendto(_build_dns_a_response(q), addr)
            except OSError:
                pass
            finally:
                udp_srv.close()

        t_u = threading.Thread(target=serve_udp, daemon=True)
        t_u.start()
        t0 = time.perf_counter()
        u_res = probe_udp_dns("127.0.0.1", port=udp_port, timeout=2.0)
        u_dur = (time.perf_counter() - t0) * 1000
        t_u.join(timeout=2.0)
        records.append(
            LabTestRecord(
                test_id="local_dns_udp",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{udp_port}",
                protocol="udp_dns",
                timestamp_utc=_utc_now(),
                duration_ms=u_dur,
                bytes_estimated=128,
                verified_real=bool(u_res["protocol_verified"]),
                result="PASS" if u_res["protocol_verified"] else "FAIL",
                reason=u_res.get("error"),
            )
        )

        # Local TCP DNS
        tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_srv.bind(("127.0.0.1", 0))
        tcp_srv.listen(1)
        tcp_port = tcp_srv.getsockname()[1]

        def serve_tcp() -> None:
            try:
                tcp_srv.settimeout(2.0)
                conn, _ = tcp_srv.accept()
                with conn:
                    qlen = struct.unpack("!H", conn.recv(2))[0]
                    q = conn.recv(qlen)
                    ans = _build_dns_a_response(q)
                    conn.sendall(struct.pack("!H", len(ans)) + ans)
            except OSError:
                pass
            finally:
                tcp_srv.close()

        t_t = threading.Thread(target=serve_tcp, daemon=True)
        t_t.start()
        t1 = time.perf_counter()
        t_res = probe_tcp_dns("127.0.0.1", port=tcp_port, timeout=2.0)
        t_dur = (time.perf_counter() - t1) * 1000
        t_t.join(timeout=2.0)
        records.append(
            LabTestRecord(
                test_id="local_dns_tcp",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{tcp_port}",
                protocol="tcp_dns",
                timestamp_utc=_utc_now(),
                duration_ms=t_dur,
                bytes_estimated=256,
                verified_real=bool(t_res["protocol_verified"]),
                result="PASS" if t_res["protocol_verified"] else "FAIL",
                reason=t_res.get("error"),
            )
        )

        # Local DoT RFC 7858
        dot_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dot_srv.bind(("127.0.0.1", 0))
        dot_srv.listen(1)
        dot_port = dot_srv.getsockname()[1]
        srv_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ssl.load_cert_chain(str(pki["valid_cert"]), str(pki["valid_key"]))

        def serve_dot() -> None:
            try:
                dot_srv.settimeout(2.0)
                conn, _ = dot_srv.accept()
                with srv_ssl.wrap_socket(conn, server_side=True) as tls_c:
                    qlen = struct.unpack("!H", tls_c.recv(2))[0]
                    q = tls_c.recv(qlen)
                    ans = _build_dns_a_response(q)
                    tls_c.sendall(struct.pack("!H", len(ans)) + ans)
            except Exception:
                pass
            finally:
                dot_srv.close()

        t_d = threading.Thread(target=serve_dot, daemon=True)
        t_d.start()
        t2 = time.perf_counter()
        d_res = probe_dot_dns("127.0.0.1", port=dot_port, sni="localhost", timeout=2.0, ssl_context=trusted_ctx)
        d_dur = (time.perf_counter() - t2) * 1000
        t_d.join(timeout=2.0)
        records.append(
            LabTestRecord(
                test_id="local_dot_rfc7858",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{dot_port}",
                protocol="dot",
                timestamp_utc=_utc_now(),
                duration_ms=d_dur,
                bytes_estimated=1800,
                verified_real=bool(d_res["protocol_verified"] and d_res["tls_verified"]),
                result="PASS" if (d_res["protocol_verified"] and d_res["tls_verified"]) else "FAIL",
                reason=d_res.get("error"),
            )
        )

        return records

    def _run_local_certificate_matrix(self, pki: Dict[str, Path], trusted_ctx: ssl.SSLContext) -> List[LabTestRecord]:
        records: List[LabTestRecord] = []

        def _spawn_tls_server(cert_file: Path, key_file: Path, send_http: bool = False) -> tuple[int, threading.Thread]:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert_file), str(key_file))

            def worker() -> None:
                try:
                    srv.settimeout(2.0)
                    conn, _ = srv.accept()
                    with ctx.wrap_socket(conn, server_side=True) as tls_c:
                        if send_http:
                            tls_c.recv(1024)
                            body = b"Example Domain Local Valid Cert"
                            tls_c.sendall(
                                b"HTTP/1.1 200 OK\r\n"
                                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                                + body
                            )
                except Exception:
                    pass
                finally:
                    srv.close()

            th = threading.Thread(target=worker, daemon=True)
            th.start()
            return port, th

        # Case 1: Valid CA-signed leaf + matching SNI -> accepted
        p_valid, th_valid = _spawn_tls_server(pki["valid_cert"], pki["valid_key"], send_http=True)
        t0 = time.perf_counter()
        r_valid = probe_https_egress(
            url=f"https://localhost:{p_valid}/",
            connect_host="127.0.0.1",
            sni_hostname="localhost",
            expected_status=200,
            expected_substring="Example Domain Local Valid Cert",
            timeout=2.0,
            ssl_context=trusted_ctx,
        )
        d0 = (time.perf_counter() - t0) * 1000
        th_valid.join(timeout=2.0)
        ok_valid = bool(r_valid["real_internet"] and r_valid["tls_verified"])
        records.append(
            LabTestRecord(
                test_id="local_cert_valid_chain",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{p_valid}",
                protocol="https_x509",
                timestamp_utc=_utc_now(),
                duration_ms=d0,
                bytes_estimated=2200,
                verified_real=ok_valid,
                result="PASS" if ok_valid else "FAIL",
                reason=r_valid.get("error"),
            )
        )

        # Case 2: Expired certificate -> strictly rejected
        p_exp, th_exp = _spawn_tls_server(pki["expired_cert"], pki["expired_key"])
        t1 = time.perf_counter()
        r_exp = probe_tls_handshake("127.0.0.1", port=p_exp, sni="localhost", timeout=2.0, ssl_context=trusted_ctx)
        d1 = (time.perf_counter() - t1) * 1000
        th_exp.join(timeout=2.0)
        rejected_exp = bool(r_exp["socket_ok"] and not r_exp["server_verified"])
        records.append(
            LabTestRecord(
                test_id="local_cert_expired_rejected",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{p_exp}",
                protocol="tls_x509",
                timestamp_utc=_utc_now(),
                duration_ms=d1,
                bytes_estimated=1400,
                verified_real=rejected_exp,
                result="PASS" if rejected_exp else "FAIL",
                reason=None if rejected_exp else "Expired certificate was not rejected!",
                details={"rejection_error": r_exp.get("error")},
            )
        )

        # Case 3: Untrusted self-signed certificate -> strictly rejected
        p_unt, th_unt = _spawn_tls_server(pki["untrusted_cert"], pki["untrusted_key"])
        t2 = time.perf_counter()
        r_unt = probe_tls_handshake("127.0.0.1", port=p_unt, sni="localhost", timeout=2.0, ssl_context=trusted_ctx)
        d2 = (time.perf_counter() - t2) * 1000
        th_unt.join(timeout=2.0)
        rejected_unt = bool(r_unt["socket_ok"] and not r_unt["server_verified"])
        records.append(
            LabTestRecord(
                test_id="local_cert_untrusted_rejected",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{p_unt}",
                protocol="tls_x509",
                timestamp_utc=_utc_now(),
                duration_ms=d2,
                bytes_estimated=1400,
                verified_real=rejected_unt,
                result="PASS" if rejected_unt else "FAIL",
                reason=None if rejected_unt else "Untrusted self-signed certificate was not rejected!",
                details={"rejection_error": r_unt.get("error")},
            )
        )

        # Case 4: Wrong SNI / SAN mismatch -> strictly rejected
        p_sni, th_sni = _spawn_tls_server(pki["valid_cert"], pki["valid_key"])
        t3 = time.perf_counter()
        r_sni = probe_tls_handshake(
            "127.0.0.1",
            port=p_sni,
            sni="mismatch.jaro.internal",
            timeout=2.0,
            ssl_context=trusted_ctx,
        )
        d3 = (time.perf_counter() - t3) * 1000
        th_sni.join(timeout=2.0)
        rejected_sni = bool(r_sni["socket_ok"] and not r_sni["server_verified"])
        records.append(
            LabTestRecord(
                test_id="local_cert_wrong_sni_rejected",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{p_sni}",
                protocol="tls_x509",
                timestamp_utc=_utc_now(),
                duration_ms=d3,
                bytes_estimated=1400,
                verified_real=rejected_sni,
                result="PASS" if rejected_sni else "FAIL",
                reason=None if rejected_sni else "Mismatched SNI certificate was not rejected!",
                details={"rejection_error": r_sni.get("error")},
            )
        )

        return records

    def _run_local_socks5_and_ssh_checks(self, pki: Dict[str, Path], trusted_ctx: ssl.SSLContext) -> List[LabTestRecord]:
        records: List[LabTestRecord] = []

        # 1. Local RFC 1928 SOCKS5 server + local TLS/HTTPS server relay on 127.0.0.1
        https_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        https_srv.bind(("127.0.0.1", 0))
        https_srv.listen(2)
        https_port = https_srv.getsockname()[1]

        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.load_cert_chain(str(pki["valid_cert"]), str(pki["valid_key"]))

        def https_worker() -> None:
            try:
                https_srv.settimeout(2.5)
                conn, _ = https_srv.accept()
                with srv_ctx.wrap_socket(conn, server_side=True) as tls_c:
                    tls_c.recv(1024)
                    body = b"Example Domain via Local SOCKS5 Lab"
                    tls_c.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                        + body
                    )
            except Exception:
                pass
            finally:
                https_srv.close()

        socks_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socks_srv.bind(("127.0.0.1", 0))
        socks_srv.listen(3)
        socks_port = socks_srv.getsockname()[1]

        def socks_worker() -> None:
            try:
                for _ in range(2):
                    socks_srv.settimeout(2.5)
                    c_sock, _ = socks_srv.accept()
                    try:
                        hdr = c_sock.recv(3)
                        if len(hdr) < 3 or hdr[0] != 0x05:
                            c_sock.close()
                            continue
                        c_sock.sendall(b"\x05\x00")
                        req_h = c_sock.recv(4)
                        if not req_h:
                            # Greeting-only probe
                            c_sock.close()
                            continue
                        atyp = req_h[3]
                        if atyp == 0x01:
                            dst_h = socket.inet_ntoa(c_sock.recv(4))
                        elif atyp == 0x03:
                            ln = c_sock.recv(1)[0]
                            dst_h = c_sock.recv(ln).decode("ascii")
                            if dst_h == "localhost":
                                dst_h = "127.0.0.1"
                        else:
                            c_sock.close()
                            continue
                        dst_p = struct.unpack("!H", c_sock.recv(2))[0]
                        up = socket.create_connection((dst_h, dst_p), timeout=2.0)
                        c_sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", dst_p))

                        def relay(src: socket.socket, dst: socket.socket) -> None:
                            try:
                                while True:
                                    chunk = src.recv(4096)
                                    if not chunk:
                                        break
                                    dst.sendall(chunk)
                            except OSError:
                                pass
                            finally:
                                try:
                                    dst.shutdown(socket.SHUT_WR)
                                except OSError:
                                    pass

                        r1 = threading.Thread(target=relay, args=(c_sock, up), daemon=True)
                        r2 = threading.Thread(target=relay, args=(up, c_sock), daemon=True)
                        r1.start()
                        r2.start()
                        r1.join(timeout=2.0)
                        r2.join(timeout=2.0)
                        up.close()
                    finally:
                        c_sock.close()
            except OSError:
                pass
            finally:
                socks_srv.close()

        th_h = threading.Thread(target=https_worker, daemon=True)
        th_s = threading.Thread(target=socks_worker, daemon=True)
        th_h.start()
        th_s.start()

        t0 = time.perf_counter()
        greet = socks5_greeting_probe("127.0.0.1", socks_port, timeout=2.0)
        egress = probe_https_over_socks5(
            socks_host="127.0.0.1",
            socks_port=socks_port,
            target_host="localhost",
            target_port=https_port,
            expected_status=200,
            expected_substring="Example Domain via Local SOCKS5 Lab",
            timeout=2.5,
            ssl_context=trusted_ctx,
        )
        dur = (time.perf_counter() - t0) * 1000
        th_s.join(timeout=2.5)
        th_h.join(timeout=2.5)

        relay_ok = bool(greet["socks5_ready"] and egress["real_internet"] and egress["tls_verified"])
        records.append(
            LabTestRecord(
                test_id="local_socks5_https_relay",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=f"127.0.0.1:{socks_port}",
                protocol="socks5_https",
                timestamp_utc=_utc_now(),
                duration_ms=dur,
                bytes_estimated=int(egress.get("bytes_estimated", 2400)) + 64,
                verified_real=relay_ok,
                result="PASS" if relay_ok else "FAIL",
                reason=egress.get("error") or greet.get("error"),
                details={"target_https_port": https_port, "status_code": egress.get("status_code")},
            )
        )

        # 2. Local OpenSSH sshd daemon check (never fake or invent sshd if absent!)
        sshd_bin = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").is_file() else None)
        if not sshd_bin:
            records.append(
                LabTestRecord(
                    test_id="local_openssh_sshd_daemon",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server="127.0.0.1:22",
                    protocol="ssh_socks5",
                    timestamp_utc=_utc_now(),
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=(
                        "OpenSSH server binary ('sshd') is not installed on host; "
                        "RFC 1928 SOCKS5 + TLS/HTTPS stream relay verified locally in local_socks5_https_relay"
                    ),
                )
            )
        else:
            from core.network_tests.local_tunnel_labs import LocalOpenSshLoopbackLab

            t_sshd = time.perf_counter()
            sshd_lab = LocalOpenSshLoopbackLab().run()
            dur_sshd = (time.perf_counter() - t_sshd) * 1000
            sshd_ok = sshd_lab.get("status") == "LOCAL_VERIFIED"
            records.append(
                LabTestRecord(
                    test_id="local_openssh_sshd_daemon",
                    execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                    server="127.0.0.1 (ephemeral sshd)",
                    protocol="ssh_socks5",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur_sshd,
                    bytes_estimated=int(sshd_lab.get("loopback_bytes_estimated", 0)),
                    verified_real=sshd_ok,
                    result="PASS" if sshd_ok else "FAIL",
                    reason=None if sshd_ok else f"Local OpenSSH lab status: {sshd_lab.get('status')}",
                    details={
                        "subtests": sshd_lab.get("counts"),
                        "remote_ssh_status": sshd_lab.get("remote_ssh_status"),
                    },
                )
            )

        return records

    def _run_local_wireguard_checks(self) -> List[LabTestRecord]:
        records: List[LabTestRecord] = []

        # 1. Local cryptographic key & route-safety validator check
        t0 = time.perf_counter()
        priv = base64.b64encode(b"\x11" * 32).decode("ascii")
        pub = base64.b64encode(b"\x22" * 32).decode("ascii")
        split_conf = (
            f"[Interface]\nPrivateKey = {priv}\nAddress = 10.77.0.2/32\n\n"
            f"[Peer]\nPublicKey = {pub}\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 10.77.0.0/24\n"
        )
        global_conf = split_conf.replace("10.77.0.0/24", "0.0.0.0/0")
        ok_split = validate_wireguard_config_text(split_conf, allow_global_routes=False)
        blocked_global = validate_wireguard_config_text(global_conf, allow_global_routes=False)
        dur = (time.perf_counter() - t0) * 1000
        validator_ok = bool(ok_split["valid"] and not blocked_global["valid"])
        records.append(
            LabTestRecord(
                test_id="local_wireguard_config_validator",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server="local-validator",
                protocol="wireguard_config",
                timestamp_utc=_utc_now(),
                duration_ms=dur,
                bytes_estimated=0,
                verified_real=validator_ok,
                result="PASS" if validator_ok else "FAIL",
                reason=None if validator_ok else "WireGuard validator failed split/global route invariant",
            )
        )

        # 2. Live WireGuard tunnel inspection (only when authorized configuration + wg tools exist)
        catalog = self._load_servers_catalog()
        auth_wg = [w for w in catalog.get("authorized_wireguard_tunnels", []) if w.get("authorized")]
        tools = detect_wireguard_tooling()

        if not auth_wg or not tools["cli_ready"]:
            missing_parts = []
            if not tools["cli_ready"]:
                missing_parts.append("WireGuard CLI binaries ('wg'/'wg-quick') not installed")
            if not auth_wg:
                missing_parts.append("no authorized WireGuard profile in configs/servers.json")
            records.append(
                LabTestRecord(
                    test_id="local_wireguard_live_tunnel",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server="wg0",
                    protocol="wireguard",
                    timestamp_utc=_utc_now(),
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason="; ".join(missing_parts),
                    details={"tooling": tools},
                )
            )
        else:
            item = auth_wg[0]
            t1 = time.perf_counter()
            eng = WireGuardTunnelEngine(
                interface_name=item.get("interface", "wg0"),
                config_path=item.get("config_path"),
                authorized=True,
                allow_global_routes=False,
            )
            st = eng.inspect_state(verify_internet_egress=True)
            dur_wg = (time.perf_counter() - t1) * 1000
            wg_ok = bool(st["handshake_verified"] and st["https_egress_verified"])
            records.append(
                LabTestRecord(
                    test_id="local_wireguard_live_tunnel",
                    execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                    server=eng.interface_name,
                    protocol="wireguard",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur_wg,
                    bytes_estimated=int(st.get("bytes_estimated", 0)),
                    verified_real=wg_ok,
                    result="PASS" if wg_ok else "FAIL",
                    reason=st.get("note"),
                )
            )

        return records

    def run_local_lab_suite(self) -> Dict[str, Any]:
        """Executes the complete local loopback validation lab with 0 B external traffic."""
        suite_start = time.perf_counter()
        res_before = measure_process_resources()
        records: List[LabTestRecord] = []

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            pki = _generate_lab_pki(tmpdir)
            trusted_ctx = ssl.create_default_context(cafile=str(pki["ca"]))
            trusted_ctx.check_hostname = True
            trusted_ctx.verify_mode = ssl.CERT_REQUIRED

            records.extend(asyncio.run(self._run_local_quic_and_doq_checks(pki)))
            records.extend(self._run_local_dns_checks(pki, trusted_ctx))
            records.extend(self._run_local_certificate_matrix(pki, trusted_ctx))
            records.extend(self._run_local_socks5_and_ssh_checks(pki, trusted_ctx))
            records.extend(self._run_local_wireguard_checks())

        res_after = measure_process_resources()
        total_ms = round((time.perf_counter() - suite_start) * 1000, 2)
        return self._summarize_suite(
            suite_name="LOCAL_NETWORK_LAB",
            records=records,
            duration_ms=total_ms,
            external_bytes_consumed=0,
            resources_before=res_before,
            resources_after=res_after,
            cost_gate={"allowed": True, "effective_profile": "loopback_free", "reason": None},
        )

    def run_external_lab_suite(
        self,
        authorize_unknown_cost: Optional[bool] = None,
        authorize_metered_cost: Optional[bool] = None,
        max_suite_bytes: int = 65536,
    ) -> Dict[str, Any]:
        """Executes real external validation checks ONLY when CostManager policy authorizes them.

        Enforces strict authorization when cost profile is UNKNOWN or METERED, and caps total
        external transfer to max_suite_bytes (default 64 KB).
        """
        suite_start = time.perf_counter()
        res_before = measure_process_resources()
        bytes_before = self.cost_manager.bytes_consumed_total
        records: List[LabTestRecord] = []

        net_scan = self.network_monitor.scan_interfaces()
        active_ifaces = net_scan["active_interfaces"]
        gate = self.cost_manager.evaluate_external_lab_gate(
            active_ifaces,
            authorize_unknown=authorize_unknown_cost,
            authorize_metered=authorize_metered_cost,
        )

        planned_external_specs = [
            ("external_dns_udp", "1.1.1.1:53", "udp_dns"),
            ("external_dns_tcp", "1.1.1.1:53", "tcp_dns"),
            ("external_dot_rfc7858", "1.1.1.1:853", "dot"),
            ("external_doq_rfc9250", "94.140.14.14:853", "doq"),
            ("external_https_general_web", "example.com:443", "https"),
            ("external_http3_quic", "1.1.1.1:443", "http3"),
            ("external_latency_loss_stability", "1.1.1.1:443", "https_quality"),
            ("external_micro_download", "speed.cloudflare.com:443", "https_download"),
            ("external_micro_upload", "speed.cloudflare.com:443", "https_upload"),
        ]

        if not gate["allowed"]:
            for tid, srv, proto in planned_external_specs:
                records.append(
                    LabTestRecord(
                        test_id=tid,
                        execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                        server=srv,
                        protocol=proto,
                        timestamp_utc=_utc_now(),
                        duration_ms=0.0,
                        bytes_estimated=0,
                        verified_real=False,
                        result="SKIPPED",
                        reason=gate["reason"],
                        details={"effective_cost_profile": gate["effective_profile"]},
                    )
                )
            records.extend(self._check_external_authorized_tunnels(execute_live=False, skip_reason=gate["reason"]))
            res_after = measure_process_resources()
            return self._summarize_suite(
                suite_name="EXTERNAL_NETWORK_LAB",
                records=records,
                duration_ms=round((time.perf_counter() - suite_start) * 1000, 2),
                external_bytes_consumed=0,
                resources_before=res_before,
                resources_after=res_after,
                cost_gate=gate,
            )

        suite_bytes_used = 0
        primary_ifname = active_ifaces[0]["name"] if active_ifaces else None

        def _can_spend(est_bytes: int) -> tuple[bool, Optional[str]]:
            if suite_bytes_used + est_bytes > max_suite_bytes:
                return False, f"External lab cap ({max_suite_bytes} B) reached (used {suite_bytes_used} B)"
            b_check = self.cost_manager.check_budget_for_transfer(est_bytes)
            if not b_check["allowed"]:
                return False, b_check["reason"]
            return True, None

        def _spend(actual_bytes: int) -> None:
            nonlocal suite_bytes_used
            delta = max(0, int(actual_bytes))
            suite_bytes_used += delta
            self.cost_manager.record_consumption(delta, ifname=primary_ifname)

        # 1. External UDP DNS (1.1.1.1:53)
        ok_b, b_err = _can_spend(180)
        if ok_b:
            t0 = time.perf_counter()
            r_udp = probe_udp_dns("1.1.1.1", 53, domain="example.com", timeout=3.0)
            dur = (time.perf_counter() - t0) * 1000
            _spend(180)
            records.append(
                LabTestRecord(
                    test_id="external_dns_udp",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server="1.1.1.1:53",
                    protocol="udp_dns",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=180,
                    verified_real=bool(r_udp["protocol_verified"]),
                    result="PASS" if r_udp["protocol_verified"] else "FAIL",
                    reason=r_udp.get("error"),
                    details={"latency_ms": r_udp.get("latency_ms"), "answers": r_udp.get("answers")},
                )
            )
        else:
            records.append(self._skipped_budget("external_dns_udp", "1.1.1.1:53", "udp_dns", b_err))

        # 2. External TCP DNS (1.1.1.1:53)
        ok_b, b_err = _can_spend(320)
        if ok_b:
            t0 = time.perf_counter()
            r_tcp = probe_tcp_dns("1.1.1.1", 53, domain="example.com", timeout=3.5)
            dur = (time.perf_counter() - t0) * 1000
            _spend(320)
            records.append(
                LabTestRecord(
                    test_id="external_dns_tcp",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server="1.1.1.1:53",
                    protocol="tcp_dns",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=320,
                    verified_real=bool(r_tcp["protocol_verified"]),
                    result="PASS" if r_tcp["protocol_verified"] else "FAIL",
                    reason=r_tcp.get("error"),
                    details={"latency_ms": r_tcp.get("latency_ms"), "answers": r_tcp.get("answers")},
                )
            )
        else:
            records.append(self._skipped_budget("external_dns_tcp", "1.1.1.1:53", "tcp_dns", b_err))

        # 3. External DoT RFC 7858 (1.1.1.1:853, SNI one.one.one.one)
        ok_b, b_err = _can_spend(2400)
        if ok_b:
            t0 = time.perf_counter()
            r_dot = probe_dot_dns("1.1.1.1", 853, sni="one.one.one.one", domain="example.com", timeout=4.0)
            dur = (time.perf_counter() - t0) * 1000
            _spend(2400)
            dot_ok = bool(r_dot["protocol_verified"] and r_dot["tls_verified"])
            records.append(
                LabTestRecord(
                    test_id="external_dot_rfc7858",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server="1.1.1.1:853",
                    protocol="dot",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=2400,
                    verified_real=dot_ok,
                    result="PASS" if dot_ok else "FAIL",
                    reason=r_dot.get("error"),
                    details={"sni": "one.one.one.one", "latency_ms": r_dot.get("latency_ms")},
                )
            )
        else:
            records.append(self._skipped_budget("external_dot_rfc7858", "1.1.1.1:853", "dot", b_err))

        # 4. External DoQ RFC 9250 (AdGuard 94.140.14.14:853, SNI dns.adguard-dns.com)
        ok_b, b_err = _can_spend(2600)
        if ok_b:
            t0 = time.perf_counter()
            r_doq = asyncio.run(
                async_probe_doq(
                    host="94.140.14.14",
                    port=853,
                    sni="dns.adguard-dns.com",
                    domain="example.com",
                    timeout=4.0,
                )
            )
            dur = (time.perf_counter() - t0) * 1000
            _spend(2600)
            doq_ok = bool(r_doq["protocol_verified"] and r_doq["quic_connected"])
            records.append(
                LabTestRecord(
                    test_id="external_doq_rfc9250",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server="94.140.14.14:853",
                    protocol="doq",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=2600,
                    verified_real=doq_ok,
                    result="PASS" if doq_ok else "FAIL",
                    reason=r_doq.get("error"),
                    details={"sni": "dns.adguard-dns.com", "latency_ms": r_doq.get("latency_ms")},
                )
            )
        else:
            records.append(self._skipped_budget("external_doq_rfc9250", "94.140.14.14:853", "doq", b_err))

        # 5. External General Non-DNS Web HTTPS (example.com & connectivitycheck.gstatic.com)
        ok_b, b_err = _can_spend(4500)
        if ok_b:
            t0 = time.perf_counter()
            r_ex = probe_https_egress(
                url="https://example.com/",
                expected_status=200,
                expected_substring="Example Domain",
                timeout=4.5,
            )
            r_gs = probe_https_egress(
                url="https://connectivitycheck.gstatic.com/generate_204",
                expected_status=204,
                expected_substring="",
                timeout=4.0,
            )
            dur = (time.perf_counter() - t0) * 1000
            b_est = int(r_ex.get("bytes_estimated", 2500)) + int(r_gs.get("bytes_estimated", 2000))
            _spend(b_est)
            https_ok = bool(r_ex["real_internet"] or r_gs["real_internet"])
            records.append(
                LabTestRecord(
                    test_id="external_https_general_web",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server="example.com / connectivitycheck.gstatic.com",
                    protocol="https",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=b_est,
                    verified_real=https_ok,
                    result="PASS" if https_ok else "FAIL",
                    reason=None if https_ok else (r_ex.get("error") or r_gs.get("error")),
                    details={
                        "example_com_ok": r_ex["real_internet"],
                        "example_com_latency_ms": r_ex.get("latency_ms"),
                        "gstatic_204_ok": r_gs["real_internet"],
                        "gstatic_latency_ms": r_gs.get("latency_ms"),
                    },
                )
            )
        else:
            records.append(self._skipped_budget("external_https_general_web", "example.com:443", "https", b_err))

        # 6. External HTTP/3 over QUIC (Cloudflare 1.1.1.1:443/UDP)
        ok_b, b_err = _can_spend(3200)
        if ok_b:
            t0 = time.perf_counter()
            r_h3 = asyncio.run(
                async_request_http3(
                    url="https://one.one.one.one/cdn-cgi/trace",
                    connect_host="1.1.1.1",
                    connect_port=443,
                    sni_hostname="one.one.one.one",
                    expected_status=200,
                    expected_substring="fl=",
                    timeout=4.5,
                )
            )
            dur = (time.perf_counter() - t0) * 1000
            b_h3 = int(r_h3.get("response_bytes", 0)) + 2400
            _spend(b_h3)
            h3_ok = bool(r_h3["http3_verified"] and r_h3["tls_verified"])
            records.append(
                LabTestRecord(
                    test_id="external_http3_quic",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server="1.1.1.1:443 (one.one.one.one)",
                    protocol="http3",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=b_h3,
                    verified_real=h3_ok,
                    result="PASS" if h3_ok else "FAIL",
                    reason=r_h3.get("error"),
                    details={
                        "handshake_time_ms": r_h3.get("handshake_time_ms"),
                        "response_time_ms": r_h3.get("response_time_ms"),
                        "total_latency_ms": r_h3.get("total_latency_ms"),
                    },
                )
            )
        else:
            records.append(self._skipped_budget("external_http3_quic", "1.1.1.1:443", "http3", b_err))

        # 7. Multi-sample Latency, Jitter, Packet Loss & Stability (4 lightweight UDP DNS + HTTPS samples)
        bw_tester = BandwidthTester(cost_manager=self.cost_manager)
        if suite_bytes_used + 8000 <= max_suite_bytes:
            t0 = time.perf_counter()

            def _light_sample() -> Dict[str, Any]:
                s_res = probe_https_egress(
                    url="https://one.one.one.one/cdn-cgi/trace",
                    connect_host="1.1.1.1",
                    sni_hostname="one.one.one.one",
                    expected_status=200,
                    expected_substring="fl=",
                    timeout=3.5,
                )
                return {
                    "verified": bool(s_res["real_internet"]),
                    "latency_ms": s_res.get("latency_ms"),
                    "bytes_transferred": int(s_res.get("bytes_estimated", 1800)),
                    "error": s_res.get("error"),
                }

            qual = bw_tester.measure_quality_samples(
                probe_fn=_light_sample,
                samples=4,
                estimated_bytes_per_sample=2000,
                interface_name=primary_ifname,
            )
            dur = (time.perf_counter() - t0) * 1000
            q_bytes = int(qual.get("bytes_consumed", 0))
            suite_bytes_used += q_bytes
            q_ok = bool(qual.get("allowed") and qual.get("samples_received", 0) > 0)
            records.append(
                LabTestRecord(
                    test_id="external_latency_loss_stability",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server="1.1.1.1:443 (one.one.one.one)",
                    protocol="https_stability",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=q_bytes,
                    verified_real=q_ok,
                    result="PASS" if q_ok else "FAIL",
                    reason=qual.get("error"),
                    details={
                        "samples_sent": qual.get("samples_sent"),
                        "samples_received": qual.get("samples_received"),
                        "avg_latency_ms": qual.get("avg_latency_ms"),
                        "jitter_ms": qual.get("jitter_ms"),
                        "packet_loss_pct": qual.get("packet_loss_pct"),
                        "stability_ratio": qual.get("stability_ratio"),
                    },
                )
            )
        else:
            records.append(
                self._skipped_budget(
                    "external_latency_loss_stability",
                    "1.1.1.1:443",
                    "https_stability",
                    "External lab suite byte cap reached",
                )
            )

        # 8 & 9. Bounded Micro-Download (8 KB) & Micro-Upload (4 KB) on authorized speed.cloudflare.com
        # Verify endpoint TLS compatibility first before declaring support!
        compat = probe_tls_handshake("speed.cloudflare.com", 443, sni="speed.cloudflare.com", timeout=4.0)
        _spend(1800)
        if not compat["server_verified"]:
            for tid, proto in (("external_micro_download", "https_download"), ("external_micro_upload", "https_upload")):
                records.append(
                    LabTestRecord(
                        test_id=tid,
                        execution_scope=ExecutionScope.EXTERNAL_REAL,
                        server="speed.cloudflare.com:443",
                        protocol=proto,
                        timestamp_utc=_utc_now(),
                        duration_ms=0.0,
                        bytes_estimated=900,
                        verified_real=False,
                        result="FAIL",
                        reason=f"Endpoint TLS compatibility check failed: {compat.get('error')}",
                    )
                )
        else:
            # Micro-download capped strictly at 8,192 B
            if suite_bytes_used + 9500 <= max_suite_bytes:
                t0 = time.perf_counter()
                dl = bw_tester.measure_download_speed(
                    url="https://speed.cloudflare.com/__down?bytes=8192",
                    sni_hostname="speed.cloudflare.com",
                    authorized=True,
                    max_bytes=8192,
                    timeout=5.0,
                    interface_name=primary_ifname,
                )
                dur_dl = (time.perf_counter() - t0) * 1000
                dl_b = int(dl.get("bytes_transferred", 0)) + 1500 if dl.get("succeeded") else 600
                suite_bytes_used += dl_b
                records.append(
                    LabTestRecord(
                        test_id="external_micro_download",
                        execution_scope=ExecutionScope.EXTERNAL_REAL,
                        server="speed.cloudflare.com:443",
                        protocol="https_download",
                        timestamp_utc=_utc_now(),
                        duration_ms=dur_dl,
                        bytes_estimated=dl_b,
                        verified_real=bool(dl.get("succeeded")),
                        result="PASS" if dl.get("succeeded") else "FAIL",
                        reason=dl.get("error"),
                        details={
                            "payload_bytes": dl.get("bytes_transferred"),
                            "download_kbps": dl.get("download_kbps"),
                        },
                    )
                )
            else:
                records.append(
                    self._skipped_budget(
                        "external_micro_download",
                        "speed.cloudflare.com:443",
                        "https_download",
                        "External lab suite byte cap reached",
                    )
                )

            # Micro-upload capped strictly at 4,096 B
            if suite_bytes_used + 6000 <= max_suite_bytes:
                t0 = time.perf_counter()
                ul = bw_tester.measure_upload_speed(
                    url="https://speed.cloudflare.com/__up",
                    sni_hostname="speed.cloudflare.com",
                    authorized=True,
                    payload_bytes=4096,
                    timeout=5.0,
                    interface_name=primary_ifname,
                )
                dur_ul = (time.perf_counter() - t0) * 1000
                ul_b = int(ul.get("bytes_transferred", 0)) + 1500 if ul.get("succeeded") else 600
                suite_bytes_used += ul_b
                records.append(
                    LabTestRecord(
                        test_id="external_micro_upload",
                        execution_scope=ExecutionScope.EXTERNAL_REAL,
                        server="speed.cloudflare.com:443",
                        protocol="https_upload",
                        timestamp_utc=_utc_now(),
                        duration_ms=dur_ul,
                        bytes_estimated=ul_b,
                        verified_real=bool(ul.get("succeeded")),
                        result="PASS" if ul.get("succeeded") else "FAIL",
                        reason=ul.get("error"),
                        details={
                            "payload_bytes": ul.get("bytes_transferred"),
                            "upload_kbps": ul.get("upload_kbps"),
                        },
                    )
                )
            else:
                records.append(
                    self._skipped_budget(
                        "external_micro_upload",
                        "speed.cloudflare.com:443",
                        "https_upload",
                        "External lab suite byte cap reached",
                    )
                )

        # 10 & 11. Authorized External SSH & WireGuard Tunnels (never invent free servers!)
        records.extend(self._check_external_authorized_tunnels(execute_live=True, skip_reason=None))

        res_after = measure_process_resources()
        total_ext_bytes = max(suite_bytes_used, self.cost_manager.bytes_consumed_total - bytes_before)
        return self._summarize_suite(
            suite_name="EXTERNAL_NETWORK_LAB",
            records=records,
            duration_ms=round((time.perf_counter() - suite_start) * 1000, 2),
            external_bytes_consumed=total_ext_bytes,
            resources_before=res_before,
            resources_after=res_after,
            cost_gate=gate,
        )

    def _check_external_authorized_tunnels(
        self,
        execute_live: bool,
        skip_reason: Optional[str],
    ) -> List[LabTestRecord]:
        catalog = self._load_servers_catalog()
        records: List[LabTestRecord] = []

        auth_ssh = [s for s in catalog.get("authorized_ssh_tunnels", []) if s.get("authorized")]
        if not auth_ssh:
            records.append(
                LabTestRecord(
                    test_id="external_ssh_tunnel",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server="unconfigured",
                    protocol="ssh_socks5",
                    timestamp_utc=_utc_now(),
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=(
                        "REMOTE_SERVER_REQUIRED: No authorized SSH server configured in configs/servers.json "
                        "(policy forbids inventing or using unauthorized public SSH servers)"
                    ),
                    details={"remote_status": "REMOTE_SERVER_REQUIRED"},
                )
            )
        elif not execute_live:
            records.append(
                LabTestRecord(
                    test_id="external_ssh_tunnel",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server=str(auth_ssh[0].get("host", "configured")),
                    protocol="ssh_socks5",
                    timestamp_utc=_utc_now(),
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=skip_reason,
                )
            )
        else:
            s_item = auth_ssh[0]
            cfg = SshTunnelConfig(
                host=s_item["host"],
                port=int(s_item.get("port", 22)),
                username=s_item["username"],
                identity_file=s_item["identity_file"],
                known_hosts_file=s_item["known_hosts_file"],
                local_bind_host=s_item.get("local_bind_host", "127.0.0.1"),
                local_socks_port=int(s_item.get("local_socks_port", 0)),
                authorized=True,
            )
            t0 = time.perf_counter()
            with SshSocksTunnel(cfg) as tun:
                st = tun.start()
                if st["connected"]:
                    hl = tun.check_health(verify_https_egress=True)
                    ok = bool(hl["healthy"] and hl["https_egress_verified"])
                    err = hl.get("error")
                    b_est = int(hl.get("bytes_estimated", 2500))
                else:
                    ok = False
                    err = st.get("error")
                    b_est = 512
            dur = (time.perf_counter() - t0) * 1000
            records.append(
                LabTestRecord(
                    test_id="external_ssh_tunnel",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server=f"{cfg.host}:{cfg.port}",
                    protocol="ssh_socks5",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=b_est,
                    verified_real=ok,
                    result="PASS" if ok else "FAIL",
                    reason=err,
                )
            )

        auth_wg = [w for w in catalog.get("authorized_wireguard_tunnels", []) if w.get("authorized")]
        if not auth_wg:
            records.append(
                LabTestRecord(
                    test_id="external_wireguard_tunnel",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server="unconfigured",
                    protocol="wireguard",
                    timestamp_utc=_utc_now(),
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=(
                        "REMOTE_SERVER_REQUIRED: No authorized WireGuard tunnel configured in configs/servers.json "
                        "(policy forbids inventing third-party VPN profiles)"
                    ),
                    details={"remote_status": "REMOTE_SERVER_REQUIRED"},
                )
            )
        elif not execute_live:
            records.append(
                LabTestRecord(
                    test_id="external_wireguard_tunnel",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server=str(auth_wg[0].get("interface", "wg0")),
                    protocol="wireguard",
                    timestamp_utc=_utc_now(),
                    duration_ms=0.0,
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=skip_reason,
                )
            )
        else:
            w_item = auth_wg[0]
            t0 = time.perf_counter()
            eng = WireGuardTunnelEngine(
                interface_name=w_item.get("interface", "wg0"),
                config_path=w_item.get("config_path"),
                authorized=True,
                allow_global_routes=False,
            )
            st = eng.inspect_state(verify_internet_egress=True)
            dur = (time.perf_counter() - t0) * 1000
            ok = bool(st["handshake_verified"] and st["https_egress_verified"])
            records.append(
                LabTestRecord(
                    test_id="external_wireguard_tunnel",
                    execution_scope=ExecutionScope.EXTERNAL_REAL,
                    server=eng.interface_name,
                    protocol="wireguard",
                    timestamp_utc=_utc_now(),
                    duration_ms=dur,
                    bytes_estimated=int(st.get("bytes_estimated", 0)),
                    verified_real=ok,
                    result="PASS" if ok else "FAIL",
                    reason=st.get("note"),
                )
            )

        return records

    @staticmethod
    def _skipped_budget(test_id: str, server: str, protocol: str, reason: Optional[str]) -> LabTestRecord:
        return LabTestRecord(
            test_id=test_id,
            execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
            server=server,
            protocol=protocol,
            timestamp_utc=_utc_now(),
            duration_ms=0.0,
            bytes_estimated=0,
            verified_real=False,
            result="SKIPPED",
            reason=reason or "Skipped due to byte budget cap",
        )

    @staticmethod
    def _summarize_suite(
        *,
        suite_name: str,
        records: List[LabTestRecord],
        duration_ms: float,
        external_bytes_consumed: int,
        resources_before: Dict[str, Any],
        resources_after: Dict[str, Any],
        cost_gate: Dict[str, Any],
    ) -> Dict[str, Any]:
        serialized = [r.to_dict() for r in records]
        passed = [r for r in serialized if r["result"] == "PASS"]
        failed = [r for r in serialized if r["result"] == "FAIL"]
        skipped = [r for r in serialized if r["result"] == "SKIPPED"]

        cpu_delta_s = round(
            max(0.0, float(resources_after["cpu_total_s"]) - float(resources_before["cpu_total_s"])),
            4,
        )

        return {
            "suite": suite_name,
            "timestamp_utc": _utc_now(),
            "duration_ms": duration_ms,
            "cost_gate": cost_gate,
            "counts": {
                "total": len(serialized),
                "passed": len(passed),
                "failed": len(failed),
                "skipped": len(skipped),
            },
            "data_consumption": {
                "external_bytes_consumed": external_bytes_consumed,
                "loopback_bytes_estimated": sum(
                    r["bytes_estimated"] for r in serialized if r["execution_scope"] == ExecutionScope.LOCAL_LOOPBACK.value
                ),
                "total_bytes_estimated": sum(r["bytes_estimated"] for r in serialized),
            },
            "resources": {
                "vm_rss_mb": resources_after["vm_rss_mb"],
                "vm_hwm_mb": resources_after["vm_hwm_mb"],
                "cpu_seconds_used": cpu_delta_s,
            },
            "records": serialized,
        }
