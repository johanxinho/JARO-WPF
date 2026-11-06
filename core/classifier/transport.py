"""Transporte de sondas del clasificador: ABC inyectable + implementación real.

- Todos los sockets se crean con la familia explícita (AF_INET / AF_INET6).
- Los destinos SIEMPRE provienen de la configuración del usuario; no hay
  destinos externos por defecto.
- Portal cautivo: heurística solo ante redirección 302/307 hacia endpoints de
  login o sustitución de payload (marcador esperado del usuario). Un HTTP 5xx
  o un fallo TLS NUNCA marcan portal cautivo.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .models import (
    CaptivePortalStatus,
    DnsStatus,
    HttpsStatus,
    IpLayerStatus,
)

DEFAULT_TIMEOUT_S = 3.0

_LOGIN_MARKERS = ("login", "portal", "auth", "captive", "activar", "saldo")


@dataclass
class DnsProbeOutcome:
    status: DnsStatus
    evidence: list[str] = field(default_factory=list)


@dataclass
class HttpsProbeOutcome:
    status: HttpsStatus
    http_code: int | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class PortalProbeOutcome:
    status: CaptivePortalStatus
    evidence: list[str] = field(default_factory=list)


class ProbeTransport(ABC):
    """Transporte inyectable: las pruebas sustituyen estas operaciones."""

    @abstractmethod
    def ip_layer_probe(self, family: int) -> IpLayerStatus: ...

    @abstractmethod
    def dns_query(self, resolver_ip: str, name: str, family: int, timeout: float) -> DnsProbeOutcome: ...

    @abstractmethod
    def https_request(self, url: str, family: int, timeout: float) -> HttpsProbeOutcome: ...

    @abstractmethod
    def portal_request(
        self, url: str, family: int, timeout: float, expected_body_marker: str | None
    ) -> PortalProbeOutcome: ...


def _family_of_ip(value: str) -> int:
    return socket.AF_INET6 if ":" in value else socket.AF_INET


def _build_dns_query(name: str, qtype: int) -> bytes:
    tid = os.urandom(2)
    header = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return header + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def _parse_dns_response(response: bytes, tid: bytes) -> tuple[int, int]:
    if len(response) < 12 or response[:2] != tid:
        raise ValueError("dns response mismatch")
    flags = struct.unpack(">H", response[2:4])[0]
    ancount = struct.unpack(">H", response[6:8])[0]
    return flags & 0xF, ancount


class RealTransport(ProbeTransport):
    """Sondas reales sobre sockets ligados explícitamente a la familia."""

    def open_socket(self, family: int, socket_type: int = socket.SOCK_STREAM) -> socket.socket:
        """Familia SIEMPRE explícita (AF_INET o AF_INET6)."""
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError(f"familia no soportada: {family}")
        return socket.socket(family, socket_type)

    # --- Capa IP (solo Linux; fuera de Linux devuelve NOT_PROBED) ---

    def ip_layer_probe(self, family: int) -> IpLayerStatus:
        try:
            if family == socket.AF_INET:
                return self._ipv4_layer()
            if family == socket.AF_INET6:
                return self._ipv6_layer()
        except OSError:
            return IpLayerStatus.NOT_PROBED
        return IpLayerStatus.NOT_PROBED

    def _ipv4_layer(self) -> IpLayerStatus:
        import fcntl

        has_addr = False
        with self.open_socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for _, name in socket.if_nameindex():
                try:
                    packed = struct.pack("256s", name[:15].encode())
                    addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24])
                except OSError:
                    continue
                if not addr.startswith("127."):
                    has_addr = True
        if not has_addr:
            return IpLayerStatus.UNAVAILABLE
        with open("/proc/net/route", encoding="ascii") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000" and parts[3] == "0003":
                    return IpLayerStatus.AVAILABLE
        return IpLayerStatus.UNAVAILABLE

    def _ipv6_layer(self) -> IpLayerStatus:
        has_addr = False
        try:
            with open("/proc/net/if_inet6", encoding="ascii") as fh:
                for line in fh:
                    addr = line.split()[0]
                    if not addr.startswith("fe80") and addr != "00000000000000000000000000000001":
                        has_addr = True
        except OSError:
            return IpLayerStatus.NOT_PROBED
        if not has_addr:
            return IpLayerStatus.UNAVAILABLE
        try:
            with open("/proc/net/ipv6_route", encoding="ascii") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) > 4 and parts[0] == "00" * 16 and parts[1] == "00":
                        return IpLayerStatus.AVAILABLE
        except OSError:
            pass
        return IpLayerStatus.UNAVAILABLE

    # --- DNS ---

    def dns_query(self, resolver_ip: str, name: str, family: int, timeout: float) -> DnsProbeOutcome:
        evidence: list[str] = [f"resolver={resolver_ip}", f"family={'v6' if family == socket.AF_INET6 else 'v4'}"]
        try:
            ipaddress.ip_address(resolver_ip)
        except ValueError:
            return DnsProbeOutcome(DnsStatus.FAILED, evidence + ["invalid_resolver"])
        qtype = 28 if family == socket.AF_INET6 else 1  # AAAA / A
        query = _build_dns_query(name, qtype)
        try:
            with self.open_socket(_family_of_ip(resolver_ip), socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, (resolver_ip, 53))
                response, _ = s.recvfrom(4096)
        except (TimeoutError, socket.timeout):
            return DnsProbeOutcome(DnsStatus.FAILED, evidence + ["timeout"])
        except OSError as exc:
            return DnsProbeOutcome(DnsStatus.FAILED, evidence + [f"os_error:{exc.errno}"])
        try:
            rcode, ancount = _parse_dns_response(response, query[:2])
        except ValueError as exc:
            return DnsProbeOutcome(DnsStatus.FAILED, evidence + [str(exc)])
        if rcode != 0:
            return DnsProbeOutcome(DnsStatus.FAILED, evidence + [f"rcode={rcode}"])
        if ancount > 0:
            return DnsProbeOutcome(DnsStatus.OK, evidence + [f"answers={ancount}"])
        return DnsProbeOutcome(DnsStatus.FAILED, evidence + ["noerror_no_answers"])

    # --- HTTPS ---

    def https_request(self, url: str, family: int, timeout: float) -> HttpsProbeOutcome:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return HttpsProbeOutcome(HttpsStatus.DESTINATION_UNAVAILABLE, None, ["invalid_url"])
        port = parsed.port or 443
        host = parsed.hostname
        if ipaddress.ip_address(host):  # literal: familia directa
            addrs = [host]
        else:
            try:
                infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
                addrs = [info[4][0] for info in infos]
            except OSError as exc:
                return HttpsProbeOutcome(HttpsStatus.DESTINATION_UNAVAILABLE, None, [f"resolve_error:{exc.errno}"])
        path = parsed.path or "/"
        request = (
            f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        last_status = HttpsStatus.DESTINATION_UNAVAILABLE
        evidence: list[str] = []
        for addr in addrs[:3]:
            try:
                with self.open_socket(family, socket.SOCK_STREAM) as raw:
                    raw.settimeout(timeout)
                    raw.connect((addr, port))
                    with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
                        tls.sendall(request)
                        header = b""
                        while b"\r\n\r\n" not in header:
                            chunk = tls.recv(4096)
                            if not chunk:
                                break
                            header += chunk
                code = int(header.split(b" ", 2)[1]) if b" " in header else 0
                if code >= 500:
                    return HttpsProbeOutcome(HttpsStatus.HTTP_ERROR_SERVER, code, [f"http_code={code}"])
                return HttpsProbeOutcome(HttpsStatus.OK, code, [f"http_code={code}"])
            except (TimeoutError, socket.timeout):
                return HttpsProbeOutcome(HttpsStatus.TIMEOUT, None, [f"timeout addr={addr}"])
            except ssl.SSLError as exc:
                last_status = HttpsStatus.TLS_ERROR
                evidence.append(f"tls_error addr={addr}: {str(exc)[:80]}")
            except OSError as exc:
                last_status = HttpsStatus.DESTINATION_UNAVAILABLE
                evidence.append(f"unreachable addr={addr}: {str(exc)[:60]}")
        return HttpsProbeOutcome(last_status, None, evidence)

    # --- Portal cautivo (solo puerto 80, heurística) ---

    def portal_request(
        self, url: str, family: int, timeout: float, expected_body_marker: str | None
    ) -> PortalProbeOutcome:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return PortalProbeOutcome(CaptivePortalStatus.NOT_SUSPECTED, ["invalid_url"])
        port = parsed.port or 80
        host = parsed.hostname
        try:
            if ipaddress.ip_address(host):
                addrs = [host]
            else:
                infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
                addrs = [info[4][0] for info in infos]
        except OSError as exc:
            return PortalProbeOutcome(CaptivePortalStatus.NOT_SUSPECTED, [f"resolve_error:{exc.errno}"])
        path = parsed.path or "/"
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
        try:
            with self.open_socket(family, socket.SOCK_STREAM) as raw:
                raw.settimeout(timeout)
                raw.connect((addrs[0], port))
                raw.sendall(request)
                payload = b""
                while b"\r\n\r\n" not in payload and len(payload) < 16384:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    payload += chunk
        except (TimeoutError, socket.timeout):
            return PortalProbeOutcome(CaptivePortalStatus.NOT_SUSPECTED, ["timeout_no_portal_claim"])
        except OSError as exc:
            return PortalProbeOutcome(CaptivePortalStatus.NOT_SUSPECTED, [f"unreachable:{exc.errno}"])
        header_part = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        body = payload.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in payload else b""
        status_line = header_part.splitlines()[0] if header_part else ""
        try:
            code = int(status_line.split()[1])
        except (IndexError, ValueError):
            return PortalProbeOutcome(CaptivePortalStatus.NOT_SUSPECTED, ["malformed_response"])
        location = ""
        for line in header_part.splitlines():
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                break
        if code in (302, 307) and any(m in location.lower() for m in _LOGIN_MARKERS):
            return PortalProbeOutcome(
                CaptivePortalStatus.PORTAL_DETECTED, [f"redirect_30x_to_login={location[:80]}"]
            )
        if code == 200 and expected_body_marker and expected_body_marker not in body.decode("latin-1", "replace"):
            return PortalProbeOutcome(
                CaptivePortalStatus.PORTAL_DETECTED, ["payload_substitution_expected_marker_missing"]
            )
        return PortalProbeOutcome(CaptivePortalStatus.NOT_SUSPECTED, [f"http_code={code}"])
