"""JARO WPF - Connectivity Prober & Real Internet Verification."""
from enum import Enum
import http.client
import json
from pathlib import Path
import socket
import ssl
import struct
import time
from typing import Any, Dict, List, Optional
import urllib.parse

import certifi

from core.protocols import tcp_dns_engine
from core.protocols import udp_engine

DEFAULT_SERVERS_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "servers.json"


class ConnectivityState(str, Enum):
    """Differentiates transport availability from actual internet access."""
    NO_NETWORK = "NO_NETWORK"
    SOCKET_ONLY = "SOCKET_ONLY"            # Local socket / TCP SYN-ACK (possible middlebox/firewall interception)
    DNS_ONLY = "DNS_ONLY"                  # DNS resolves (or only DNS provider IP is reachable), general web blocked
    SERVER_HANDSHAKE = "SERVER_HANDSHAKE"  # Verified cryptographic TLS handshake to remote endpoint, no full egress
    CAPTIVE_PORTAL = "CAPTIVE_PORTAL"      # HTTP/HTTPS intercepted or redirected to billing/login portal
    REAL_INTERNET = "REAL_INTERNET"        # Verified end-to-end encrypted payload with non-DNS external web host


_SHARED_SSL_CONTEXT: Optional[ssl.SSLContext] = None


def _create_verified_ssl_context() -> ssl.SSLContext:
    """Returns a cached strict SSLContext enforcing CERT_REQUIRED, hostname verification, and certifi CA bundle."""
    global _SHARED_SSL_CONTEXT
    if _SHARED_SSL_CONTEXT is None:
        ctx = ssl.create_default_context(cafile=certifi.where())
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        _SHARED_SSL_CONTEXT = ctx
    return _SHARED_SSL_CONTEXT


def parse_dns_response_ips(response: bytes, expected_txid: int) -> Dict[str, Any]:
    """Validates RFC 1035 DNS packet header and extracts RCODE and answer count."""
    if len(response) < 12:
        return {"valid": False, "error": "Packet shorter than 12-byte DNS header"}

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", response[:12])
    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F

    if txid != expected_txid:
        return {"valid": False, "error": f"Transaction ID mismatch ({txid} != {expected_txid})"}
    if not is_response:
        return {"valid": False, "error": "QR bit is 0 (not a response)"}
    if rcode != 0:
        return {"valid": False, "rcode": rcode, "error": f"DNS RCODE error: {rcode}"}

    return {
        "valid": ancount > 0,
        "rcode": rcode,
        "questions": qdcount,
        "answers": ancount,
        "authorities": nscount,
        "additionals": arcount,
    }


def probe_udp_dns(host: str, port: int = 53, domain: str = "example.com", timeout: float = 3.0) -> Dict[str, Any]:
    """Tests UDP DNS resolution without assuming general internet availability."""
    txid, query = udp_engine.create_dns_query(domain)
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (host, port))
            response, _ = sock.recvfrom(4096)
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        parsed = parse_dns_response_ips(response, txid)
        return {
            "layer": "DNS_UDP",
            "host": host,
            "port": port,
            "socket_ok": True,
            "protocol_verified": parsed["valid"],
            "answers": parsed.get("answers", 0),
            "latency_ms": latency_ms if parsed["valid"] else None,
            "error": parsed.get("error"),
        }
    except OSError as exc:
        return {
            "layer": "DNS_UDP",
            "host": host,
            "port": port,
            "socket_ok": False,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": str(exc),
        }


def probe_tcp_dns(host: str, port: int = 53, domain: str = "example.com", timeout: float = 3.5) -> Dict[str, Any]:
    """Tests RFC 1035 TCP DNS with 2-byte length prefix."""
    txid, query = tcp_dns_engine.create_query(domain)
    start = time.perf_counter()
    socket_connected = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            socket_connected = True
            sock.settimeout(timeout)
            sock.sendall(struct.pack("!H", len(query)) + query)
            length_bytes = tcp_dns_engine.receive_exact(sock, 2)
            length = struct.unpack("!H", length_bytes)[0]
            response = tcp_dns_engine.receive_exact(sock, length)
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        parsed = parse_dns_response_ips(response, txid)
        return {
            "layer": "DNS_TCP",
            "host": host,
            "port": port,
            "socket_ok": True,
            "protocol_verified": parsed["valid"],
            "answers": parsed.get("answers", 0),
            "latency_ms": latency_ms if parsed["valid"] else None,
            "error": parsed.get("error"),
        }
    except (OSError, ConnectionError) as exc:
        return {
            "layer": "DNS_TCP",
            "host": host,
            "port": port,
            "socket_ok": socket_connected,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": str(exc),
        }


def probe_dot_dns(
    host: str,
    port: int = 853,
    sni: Optional[str] = None,
    domain: str = "example.com",
    timeout: float = 4.0,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Tests RFC 7858 DNS-over-TLS (DoT), verifying both X.509 certificate/hostname and DNS wire response."""
    server_hostname = sni or host
    context = ssl_context or _create_verified_ssl_context()
    txid, query = tcp_dns_engine.create_query(domain)
    start = time.perf_counter()
    socket_ok = False
    tls_ok = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            socket_ok = True
            raw_sock.settimeout(timeout)
            with context.wrap_socket(raw_sock, server_hostname=server_hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                if not cert:
                    raise ssl.SSLError("Empty peer certificate on DoT connection")
                tls_ok = True
                tls_sock.sendall(struct.pack("!H", len(query)) + query)
                length_bytes = tcp_dns_engine.receive_exact(tls_sock, 2)
                length = struct.unpack("!H", length_bytes)[0]
                response = tcp_dns_engine.receive_exact(tls_sock, length)

        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        parsed = parse_dns_response_ips(response, txid)
        return {
            "layer": "DNS_DOT",
            "host": host,
            "port": port,
            "sni": server_hostname,
            "socket_ok": True,
            "tls_verified": True,
            "protocol_verified": parsed["valid"],
            "answers": parsed.get("answers", 0),
            "latency_ms": latency_ms if parsed["valid"] else None,
            "error": parsed.get("error"),
        }
    except (ssl.SSLError, OSError, ConnectionError) as exc:
        return {
            "layer": "DNS_DOT",
            "host": host,
            "port": port,
            "sni": server_hostname,
            "socket_ok": socket_ok,
            "tls_verified": tls_ok,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": str(exc),
        }


def probe_tcp_socket(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """Tests raw TCP 3-way handshake (Note: middleboxes may spoof SYN-ACK)."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "layer": "TCP_SOCKET",
                "host": host,
                "port": port,
                "socket_ok": True,
                "latency_ms": latency_ms,
                "error": None,
            }
    except OSError as exc:
        return {
            "layer": "TCP_SOCKET",
            "host": host,
            "port": port,
            "socket_ok": False,
            "latency_ms": None,
            "error": str(exc),
        }


def probe_tls_handshake(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    timeout: float = 4.0,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Verifies authentic cryptographic TLS handshake, hostname match, and X.509 certificate chain."""
    server_hostname = sni or host
    context = ssl_context or _create_verified_ssl_context()
    start = time.perf_counter()
    socket_ok = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            socket_ok = True
            raw_sock.settimeout(timeout)
            with context.wrap_socket(raw_sock, server_hostname=server_hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                if not cert:
                    raise ssl.SSLError("Peer did not present a verified X.509 certificate")
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version()
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                return {
                    "layer": "TLS_HANDSHAKE",
                    "host": host,
                    "port": port,
                    "sni": server_hostname,
                    "socket_ok": True,
                    "server_verified": True,
                    "cert_subject": dict(x[0] for x in cert.get("subject", ())),
                    "tls_version": tls_version,
                    "cipher": cipher[0] if cipher else None,
                    "latency_ms": latency_ms,
                    "error": None,
                }
    except ssl.SSLError as exc:
        return {
            "layer": "TLS_HANDSHAKE",
            "host": host,
            "port": port,
            "sni": server_hostname,
            "socket_ok": socket_ok,
            "server_verified": False,
            "cert_subject": None,
            "tls_version": None,
            "cipher": None,
            "latency_ms": None,
            "error": f"SSL verification failed (possible captive portal MITM): {exc}",
        }
    except OSError as exc:
        return {
            "layer": "TLS_HANDSHAKE",
            "host": host,
            "port": port,
            "sni": server_hostname,
            "socket_ok": socket_ok,
            "server_verified": False,
            "cert_subject": None,
            "tls_version": None,
            "cipher": None,
            "latency_ms": None,
            "error": str(exc),
        }


def probe_https_egress(
    url: str = "https://example.com/",
    expected_status: int = 200,
    expected_substring: str = "Example Domain",
    connect_host: Optional[str] = None,
    sni_hostname: Optional[str] = None,
    timeout: float = 4.5,
    source_address: Optional[tuple[str, int]] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Verifies HTTPS egress by checking X.509 cert + hostname, HTTP status, redirection, and payload."""
    parsed_url = urllib.parse.urlsplit(url)
    target_hostname = sni_hostname or parsed_url.hostname or ""
    target_ip_or_host = connect_host or parsed_url.hostname or ""
    target_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    path_and_query = parsed_url.path or "/"
    if parsed_url.query:
        path_and_query += f"?{parsed_url.query}"

    if not target_hostname or not target_ip_or_host:
        return {
            "layer": "HTTPS_EGRESS",
            "url": url,
            "connect_host": target_ip_or_host,
            "sni": target_hostname,
            "status_code": None,
            "tls_verified": False,
            "real_internet": False,
            "captive_portal_suspected": False,
            "latency_ms": None,
            "bytes_estimated": 0,
            "error": "Invalid URL or hostname",
        }

    start = time.perf_counter()
    tls_verified = False
    try:
        with socket.create_connection(
            (target_ip_or_host, target_port),
            timeout=timeout,
            source_address=source_address,
        ) as raw_sock:
            raw_sock.settimeout(timeout)
            if parsed_url.scheme == "https":
                context = ssl_context or _create_verified_ssl_context()
                sock: socket.socket = context.wrap_socket(raw_sock, server_hostname=target_hostname)
                if not sock.getpeercert():  # type: ignore[attr-defined]
                    raise ssl.SSLError("Empty peer certificate")
                tls_verified = True
            else:
                sock = raw_sock

            with sock:
                request_lines = (
                    f"GET {path_and_query} HTTP/1.1\r\n"
                    f"Host: {target_hostname}\r\n"
                    f"User-Agent: JARO-WPF/1.1 ConnectivityProber\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                )
                req_bytes = request_lines.encode("ascii")
                sock.sendall(req_bytes)

                http_resp = http.client.HTTPResponse(sock)
                http_resp.begin()
                status = http_resp.status
                location = http_resp.getheader("Location")
                raw_body = http_resp.read(4096)
                body = raw_body.decode("utf-8", errors="replace")

        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        tls_overhead = 2048 if parsed_url.scheme == "https" else 256
        bytes_estimated = len(req_bytes) + len(raw_body) + tls_overhead
        is_redirect = status in (301, 302, 303, 307, 308) or location is not None
        status_match = status == expected_status

        if expected_status == 204 and not expected_substring:
            content_match = len(body.strip()) == 0
        elif expected_substring:
            content_match = expected_substring in body
        else:
            content_match = len(body) > 0

        real_internet = (
            (tls_verified if parsed_url.scheme == "https" else True)
            and status_match
            and content_match
            and not is_redirect
        )
        captive_detected = (
            is_redirect
            or status == 511
            or (status == 200 and not content_match)
            or (status_match and not content_match)
        )

        error_msg: Optional[str] = None
        if not real_internet:
            if is_redirect:
                error_msg = f"Unexpected HTTP redirect ({status}) to {location}"
            elif not status_match:
                error_msg = f"Unexpected HTTP status {status} (expected {expected_status})"
            elif not content_match:
                error_msg = "Response body did not match expected content signature"

        return {
            "layer": "HTTPS_EGRESS",
            "url": url,
            "connect_host": target_ip_or_host,
            "sni": target_hostname,
            "status_code": status,
            "tls_verified": tls_verified,
            "real_internet": real_internet,
            "captive_portal_suspected": captive_detected,
            "latency_ms": latency_ms,
            "bytes_estimated": bytes_estimated,
            "error": error_msg,
        }
    except ssl.SSLError as exc:
        return {
            "layer": "HTTPS_EGRESS",
            "url": url,
            "connect_host": target_ip_or_host,
            "sni": target_hostname,
            "status_code": None,
            "tls_verified": False,
            "real_internet": False,
            "captive_portal_suspected": True,
            "latency_ms": None,
            "error": f"TLS certificate/hostname verification failed: {exc}",
        }
    except Exception as exc:
        return {
            "layer": "HTTPS_EGRESS",
            "url": url,
            "connect_host": target_ip_or_host,
            "sni": target_hostname,
            "status_code": None,
            "tls_verified": tls_verified,
            "real_internet": False,
            "captive_portal_suspected": False,
            "latency_ms": None,
            "error": str(exc),
        }


def classify_connectivity(
    dns_udp: Dict[str, Any],
    dns_tcp: Dict[str, Any],
    tcp_sock: Dict[str, Any],
    tls_check: Dict[str, Any],
    https_check: Dict[str, Any],
    non_dns_https_checks: Optional[List[Dict[str, Any]]] = None,
) -> ConnectivityState:
    """Strictly classifies network state.

    Requires at least one non-DNS general web endpoint to succeed before declaring REAL_INTERNET.
    If only a DNS server's HTTPS endpoint succeeds while general web endpoints fail, classifies as DNS_ONLY.
    """
    non_dns_checks = non_dns_https_checks if non_dns_https_checks is not None else [https_check]

    any_captive = https_check.get("captive_portal_suspected", False) or any(
        c.get("captive_portal_suspected", False) for c in non_dns_checks
    )
    non_dns_real_internet = any(c.get("real_internet", False) for c in non_dns_checks)

    if non_dns_real_internet and not any_captive:
        return ConnectivityState.REAL_INTERNET

    if any_captive:
        return ConnectivityState.CAPTIVE_PORTAL

    # If only the DNS provider's HTTPS endpoint works, but general non-DNS web hosts are unreachable:
    if https_check.get("real_internet") and not non_dns_real_internet:
        return ConnectivityState.DNS_ONLY

    if tls_check.get("server_verified"):
        return ConnectivityState.SERVER_HANDSHAKE

    if dns_udp.get("protocol_verified") or dns_tcp.get("protocol_verified"):
        return ConnectivityState.DNS_ONLY

    if (
        tcp_sock.get("socket_ok")
        or dns_tcp.get("socket_ok")
        or tls_check.get("socket_ok")
    ):
        return ConnectivityState.SOCKET_ONLY

    return ConnectivityState.NO_NETWORK


def evaluate_full_connectivity(
    target_host: str = "1.1.1.1",
    target_sni: str = "one.one.one.one",
    egress_url: str = "https://one.one.one.one/cdn-cgi/trace",
    expected_status: int = 200,
    expected_substring: str = "fl=",
    include_dns: bool = True,
) -> Dict[str, Any]:
    """Runs layered diagnostics including non-DNS general internet endpoints to verify REAL_INTERNET."""
    if include_dns:
        dns_udp = probe_udp_dns(target_host, 53)
        dns_tcp = probe_tcp_dns(target_host, 53)
    else:
        dns_udp = {
            "layer": "DNS_UDP",
            "host": target_host,
            "port": 53,
            "skipped": True,
            "socket_ok": False,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": "Skipped DNS probe (include_dns=False)",
        }
        dns_tcp = {
            "layer": "DNS_TCP",
            "host": target_host,
            "port": 53,
            "skipped": True,
            "socket_ok": False,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": "Skipped DNS probe (include_dns=False)",
        }
    tcp_sock = probe_tcp_socket(target_host, 443)
    tls_check = probe_tls_handshake(target_host, 443, sni=target_sni)
    dns_provider_https = probe_https_egress(
        url=egress_url,
        expected_status=expected_status,
        expected_substring=expected_substring,
        connect_host=target_host,
        sni_hostname=target_sni,
    )

    # Probe independent non-DNS general web endpoints so REAL_INTERNET never depends solely on DNS servers
    non_dns_endpoints = [
        {
            "url": "https://example.com/",
            "expected_status": 200,
            "expected_substring": "Example Domain",
        },
        {
            "url": "https://connectivitycheck.gstatic.com/generate_204",
            "expected_status": 204,
            "expected_substring": "",
        },
    ]
    non_dns_results: List[Dict[str, Any]] = []
    for ep in non_dns_endpoints:
        res = probe_https_egress(
            url=ep["url"],
            expected_status=ep["expected_status"],
            expected_substring=ep["expected_substring"],
        )
        non_dns_results.append(res)
        if res["real_internet"]:
            break

    state = classify_connectivity(
        dns_udp=dns_udp,
        dns_tcp=dns_tcp,
        tcp_sock=tcp_sock,
        tls_check=tls_check,
        https_check=dns_provider_https,
        non_dns_https_checks=non_dns_results,
    )

    return {
        "target_host": target_host,
        "state": state.value,
        "real_internet_verified": state == ConnectivityState.REAL_INTERNET,
        "summary": {
            "socket_connection": tcp_sock["socket_ok"] or dns_tcp["socket_ok"],
            "dns_resolution": dns_udp["protocol_verified"] or dns_tcp["protocol_verified"],
            "authentic_server_tls": tls_check["server_verified"],
            "dns_provider_https_ok": dns_provider_https["real_internet"],
            "non_dns_web_egress_ok": any(r["real_internet"] for r in non_dns_results),
            "real_internet_egress": state == ConnectivityState.REAL_INTERNET,
        },
        "probes": {
            "dns_udp": dns_udp,
            "dns_tcp": dns_tcp,
            "tcp_socket": tcp_sock,
            "tls_handshake": tls_check,
            "https_dns_provider": dns_provider_https,
            "https_non_dns_egress": non_dns_results,
        },
    }


def main() -> None:
    report = evaluate_full_connectivity()
    print(json.dumps(report, indent=4))


if __name__ == "__main__":
    main()
