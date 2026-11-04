"""JARO WPF - Dual SOCKS5 (RFC 1928) + HTTP CONNECT (RFC 9110) Local Proxy Bridge (Phase 6).

Mirrors the exact state machine implemented in Swift (`ios/Sources/JaroTunnelEngine/JaroLocalSOCKS5Server.swift`):
- Auto-detects on the first client byte:
    * `0x05` -> RFC 1928 SOCKS5 (`NO AUTH`, `CMD=CONNECT`, IPv4 `0x01`, Domain `0x03`, IPv6 `0x04`)
    * `'C'`  -> RFC 9110 `CONNECT host:port HTTP/1.1` (required on iOS so `NEProxySettings.httpsServer`
      can route system HTTPS traffic into the SSH `direct-tcpip` tunnel!)
- Forwards established streams either through an upstream SOCKS5 listener (e.g., OpenSSH `ssh -D`
  `direct-tcpip` channel) or directly when configured in standalone local relay mode.
- Atomically tracks `rx_bytes`, `tx_bytes`, `socks5_connections`, `http_connect_connections`, and
  redacted diagnostic events.
"""
import http.client
import socket
import ssl
import struct
import threading
import time
from typing import Any, Dict, List, Optional

from core.network_tests.connectivity_prober import _create_verified_ssl_context
from core.security.secret_guard import redact_secrets


class DualProxyError(Exception):
    """Raised on SOCKS5 or HTTP CONNECT framing/forwarding errors."""


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DualProxyError("Unexpected EOF while reading proxy header")
        buf.extend(chunk)
    return bytes(buf)


def probe_https_over_http_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int = 443,
    path: str = "/",
    expected_status: int = 200,
    expected_substring: str = "Example Domain",
    timeout: float = 4.0,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Verifies end-to-end TLS X.509 HTTPS over an RFC 9110 `HTTP CONNECT` tunnel (iOS `NEProxySettings` path)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            connect_req = (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"Proxy-Connection: keep-alive\r\n\r\n"
            ).encode("ascii")
            raw_sock.sendall(connect_req)

            hdr_buf = bytearray()
            while b"\r\n\r\n" not in hdr_buf:
                chunk = raw_sock.recv(1024)
                if not chunk:
                    raise DualProxyError("EOF waiting for HTTP CONNECT 200 response")
                hdr_buf.extend(chunk)
                if len(hdr_buf) > 8192:
                    raise DualProxyError("Oversized HTTP CONNECT response header")

            status_line = bytes(hdr_buf).split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            parts = status_line.split()
            if len(parts) < 2 or parts[1] != "200":
                return {
                    "connect_tunnel_established": False,
                    "tls_verified": False,
                    "https_verified": False,
                    "status_code": None,
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                    "bytes_estimated": len(connect_req) + len(hdr_buf),
                    "error": f"HTTP CONNECT rejected: {status_line}",
                }

            ctx = ssl_context or _create_verified_ssl_context()
            with ctx.wrap_socket(raw_sock, server_hostname=target_host) as tls_sock:
                tls_sock.settimeout(timeout)
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target_host}\r\n"
                    f"User-Agent: JARO-WPF-Phase6/1.0\r\n"
                    f"Accept-Encoding: identity\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                tls_sock.sendall(req)

                resp = http.client.HTTPResponse(tls_sock)  # type: ignore[arg-type]
                resp.begin()
                body = resp.read(8192)
                latency = round((time.perf_counter() - t0) * 1000, 2)
                text_preview = body.decode("utf-8", errors="replace")
                status_ok = resp.status == expected_status
                sub_ok = (expected_substring in text_preview) if expected_substring else True
                ok = status_ok and sub_ok
                return {
                    "connect_tunnel_established": True,
                    "tls_verified": True,
                    "https_verified": ok,
                    "status_code": resp.status,
                    "latency_ms": latency,
                    "bytes_estimated": len(connect_req) + len(hdr_buf) + len(req) + len(body) + 1200,
                    "error": None if ok else f"Unexpected HTTP status ({resp.status}) or payload mismatch",
                }
    except (OSError, ssl.SSLError, http.client.HTTPException, DualProxyError) as exc:
        return {
            "connect_tunnel_established": False,
            "tls_verified": False,
            "https_verified": False,
            "status_code": None,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            "bytes_estimated": 256,
            "error": redact_secrets(f"{exc.__class__.__name__}: {exc}"),
        }


class JaroDualProxyBridge:
    """Loopback SOCKS5 + HTTP CONNECT dual listener forwarding into an upstream SOCKS5/SSH tunnel or local target."""

    def __init__(
        self,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        upstream_socks5_host: Optional[str] = None,
        upstream_socks5_port: Optional[int] = None,
        connect_timeout: float = 4.0,
    ) -> None:
        if bind_host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("JaroDualProxyBridge must bind exclusively to loopback")
        self.bind_host = "127.0.0.1" if bind_host == "localhost" else bind_host
        self.bind_port = int(bind_port)
        self.upstream_socks5_host = upstream_socks5_host
        self.upstream_socks5_port = upstream_socks5_port
        self.connect_timeout = connect_timeout

        self._srv_sock: Optional[socket.socket] = None
        self._stop_ev = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._socks5_count = 0
        self._http_connect_count = 0
        self._active_streams = 0
        self._logs: List[str] = []

    def _log(self, message: str) -> None:
        with self._lock:
            if len(self._logs) >= 100:
                self._logs.pop(0)
            self._logs.append(redact_secrets(message))

    def start(self) -> int:
        self.stop()
        self._stop_ev.clear()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind_host, self.bind_port))
        srv.listen(16)
        srv.settimeout(0.25)
        self._srv_sock = srv
        self.bind_port = int(srv.getsockname()[1])
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self._log(f"Dual proxy started on {self.bind_host}:{self.bind_port}")
        return self.bind_port

    def stop(self) -> None:
        self._stop_ev.set()
        if self._srv_sock is not None:
            try:
                self._srv_sock.close()
            except OSError:
                pass
            self._srv_sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None

    def stats_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "bind_endpoint": f"{self.bind_host}:{self.bind_port}",
                "rx_bytes": self._rx_bytes,
                "tx_bytes": self._tx_bytes,
                "socks5_connections": self._socks5_count,
                "http_connect_connections": self._http_connect_count,
                "active_streams": self._active_streams,
                "recent_logs": list(self._logs[-20:]),
            }

    def _accept_loop(self) -> None:
        assert self._srv_sock is not None
        while not self._stop_ev.is_set():
            try:
                client_sock, _ = self._srv_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            th = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
            th.start()

    def _open_upstream(self, dst_host: str, dst_port: int) -> socket.socket:
        if self.upstream_socks5_host and self.upstream_socks5_port:
            up = socket.create_connection(
                (self.upstream_socks5_host, self.upstream_socks5_port),
                timeout=self.connect_timeout,
            )
            up.settimeout(self.connect_timeout)
            up.sendall(b"\x05\x01\x00")
            ver, method = struct.unpack("!BB", _recv_exact(up, 2))
            if ver != 0x05 or method != 0x00:
                up.close()
                raise DualProxyError("Upstream SOCKS5 rejected NO_AUTH")
            host_b = dst_host.encode("idna")
            req = struct.pack("!BBBBB", 0x05, 0x01, 0x00, 0x03, len(host_b)) + host_b + struct.pack("!H", dst_port)
            up.sendall(req)
            r_ver, rep, _rsv, atyp = struct.unpack("!BBBB", _recv_exact(up, 4))
            if r_ver != 0x05 or rep != 0x00:
                up.close()
                raise DualProxyError(f"Upstream SOCKS5 CONNECT failed (REP=0x{rep:02x})")
            if atyp == 0x01:
                _recv_exact(up, 6)
            elif atyp == 0x03:
                ln = _recv_exact(up, 1)[0]
                _recv_exact(up, ln + 2)
            elif atyp == 0x04:
                _recv_exact(up, 18)
            return up

        resolved = "127.0.0.1" if dst_host == "localhost" else dst_host
        up = socket.create_connection((resolved, dst_port), timeout=self.connect_timeout)
        up.settimeout(self.connect_timeout)
        return up

    def _handle_client(self, client_sock: socket.socket) -> None:
        upstream: Optional[socket.socket] = None
        with self._lock:
            self._active_streams += 1
        try:
            client_sock.settimeout(self.connect_timeout)
            first = client_sock.recv(1, socket.MSG_PEEK)
            if not first:
                return

            if first[0] == 0x05:
                # RFC 1928 SOCKS5 path
                with self._lock:
                    self._socks5_count += 1
                ver, nmethods = struct.unpack("!BB", _recv_exact(client_sock, 2))
                methods = _recv_exact(client_sock, nmethods)
                if ver != 0x05 or 0x00 not in methods:
                    client_sock.sendall(b"\x05\xff")
                    return
                client_sock.sendall(b"\x05\x00")
                # Support greeting-only probe cleanly
                try:
                    req_hdr = _recv_exact(client_sock, 4)
                except DualProxyError:
                    return
                _v, cmd, _rsv, atyp = struct.unpack("!BBBB", req_hdr)
                if cmd != 0x01:
                    client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                if atyp == 0x01:
                    dst_host = socket.inet_ntoa(_recv_exact(client_sock, 4))
                elif atyp == 0x03:
                    dlen = _recv_exact(client_sock, 1)[0]
                    dst_host = _recv_exact(client_sock, dlen).decode("ascii", errors="replace")
                elif atyp == 0x04:
                    dst_host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client_sock, 16))
                else:
                    client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                dst_port = struct.unpack("!H", _recv_exact(client_sock, 2))[0]

                upstream = self._open_upstream(dst_host, dst_port)
                client_sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.bind_port))
            elif first[0] in (ord("C"), ord("c")):
                # RFC 9110 HTTP CONNECT path (mirrors iOS NEProxySettings.httpsServer!)
                with self._lock:
                    self._http_connect_count += 1
                hdr = bytearray()
                while b"\r\n\r\n" not in hdr:
                    chunk = client_sock.recv(1024)
                    if not chunk:
                        return
                    hdr.extend(chunk)
                    if len(hdr) > 8192:
                        return
                req_line = bytes(hdr).split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                tokens = req_line.split()
                if len(tokens) < 2 or tokens[0].upper() != "CONNECT":
                    client_sock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                    return
                authority = tokens[1]
                if authority.startswith("["):
                    dst_host, port_s = authority[1:].rsplit("]:", 1)
                else:
                    dst_host, port_s = authority.rsplit(":", 1)
                dst_port = int(port_s)
                upstream = self._open_upstream(dst_host, dst_port)
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                self._log(f"Rejected unknown proxy framing byte 0x{first[0]:02x}")
                return

            self._pipe_bidirectional(client_sock, upstream)
        except Exception as exc:
            self._log(f"Stream error: {exc.__class__.__name__}: {exc}")
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client_sock.close()
            except OSError:
                pass
            with self._lock:
                self._active_streams = max(0, self._active_streams - 1)

    def _pipe_bidirectional(self, client_sock: socket.socket, upstream_sock: socket.socket) -> None:
        def forward(src: socket.socket, dst: socket.socket, is_tx: bool) -> None:
            try:
                while not self._stop_ev.is_set():
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
                    with self._lock:
                        if is_tx:
                            self._tx_bytes += len(data)
                        else:
                            self._rx_bytes += len(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t_up = threading.Thread(target=forward, args=(client_sock, upstream_sock, True), daemon=True)
        t_dn = threading.Thread(target=forward, args=(upstream_sock, client_sock, False), daemon=True)
        t_up.start()
        t_dn.start()
        t_up.join(timeout=5.0)
        t_dn.join(timeout=5.0)

    def __enter__(self) -> "JaroDualProxyBridge":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
