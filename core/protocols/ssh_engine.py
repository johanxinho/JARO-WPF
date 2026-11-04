"""JARO WPF - Secure SSH Client & Local Dynamic SOCKS5 Tunnel Engine (Phase 5 Audited).

Features:
- Uses native OpenSSH client (Linux /usr/bin/ssh & Windows ssh.exe) for minimal RAM footprint.
- Enforces public-key authentication (IdentityFile 0o600/0o400) and strict pinned host-key verification
  (StrictHostKeyChecking=yes + pre-flight known_hosts verification for plain and |1| hashed entries).
- Contains NO default credentials and NO invented servers; requires explicit authorized configuration.
- Prevents false positives via pre-spawn local port-collision detection and explicit differentiation between:
    1. local_socks5_functional          (RFC 1928 SOCKS5 listener)
    2. local_ssh_tunnel_functional      (SSHv2 loopback session + direct-tcpip forwarding)
    3. remote_ssh_tunnel_functional     (Non-loopback remote SSHv2 session + direct-tcpip forwarding)
    4. https_egress_verified            (End-to-end X.509 TLS + HTTP status + payload over tunnel)
- Scrubs all errors through redact_secrets(), classifies SSH errors deterministically, and terminates
  process groups cleanly on teardown.
"""
from dataclasses import dataclass
import http.client
import ipaddress
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional

from core.connection.reconnector import ExponentialBackoffReconnector
from core.connection.server_manager import is_loopback_host
from core.network_tests.connectivity_prober import _create_verified_ssl_context
from core.security.secret_guard import (
    inspect_ssh_identity_file,
    redact_secrets,
    verify_known_hosts_entry,
)


class SshTunnelError(Exception):
    """Raised on SSH configuration, authentication, host-key, or SOCKS5 forwarding errors."""


def classify_ssh_error(error_text: Optional[str]) -> str:
    """Classifies OpenSSH client failure diagnostics into deterministic error codes."""
    msg = (error_text or "").lower()
    if not msg:
        return "NONE"
    if (
        "host key verification failed" in msg
        or "remote host identification has changed" in msg
        or "no ed25519 host key is known" in msg
        or "no ecdsa host key is known" in msg
        or "no rsa host key is known" in msg
        or "pinned ssh host key" in msg
        or "revoked" in msg
    ):
        return "HOST_KEY_VERIFICATION_FAILED"
    if (
        "permission denied (publickey" in msg
        or "too many authentication failures" in msg
        or "load key" in msg
        or "invalid format" in msg
    ):
        return "PUBLICKEY_AUTH_REJECTED"
    if (
        "could not request local forwarding" in msg
        or "address already in use" in msg
        or "administratively prohibited" in msg
        or "port collision" in msg
    ):
        return "PORT_FORWARD_FAILED"
    if "connection refused" in msg:
        return "CONNECTION_REFUSED"
    if "timed out" in msg or "operation timed out" in msg:
        return "CONNECTION_TIMED_OUT"
    if "not marked as authorized" in msg:
        return "UNAUTHORIZED_SERVER"
    return "SSH_SESSION_ERROR"


def _is_tcp_port_in_use(bind_host: str, port: int, timeout: float = 0.25) -> bool:
    """Returns True if a TCP listener is already accepting connections on (bind_host, port)."""
    if port <= 0:
        return False
    target = "127.0.0.1" if bind_host == "localhost" else bind_host
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((target, port)) == 0
    except OSError:
        return False


@dataclass
class SshTunnelConfig:
    """Explicit configuration for an authorized SSH server. No default hosts or credentials."""
    host: str
    username: str
    identity_file: str
    known_hosts_file: str
    port: int = 22
    local_bind_host: str = "127.0.0.1"
    local_socks_port: int = 1080
    connect_timeout_s: int = 6
    server_alive_interval_s: int = 15
    server_alive_count_max: int = 2
    authorized: bool = False

    @property
    def is_loopback_target(self) -> bool:
        """True if this SSH config targets a local loopback SSH server (127.0.0.1 / ::1 / localhost)."""
        return is_loopback_host(self.host)

    def validate(self, strict_crypto: bool = False) -> Dict[str, Any]:
        """Validates security invariants before spawning any SSH process.

        When strict_crypto=True (always enabled on real process spawn in SshSocksTunnel.start()),
        additionally verifies IdentityFile PEM/OpenSSH key headers and exact (host, port)
        cryptographic pinning in known_hosts.
        """
        if not self.authorized:
            return {"valid": False, "error": "SSH server is not marked as authorized"}
        if not self.host or not self.host.strip():
            return {"valid": False, "error": "SSH host must be explicitly configured"}
        if not self.username or not self.username.strip():
            return {"valid": False, "error": "SSH username must be explicitly configured"}
        if not (1 <= self.port <= 65535):
            return {"valid": False, "error": f"Invalid SSH port: {self.port}"}
        if not (0 <= self.local_socks_port <= 65535):
            return {"valid": False, "error": f"Invalid local SOCKS5 port: {self.local_socks_port}"}

        if self.local_bind_host not in ("127.0.0.1", "::1", "localhost"):
            return {
                "valid": False,
                "error": "local_bind_host must be loopback (127.0.0.1 or ::1) to prevent exposing local proxy",
            }

        key_path = Path(self.identity_file)
        if not key_path.is_file():
            return {"valid": False, "error": f"IdentityFile does not exist: {self.identity_file}"}

        if os.name == "posix":
            mode = stat.S_IMODE(key_path.stat().st_mode)
            if mode & 0o077:
                return {
                    "valid": False,
                    "error": f"Insecure IdentityFile permissions ({oct(mode)}); expected 0o600 or 0o400",
                }

        kh_path = Path(self.known_hosts_file)
        if not kh_path.is_file() or kh_path.stat().st_size == 0:
            return {
                "valid": False,
                "error": f"Valid non-empty known_hosts file required for StrictHostKeyChecking: {self.known_hosts_file}",
            }

        if strict_crypto:
            id_audit = inspect_ssh_identity_file(self.identity_file)
            if not id_audit["valid"]:
                return {"valid": False, "error": id_audit["error"]}

            kh_audit = verify_known_hosts_entry(self.known_hosts_file, self.host, self.port)
            if not kh_audit["valid"]:
                return {"valid": False, "error": kh_audit["error"]}

            return {
                "valid": True,
                "key_format": id_audit["key_format"],
                "hostkey_fingerprints": kh_audit["fingerprints"],
                "error": None,
            }

        return {"valid": True, "error": None}


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise SshTunnelError("Unexpected EOF during SOCKS5 negotiation")
        buf.extend(chunk)
    return bytes(buf)


def socks5_greeting_probe(socks_host: str, socks_port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Verifies RFC 1928 SOCKS5 method negotiation (proves a real SOCKS5 server, not just an open port)."""
    start = time.perf_counter()
    try:
        with socket.create_connection((socks_host, socks_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # VER=5, NMETHODS=1, METHODS=[0x00 (NO AUTH)]
            sock.sendall(b"\x05\x01\x00")
            reply = _recv_exact(sock, 2)
            ver, method = struct.unpack("!BB", reply)
            if ver != 0x05 or method != 0x00:
                return {
                    "socks5_ready": False,
                    "latency_ms": None,
                    "error": f"Invalid SOCKS5 greeting reply: ver={ver:#x}, method={method:#x}",
                }
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return {"socks5_ready": True, "latency_ms": latency_ms, "error": None}
    except (OSError, SshTunnelError) as exc:
        return {"socks5_ready": False, "latency_ms": None, "error": redact_secrets(str(exc))}


def socks5_open_tunnel_socket(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 4.5,
) -> socket.socket:
    """Opens a TCP stream to (target_host, target_port) relayed through an RFC 1928 SOCKS5 proxy."""
    sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        ver, method = struct.unpack("!BB", _recv_exact(sock, 2))
        if ver != 0x05 or method != 0x00:
            raise SshTunnelError(f"SOCKS5 auth negotiation rejected (ver={ver}, method={method})")

        # Build CONNECT request (CMD = 0x01; triggers SSH RFC 4254 direct-tcpip channel on remote sshd)
        try:
            ip_obj = ipaddress.ip_address(target_host)
            if ip_obj.version == 4:
                addr_bytes = b"\x01" + ip_obj.packed
            else:
                addr_bytes = b"\x04" + ip_obj.packed
        except ValueError:
            host_bytes = target_host.encode("idna")
            if len(host_bytes) > 255:
                raise SshTunnelError("Target hostname exceeds 255 bytes for SOCKS5 ATYP=3")
            addr_bytes = b"\x03" + bytes([len(host_bytes)]) + host_bytes

        req = b"\x05\x01\x00" + addr_bytes + struct.pack("!H", target_port)
        sock.sendall(req)

        ver, rep, _rsv, atyp = struct.unpack("!BBBB", _recv_exact(sock, 4))
        if ver != 0x05:
            raise SshTunnelError(f"Invalid SOCKS5 reply version: {ver}")
        if rep != 0x00:
            raise SshTunnelError(f"SOCKS5 CONNECT / SSH direct-tcpip failed with reply code {rep:#x}")

        # Consume BND.ADDR and BND.PORT
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        elif atyp == 0x03:
            alen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, alen + 2)
        else:
            raise SshTunnelError(f"Unknown SOCKS5 address type {atyp:#x}")

        return sock
    except Exception:
        sock.close()
        raise


def probe_https_over_socks5(
    socks_host: str,
    socks_port: int,
    target_host: str = "example.com",
    target_port: int = 443,
    path: str = "/",
    expected_status: int = 200,
    expected_substring: str = "Example Domain",
    timeout: float = 5.0,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Verifies real encrypted HTTPS egress routed through the local SOCKS5 dynamic tunnel."""
    start = time.perf_counter()
    tls_verified = False
    tunnel_stream_forwarded = False
    try:
        raw_tunneled = socks5_open_tunnel_socket(
            socks_host=socks_host,
            socks_port=socks_port,
            target_host=target_host,
            target_port=target_port,
            timeout=timeout,
        )
        tunnel_stream_forwarded = True
        context = ssl_context or _create_verified_ssl_context()
        with context.wrap_socket(raw_tunneled, server_hostname=target_host) as tls_sock:
            if not tls_sock.getpeercert():
                raise ssl.SSLError("Empty peer X.509 certificate over SOCKS5")
            tls_verified = True
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"User-Agent: JARO-WPF/2.0 SSH-SOCKS5-Prober\r\n"
                f"Connection: close\r\n\r\n"
            )
            req_bytes = req.encode("ascii")
            tls_sock.sendall(req_bytes)
            resp = http.client.HTTPResponse(tls_sock)
            resp.begin()
            status = resp.status
            raw_body = resp.read(4096)
            body = raw_body.decode("utf-8", errors="replace")

        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        bytes_estimated = len(req_bytes) + len(raw_body) + 2300
        status_ok = status == expected_status
        content_ok = (expected_substring in body) if expected_substring else True
        egress_ok = tls_verified and status_ok and content_ok

        return {
            "layer": "SSH_SOCKS5_EGRESS",
            "socks_endpoint": f"{socks_host}:{socks_port}",
            "target_host": target_host,
            "tunnel_stream_forwarded": tunnel_stream_forwarded,
            "tls_verified": tls_verified,
            "status_code": status,
            "real_internet": egress_ok,
            "latency_ms": latency_ms,
            "bytes_estimated": bytes_estimated,
            "error": None if egress_ok else f"Unexpected status ({status}) or content mismatch",
        }
    except Exception as exc:
        return {
            "layer": "SSH_SOCKS5_EGRESS",
            "socks_endpoint": f"{socks_host}:{socks_port}",
            "target_host": target_host,
            "tunnel_stream_forwarded": tunnel_stream_forwarded,
            "tls_verified": tls_verified,
            "status_code": None,
            "real_internet": False,
            "latency_ms": None,
            "bytes_estimated": 512 if tunnel_stream_forwarded else 128,
            "error": redact_secrets(f"{exc.__class__.__name__}: {exc}"),
        }


class SshSocksTunnel:
    """Manages an OpenSSH dynamic SOCKS5 forwarding process with strict crypto validation and safe teardown."""

    def __init__(
        self,
        config: SshTunnelConfig,
        ssh_binary: Optional[str] = None,
    ) -> None:
        self.config = config
        self.ssh_binary = ssh_binary or shutil.which("ssh")
        self._proc: Optional[subprocess.Popen[str]] = None

    def build_command(self) -> List[str]:
        """Builds a hardened, non-interactive ssh -D command line."""
        if not self.ssh_binary:
            raise SshTunnelError("System 'ssh' client binary not found in PATH")
        validation = self.config.validate()
        if not validation["valid"]:
            raise SshTunnelError(str(validation["error"]))

        if self.config.local_socks_port == 0:
            raise SshTunnelError("Explicit non-zero local_socks_port required before building command")

        return [
            self.ssh_binary,
            "-N",
            "-T",
            "-D",
            f"{self.config.local_bind_host}:{self.config.local_socks_port}",
            "-p",
            str(self.config.port),
            "-i",
            self.config.identity_file,
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ChallengeResponseAuthentication=no",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.config.known_hosts_file}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            f"ConnectTimeout={self.config.connect_timeout_s}",
            "-o",
            f"ServerAliveInterval={self.config.server_alive_interval_s}",
            "-o",
            f"ServerAliveCountMax={self.config.server_alive_count_max}",
            f"{self.config.username}@{self.config.host}",
        ]

    @staticmethod
    def _allocate_ephemeral_port(bind_host: str) -> int:
        target = "127.0.0.1" if bind_host == "localhost" else bind_host
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.bind((target, 0))
            return int(s.getsockname()[1])

    def is_process_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, startup_timeout_s: float = 7.0) -> Dict[str, Any]:
        """Starts the SSH tunnel after verifying pinned host keys, key headers, and port availability."""
        self.stop()

        validation = self.config.validate(strict_crypto=True)
        if not validation["valid"]:
            err = redact_secrets(validation["error"])
            return {
                "connected": False,
                "category": "application_transport",
                "protocol": "ssh_socks5",
                "scope": "LOCAL_LOOPBACK" if self.config.is_loopback_target else "REMOTE_AUTHORIZED",
                "error_code": classify_ssh_error(err),
                "error": err,
            }

        if not self.ssh_binary:
            return {
                "connected": False,
                "category": "application_transport",
                "protocol": "ssh_socks5",
                "error_code": "MISSING_SSH_BINARY",
                "error": "OpenSSH binary ('ssh') not installed on system",
            }

        if self.config.local_socks_port == 0:
            self.config.local_socks_port = self._allocate_ephemeral_port(self.config.local_bind_host)
        elif _is_tcp_port_in_use(self.config.local_bind_host, self.config.local_socks_port):
            return {
                "connected": False,
                "category": "application_transport",
                "protocol": "ssh_socks5",
                "error_code": "PORT_FORWARD_FAILED",
                "error": (
                    f"Port collision: {self.config.local_bind_host}:{self.config.local_socks_port} "
                    f"is already bound by another local listener"
                ),
            }

        cmd = self.build_command()
        start_ts = time.perf_counter()
        popen_kwargs: Dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.PIPE,
            "text": True,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True

        try:
            self._proc = subprocess.Popen(cmd, **popen_kwargs)
        except OSError as exc:
            self._proc = None
            err = redact_secrets(f"Failed to spawn ssh: {exc}")
            return {
                "connected": False,
                "category": "application_transport",
                "protocol": "ssh_socks5",
                "error_code": "SSH_SESSION_ERROR",
                "error": err,
            }

        deadline = time.monotonic() + startup_timeout_s
        last_probe_err: Optional[str] = None
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                stderr_out = ""
                if self._proc.stderr:
                    stderr_out = redact_secrets(self._proc.stderr.read().strip())
                rc = self._proc.returncode
                self.stop()
                err_msg = stderr_out or f"ssh process exited prematurely with code {rc}"
                return {
                    "connected": False,
                    "category": "application_transport",
                    "protocol": "ssh_socks5",
                    "exit_code": rc,
                    "error_code": classify_ssh_error(err_msg),
                    "error": err_msg,
                }

            probe = socks5_greeting_probe(
                self.config.local_bind_host,
                self.config.local_socks_port,
                timeout=0.4,
            )
            if probe["socks5_ready"] and self.is_process_running():
                setup_ms = round((time.perf_counter() - start_ts) * 1000, 2)
                return {
                    "connected": True,
                    "category": "application_transport",
                    "protocol": "ssh_socks5",
                    "scope": "LOCAL_LOOPBACK" if self.config.is_loopback_target else "REMOTE_AUTHORIZED",
                    "socks_host": self.config.local_bind_host,
                    "socks_port": self.config.local_socks_port,
                    "setup_time_ms": setup_ms,
                    "socks5_latency_ms": probe["latency_ms"],
                    "hostkey_fingerprints": validation.get("hostkey_fingerprints", []),
                    "pid": self._proc.pid,
                    "error_code": "NONE",
                    "error": None,
                }
            last_probe_err = probe["error"]
            time.sleep(0.08)

        self.stop()
        err_timeout = redact_secrets(f"Timed out waiting for SSH SOCKS5 listener ({last_probe_err})")
        return {
            "connected": False,
            "category": "application_transport",
            "protocol": "ssh_socks5",
            "error_code": "CONNECTION_TIMED_OUT",
            "error": err_timeout,
        }

    def check_health(
        self,
        verify_https_egress: bool = True,
        target_host: str = "example.com",
        target_port: int = 443,
        path: str = "/",
        expected_status: int = 200,
        expected_substring: str = "Example Domain",
        timeout: float = 4.5,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> Dict[str, Any]:
        """Performs live SSH tunnel verification across distinct layers:
        1. local_socks5_functional         (RFC 1928 method negotiation on local listener)
        2. direct_tcpip_channel_functional (SSH RFC 4254 channel forwarding over active session)
        3. local_ssh_tunnel_functional     (True when target SSH host is loopback and channel works)
        4. remote_ssh_tunnel_functional    (True ONLY when target SSH host is non-loopback remote and channel works)
        5. https_egress_verified           (End-to-end X.509 TLS + HTTP status + payload over SSH)
        """
        is_loopback = self.config.is_loopback_target
        scope = "LOCAL_LOOPBACK" if is_loopback else "REMOTE_AUTHORIZED"

        if not self.is_process_running():
            return {
                "healthy": False,
                "scope": scope,
                "process_alive": False,
                "socks5_ready": False,
                "local_socks5_functional": False,
                "direct_tcpip_channel_functional": False,
                "local_ssh_tunnel_functional": False,
                "remote_ssh_tunnel_functional": False,
                "https_egress_verified": False,
                "real_internet": False,
                "latency_ms": None,
                "bytes_estimated": 0,
                "error": "SSH tunnel process is not running",
            }

        greeting = socks5_greeting_probe(
            self.config.local_bind_host,
            self.config.local_socks_port,
            timeout=1.5,
        )
        if not greeting["socks5_ready"]:
            return {
                "healthy": False,
                "scope": scope,
                "process_alive": True,
                "socks5_ready": False,
                "local_socks5_functional": False,
                "direct_tcpip_channel_functional": False,
                "local_ssh_tunnel_functional": False,
                "remote_ssh_tunnel_functional": False,
                "https_egress_verified": False,
                "real_internet": False,
                "latency_ms": None,
                "bytes_estimated": 64,
                "error": greeting["error"],
            }

        if not verify_https_egress:
            return {
                "healthy": False,
                "scope": scope,
                "process_alive": True,
                "socks5_ready": True,
                "local_socks5_functional": True,
                "direct_tcpip_channel_functional": False,
                "local_ssh_tunnel_functional": False,
                "remote_ssh_tunnel_functional": False,
                "https_egress_verified": False,
                "real_internet": False,
                "latency_ms": greeting["latency_ms"],
                "bytes_estimated": 64,
                "error": "SSH direct-tcpip stream forwarding and HTTPS egress verification skipped",
            }

        egress = probe_https_over_socks5(
            socks_host=self.config.local_bind_host,
            socks_port=self.config.local_socks_port,
            target_host=target_host,
            target_port=target_port,
            path=path,
            expected_status=expected_status,
            expected_substring=expected_substring,
            timeout=timeout,
            ssl_context=ssl_context,
        )
        stream_forwarded = bool(egress.get("tunnel_stream_forwarded"))
        https_ok = bool(egress.get("real_internet"))
        return {
            "healthy": stream_forwarded and https_ok,
            "scope": scope,
            "process_alive": True,
            "socks5_ready": True,
            "local_socks5_functional": True,
            "direct_tcpip_channel_functional": stream_forwarded,
            "local_ssh_tunnel_functional": bool(stream_forwarded and is_loopback),
            "remote_ssh_tunnel_functional": bool(stream_forwarded and not is_loopback),
            "https_egress_verified": https_ok,
            "real_internet": https_ok,
            "latency_ms": egress.get("latency_ms"),
            "bytes_estimated": int(egress.get("bytes_estimated", 0)) + 64,
            "error": egress.get("error"),
        }

    def reconnect(
        self,
        reconnector: Optional[ExponentialBackoffReconnector] = None,
        startup_timeout_s: float = 7.0,
    ) -> Dict[str, Any]:
        """Safely restarts the SSH tunnel using ExponentialBackoffReconnector, aborting on security errors."""
        mgr = reconnector or ExponentialBackoffReconnector(
            base_delay=1.0,
            max_delay=15.0,
            max_attempts=3,
        )

        non_retryable_codes = {
            "HOST_KEY_VERIFICATION_FAILED",
            "PUBLICKEY_AUTH_REJECTED",
            "UNAUTHORIZED_SERVER",
            "MISSING_SSH_BINARY",
            "PORT_FORWARD_FAILED",
        }

        def _non_retryable(res: Dict[str, Any]) -> bool:
            code = str(res.get("error_code") or "")
            if code in non_retryable_codes:
                return True
            err = str(res.get("error") or "")
            return (
                "not marked as authorized" in err
                or "IdentityFile" in err
                or "known_hosts" in err
                or "not installed" in err
            )

        return mgr.execute_with_retry(
            connect_fn=lambda: self.start(startup_timeout_s=startup_timeout_s),
            is_success_fn=lambda r: bool(r.get("connected")),
            should_abort_fn=_non_retryable,
        )

    def stop(self) -> None:
        """Deterministically terminates the SSH process group and closes file descriptors."""
        if self._proc is None:
            return
        proc = self._proc
        self._proc = None
        try:
            if proc.poll() is None:
                if os.name == "posix":
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except OSError:
                        proc.terminate()
                else:
                    proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    if os.name == "posix":
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except OSError:
                            proc.kill()
                    else:
                        proc.kill()
                    proc.wait(timeout=2.0)
        except OSError:
            pass
        finally:
            if proc.stderr:
                try:
                    proc.stderr.close()
                except OSError:
                    pass

    def __enter__(self) -> "SshSocksTunnel":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
