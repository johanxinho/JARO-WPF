"""JARO WPF - Real Local Loopback Tunnel Laboratories for OpenSSH (`sshd`) and WireGuard (Phase 5).

Provides two real end-to-end local protocol laboratories:
1. LocalOpenSshLoopbackLab:
   - Spawns real system OpenSSH Server (`/usr/sbin/sshd`) unprivileged on `127.0.0.1:<ephemeral_port>`.
   - Verifies host-key MITM rejection, unauthorized client key rejection, Ed25519 public-key auth,
     local SOCKS5 negotiation, RFC 4254 `direct-tcpip` channel forwarding to a local TLS/HTTPS server,
     disconnection + automatic reconnection, and deterministic process teardown.
   - Explicitly confirms remote SSH readiness remains `REMOTE_SERVER_REQUIRED` when no external server exists.

2. LocalWireGuardLoopbackLab:
   - Strictly gated by PrivilegePolicyGate (`authorize_privileged_lab=False` by default — NEVER invokes
     sudo or mutates interfaces/namespaces without explicit approval).
   - Uses WireGuard's socket-namespace isolation (`wg_jaro0` in host netns `10.199.77.1/30` <-> `wg_jaro1`
     in ephemeral netns `jaro_wg_ns` `10.199.77.2/30` communicating over `127.0.0.1` UDP) so packets
     genuinely traverse kernel Noise_IKpsk2 + ChaCha20-Poly1305 encryption instead of bypassing via
     Linux `table local`, while keeping the host's default route 100% untouched.
   - Verifies handshake, RX/TX byte deltas, HTTPS over WireGuard, route isolation, tunnel recovery,
     and complete teardown (`ip link del` + `ip netns del`).
"""
import base64
from datetime import datetime, timezone
import getpass
import os
from pathlib import Path
import shutil
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from core.connection.reconnector import ExponentialBackoffReconnector
from core.connection.server_manager import ServerManager, ServerStatus
from core.network_tests.network_lab import (
    ExecutionScope,
    LabTestRecord,
    _generate_lab_pki,
    measure_process_resources,
)
from core.protocols.ssh_engine import SshSocksTunnel, SshTunnelConfig
from core.protocols.vpn_tunnel_engine import (
    WireGuardTunnelEngine,
    detect_wireguard_tooling,
    inspect_routing_table,
    parse_wg_dump_output,
    verify_route_isolation,
)
from core.security.secret_guard import (
    PrivilegePolicyGate,
    protect_sensitive_file,
    redact_secrets,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _free_tcp_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def _free_udp_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def generate_ephemeral_wg_keypair() -> tuple[str, str]:
    """Generates an ephemeral Curve25519 keypair strictly for isolated local loopback testing."""
    priv_obj = x25519.X25519PrivateKey.generate()
    priv_raw = priv_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(priv_raw).decode("ascii"),
        base64.b64encode(pub_raw).decode("ascii"),
    )


class _LoopbackHttpsServer:
    """Minimal multi-request TLS HTTPS server on 127.0.0.1 for local tunnel relay verification."""

    def __init__(self, cert_file: Path, key_file: Path, bind_host: str = "127.0.0.1") -> None:
        self.bind_host = bind_host
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, 0))
        self._sock.listen(8)
        self._sock.settimeout(0.25)
        self.port = int(self._sock.getsockname()[1])

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(cert_file), str(key_file))
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(2.0)
                with self._ctx.wrap_socket(conn, server_side=True) as tls_c:
                    tls_c.recv(2048)
                    body = b"JARO-PHASE5-SSH-DIRECT-TCPIP-VERIFIED"
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        + f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n".encode("ascii")
                        + body
                    )
                    tls_c.sendall(resp)
            except Exception:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)


class LocalOpenSshLoopbackLab:
    """Executes real unprivileged OpenSSH Server (`sshd`) loopback tunnel verification."""

    def __init__(self, server_manager: Optional[ServerManager] = None) -> None:
        self.server_manager = server_manager or ServerManager()

    @staticmethod
    def find_sshd_binary() -> Optional[str]:
        return shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").is_file() else None)

    @staticmethod
    def _select_strictmodes_parent() -> Optional[Path]:
        """Selects a parent directory satisfying OpenSSH auth_secure_path() (no group/other write from / down)."""
        if os.name != "posix":
            return None
        uid = os.geteuid()
        try:
            import pwd
            candidate = Path(pwd.getpwuid(uid).pw_dir).resolve()
        except (ImportError, KeyError, OSError):
            candidate = Path.home().resolve()
        if not candidate.is_dir():
            return None
        chain = [candidate, *candidate.parents]
        for ancestor in chain:
            try:
                st = ancestor.stat()
            except OSError:
                return None
            if st.st_uid not in (0, uid) or (st.st_mode & 0o022) != 0:
                return None
        return candidate

    @staticmethod
    def _generate_openssh_key(keygen_bin: str, target_path: Path, comment: str) -> None:
        res = subprocess.run(
            [keygen_bin, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(target_path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode != 0:
            raise RuntimeError(f"ssh-keygen failed: {res.stderr.strip()}")
        protect_sensitive_file(target_path, 0o600)

    def _start_unprivileged_sshd(
        self,
        sshd_bin: str,
        cfg_path: Path,
        port: int,
    ) -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [sshd_bin, "-D", "-e", "-f", str(cfg_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=(os.name == "posix"),
        )
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                err = proc.stderr.read().strip() if proc.stderr else ""
                raise RuntimeError(f"sshd exited early ({proc.returncode}): {redact_secrets(err)}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    return proc
            time.sleep(0.06)
        self._stop_proc(proc)
        raise RuntimeError(f"Timed out waiting for local sshd to listen on 127.0.0.1:{port}")

    @staticmethod
    def _stop_proc(proc: Optional[subprocess.Popen[str]]) -> None:
        if proc is None:
            return
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
                    proc.kill()
                    proc.wait(timeout=2.0)
        finally:
            if proc.stderr:
                try:
                    proc.stderr.close()
                except OSError:
                    pass

    def run(self) -> Dict[str, Any]:
        """Runs the complete local OpenSSH Server (`sshd`) loopback test suite."""
        t_suite = time.perf_counter()
        res_before = measure_process_resources()
        records: List[LabTestRecord] = []

        sshd_bin = self.find_sshd_binary()
        keygen_bin = shutil.which("ssh-keygen")
        ssh_bin = shutil.which("ssh")

        remote_readiness = self.server_manager.evaluate_remote_tunnel_readiness("ssh_socks5")

        if not sshd_bin or not keygen_bin or not ssh_bin:
            missing = [
                name
                for name, val in (("sshd", sshd_bin), ("ssh-keygen", keygen_bin), ("ssh", ssh_bin))
                if not val
            ]
            records.append(
                LabTestRecord(
                    test_id="ssh_local_openssh_suite",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server="127.0.0.1",
                    protocol="ssh_socks5",
                    timestamp_utc=_utc_now(),
                    duration_ms=round((time.perf_counter() - t_suite) * 1000, 2),
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=f"Missing required OpenSSH binaries: {', '.join(missing)}",
                )
            )
            res_after = measure_process_resources()
            return {
                "lab": "LOCAL_OPENSSH_LOOPBACK_LAB",
                "status": "SKIPPED_MISSING_PREREQUISITE",
                "remote_ssh_status": remote_readiness["status"],
                "records": [r.to_dict() for r in records],
                "resources": {
                    "vm_rss_mb": res_after["vm_rss_mb"],
                    "vm_hwm_mb": res_after["vm_hwm_mb"],
                    "cpu_seconds_used": round(res_after["cpu_total_s"] - res_before["cpu_total_s"], 4),
                },
            }

        try:
            import pwd
            current_user = pwd.getpwuid(os.geteuid()).pw_name
        except (ImportError, KeyError, OSError):
            current_user = getpass.getuser()
        strict_parent = self._select_strictmodes_parent()
        strict_modes_val = "yes" if strict_parent is not None else "no"
        with tempfile.TemporaryDirectory(prefix=".jaro_sshd_lab_", dir=strict_parent) as tmp:
            tmpdir = Path(tmp)
            os.chmod(tmpdir, 0o700)

            pki = _generate_lab_pki(tmpdir)
            trusted_ctx = ssl.create_default_context(cafile=str(pki["ca"]))
            trusted_ctx.check_hostname = True
            trusted_ctx.verify_mode = ssl.CERT_REQUIRED

            host_key = tmpdir / "ssh_host_ed25519_key"
            rogue_host_key = tmpdir / "rogue_host_ed25519_key"
            client_key = tmpdir / "client_ed25519"
            rogue_client_key = tmpdir / "rogue_client_ed25519"

            self._generate_openssh_key(keygen_bin, host_key, "jaro-local-sshd-host")
            self._generate_openssh_key(keygen_bin, rogue_host_key, "jaro-rogue-host")
            self._generate_openssh_key(keygen_bin, client_key, "jaro-authorized-client")
            self._generate_openssh_key(keygen_bin, rogue_client_key, "jaro-unauthorized-client")

            auth_keys = tmpdir / "authorized_keys"
            auth_keys.write_text(Path(f"{client_key}.pub").read_text(encoding="utf-8"), encoding="utf-8")
            protect_sensitive_file(auth_keys, 0o600)

            sshd_port = _free_tcp_port("127.0.0.1")
            host_pub_parts = Path(f"{host_key}.pub").read_text(encoding="utf-8").strip().split()
            rogue_pub_parts = Path(f"{rogue_host_key}.pub").read_text(encoding="utf-8").strip().split()

            known_hosts = tmpdir / "known_hosts"
            known_hosts.write_text(
                f"[127.0.0.1]:{sshd_port} {host_pub_parts[0]} {host_pub_parts[1]}\n",
                encoding="utf-8",
            )
            bad_known_hosts = tmpdir / "bad_known_hosts"
            bad_known_hosts.write_text(
                f"[127.0.0.1]:{sshd_port} {rogue_pub_parts[0]} {rogue_pub_parts[1]}\n",
                encoding="utf-8",
            )

            sshd_cfg = tmpdir / "sshd_config"
            sshd_cfg.write_text(
                f"Port {sshd_port}\n"
                f"ListenAddress 127.0.0.1\n"
                f"HostKey {host_key}\n"
                f"PidFile {tmpdir / 'sshd.pid'}\n"
                f"AuthorizedKeysFile {auth_keys}\n"
                f"StrictModes {strict_modes_val}\n"
                f"UsePAM no\n"
                f"PasswordAuthentication no\n"
                f"KbdInteractiveAuthentication no\n"
                f"PubkeyAuthentication yes\n"
                f"PermitRootLogin {'yes' if current_user == 'root' else 'no'}\n"
                f"AllowUsers {current_user}\n"
                f"AllowTcpForwarding yes\n"
                f"X11Forwarding no\n"
                f"PrintMotd no\n",
                encoding="utf-8",
            )

            https_srv = _LoopbackHttpsServer(pki["valid_cert"], pki["valid_key"])
            https_srv.start()
            sshd_proc: Optional[subprocess.Popen[str]] = None

            try:
                sshd_proc = self._start_unprivileged_sshd(sshd_bin, sshd_cfg, sshd_port)

                # 1. Host-key MITM rejection test
                t0 = time.perf_counter()
                mitm_tun = SshSocksTunnel(
                    SshTunnelConfig(
                        host="127.0.0.1",
                        port=sshd_port,
                        username=current_user,
                        identity_file=str(client_key),
                        known_hosts_file=str(bad_known_hosts),
                        local_socks_port=0,
                        connect_timeout_s=3,
                        authorized=True,
                    )
                )
                mitm_res = mitm_tun.start(startup_timeout_s=3.5)
                mitm_tun.stop()
                mitm_rejected = (not mitm_res["connected"]) and (
                    mitm_res.get("error_code") == "HOST_KEY_VERIFICATION_FAILED"
                )
                records.append(
                    LabTestRecord(
                        test_id="ssh_local_hostkey_mitm_rejected",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=f"127.0.0.1:{sshd_port}",
                        protocol="ssh_hostkey",
                        timestamp_utc=_utc_now(),
                        duration_ms=(time.perf_counter() - t0) * 1000,
                        bytes_estimated=900,
                        verified_real=mitm_rejected,
                        result="PASS" if mitm_rejected else "FAIL",
                        reason=None if mitm_rejected else f"Unexpected MITM result: {mitm_res}",
                        details={"error_code": mitm_res.get("error_code")},
                    )
                )

                # 2. Unauthorized public-key rejection test
                t1 = time.perf_counter()
                unauth_key_tun = SshSocksTunnel(
                    SshTunnelConfig(
                        host="127.0.0.1",
                        port=sshd_port,
                        username=current_user,
                        identity_file=str(rogue_client_key),
                        known_hosts_file=str(known_hosts),
                        local_socks_port=0,
                        connect_timeout_s=3,
                        authorized=True,
                    )
                )
                unauth_res = unauth_key_tun.start(startup_timeout_s=3.5)
                unauth_key_tun.stop()
                unauth_rejected = (not unauth_res["connected"]) and (
                    unauth_res.get("error_code") == "PUBLICKEY_AUTH_REJECTED"
                )
                records.append(
                    LabTestRecord(
                        test_id="ssh_local_unauthorized_pubkey_rejected",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=f"127.0.0.1:{sshd_port}",
                        protocol="ssh_pubkey_auth",
                        timestamp_utc=_utc_now(),
                        duration_ms=(time.perf_counter() - t1) * 1000,
                        bytes_estimated=1100,
                        verified_real=unauth_rejected,
                        result="PASS" if unauth_rejected else "FAIL",
                        reason=None if unauth_rejected else f"Unexpected auth result: {unauth_res}",
                        details={"error_code": unauth_res.get("error_code")},
                    )
                )

                # 3, 4, 5, 6. Valid Ed25519 key auth + SOCKS5 + direct-tcpip HTTPS + Reconnect + Clean Teardown
                valid_cfg = SshTunnelConfig(
                    host="127.0.0.1",
                    port=sshd_port,
                    username=current_user,
                    identity_file=str(client_key),
                    known_hosts_file=str(known_hosts),
                    local_socks_port=0,
                    connect_timeout_s=4,
                    authorized=True,
                )
                with SshSocksTunnel(valid_cfg) as tun:
                    t2 = time.perf_counter()
                    start_res = tun.start(startup_timeout_s=5.0)
                    dur_start = (time.perf_counter() - t2) * 1000
                    auth_ok = bool(start_res.get("connected"))
                    socks_port = valid_cfg.local_socks_port
                    records.append(
                        LabTestRecord(
                            test_id="ssh_local_ed25519_auth_and_socks5",
                            execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                            server=f"127.0.0.1:{sshd_port}",
                            protocol="ssh_socks5",
                            timestamp_utc=_utc_now(),
                            duration_ms=dur_start,
                            bytes_estimated=2100,
                            verified_real=auth_ok,
                            result="PASS" if auth_ok else "FAIL",
                            reason=start_res.get("error"),
                            details={
                                "socks_port": socks_port,
                                "setup_time_ms": start_res.get("setup_time_ms"),
                                "hostkey_fingerprints": start_res.get("hostkey_fingerprints"),
                            },
                        )
                    )

                    # 4. Real direct-tcpip channel + TLS 1.3 HTTPS transfer through OpenSSH sshd
                    t3 = time.perf_counter()
                    health = tun.check_health(
                        verify_https_egress=True,
                        target_host="localhost",
                        target_port=https_srv.port,
                        path="/",
                        expected_status=200,
                        expected_substring="JARO-PHASE5-SSH-DIRECT-TCPIP-VERIFIED",
                        timeout=4.0,
                        ssl_context=trusted_ctx,
                    )
                    dur_h = (time.perf_counter() - t3) * 1000
                    dtcp_ok = bool(
                        health["healthy"]
                        and health["local_socks5_functional"]
                        and health["direct_tcpip_channel_functional"]
                        and health["local_ssh_tunnel_functional"]
                        and not health["remote_ssh_tunnel_functional"]  # Strictly False for loopback!
                        and health["https_egress_verified"]
                    )
                    records.append(
                        LabTestRecord(
                            test_id="ssh_local_direct_tcpip_https_transfer",
                            execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                            server=f"127.0.0.1:{sshd_port}",
                            protocol="ssh_direct_tcpip_https",
                            timestamp_utc=_utc_now(),
                            duration_ms=dur_h,
                            bytes_estimated=int(health.get("bytes_estimated", 2600)),
                            verified_real=dtcp_ok,
                            result="PASS" if dtcp_ok else "FAIL",
                            reason=health.get("error"),
                            details={
                                "latency_ms": health.get("latency_ms"),
                                "local_ssh_tunnel_functional": health["local_ssh_tunnel_functional"],
                                "remote_ssh_tunnel_functional": health["remote_ssh_tunnel_functional"],
                            },
                        )
                    )

                    # 5. Simulate abrupt SSH client/server drop & verify live reconnect()
                    t4 = time.perf_counter()
                    self._stop_proc(sshd_proc)
                    tun.stop()
                    sshd_proc = self._start_unprivileged_sshd(sshd_bin, sshd_cfg, sshd_port)
                    valid_cfg.local_socks_port = 0
                    reconn_out = tun.reconnect(
                        reconnector=ExponentialBackoffReconnector(base_delay=0.05, max_attempts=3),
                        startup_timeout_s=5.0,
                    )
                    post_reconn_health = tun.check_health(
                        verify_https_egress=True,
                        target_host="localhost",
                        target_port=https_srv.port,
                        path="/",
                        expected_status=200,
                        expected_substring="JARO-PHASE5-SSH-DIRECT-TCPIP-VERIFIED",
                        timeout=4.0,
                        ssl_context=trusted_ctx,
                    )
                    dur_rec = (time.perf_counter() - t4) * 1000
                    rec_ok = bool(reconn_out.get("connected") and post_reconn_health.get("https_egress_verified"))
                    records.append(
                        LabTestRecord(
                            test_id="ssh_local_disconnect_and_reconnect",
                            execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                            server=f"127.0.0.1:{sshd_port}",
                            protocol="ssh_socks5",
                            timestamp_utc=_utc_now(),
                            duration_ms=dur_rec,
                            bytes_estimated=3200,
                            verified_real=rec_ok,
                            result="PASS" if rec_ok else "FAIL",
                            reason=post_reconn_health.get("error"),
                            details={"attempts_used": reconn_out.get("attempts_used")},
                        )
                    )
                    reconnected_port = valid_cfg.local_socks_port

                # 6. Verify clean teardown after exiting context manager
                t5 = time.perf_counter()
                port_closed = True
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_chk:
                    s_chk.settimeout(0.2)
                    if s_chk.connect_ex(("127.0.0.1", reconnected_port)) == 0:
                        port_closed = False
                teardown_ok = (not tun.is_process_running()) and port_closed
                records.append(
                    LabTestRecord(
                        test_id="ssh_local_clean_teardown",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=f"127.0.0.1:{reconnected_port}",
                        protocol="ssh_socks5",
                        timestamp_utc=_utc_now(),
                        duration_ms=(time.perf_counter() - t5) * 1000,
                        bytes_estimated=0,
                        verified_real=teardown_ok,
                        result="PASS" if teardown_ok else "FAIL",
                        reason=None if teardown_ok else "SSH process or local SOCKS5 port remained open after stop()",
                    )
                )
            finally:
                self._stop_proc(sshd_proc)
                https_srv.stop()

        res_after = measure_process_resources()
        all_passed = all(r.result == "PASS" for r in records)
        return {
            "lab": "LOCAL_OPENSSH_LOOPBACK_LAB",
            "status": "LOCAL_VERIFIED" if all_passed else "FAILED",
            "remote_ssh_status": remote_readiness["status"],
            "remote_ssh_detail": remote_readiness,
            "counts": {
                "total": len(records),
                "passed": sum(1 for r in records if r.result == "PASS"),
                "failed": sum(1 for r in records if r.result == "FAIL"),
            },
            "external_bytes_consumed": 0,
            "loopback_bytes_estimated": sum(r.bytes_estimated for r in records),
            "resources": {
                "vm_rss_mb": res_after["vm_rss_mb"],
                "vm_hwm_mb": res_after["vm_hwm_mb"],
                "cpu_seconds_used": round(res_after["cpu_total_s"] - res_before["cpu_total_s"], 4),
            },
            "records": [r.to_dict() for r in records],
        }


class LocalWireGuardLoopbackLab:
    """Executes a real two-peer isolated kernel WireGuard lab WITHOUT touching default routes.

    Topology (only created when authorize_privileged_lab=True):
    - Host netns: `wg_jaro0` (10.199.77.1/30, UDP 127.0.0.1:<port0>)
      -> Route added ONLY for 10.199.77.0/30 dev wg_jaro0. Default route on wlp2s0/enp1s0 is UNTOUCHED.
    - Peer netns (`jaro_wg_ns`): `wg_jaro1` (10.199.77.2/30, UDP socket retained in host netns on 127.0.0.1:<port1>)
      -> Hosts a temporary TLS 1.3 HTTPS server bound to 10.199.77.2:<https_port>.
    - Guaranteed cleanup in `finally`: deletes `wg_jaro0`, `wg_jaro1` (if present), and `jaro_wg_ns`.
    """

    IFACE_A = "wg_jaro0"
    IFACE_B = "wg_jaro1"
    PEER_NETNS = "jaro_wg_ns"
    ADDR_A = "10.199.77.1/30"
    IP_A = "10.199.77.1"
    ADDR_B = "10.199.77.2/30"
    IP_B = "10.199.77.2"

    def __init__(self, server_manager: Optional[ServerManager] = None) -> None:
        self.server_manager = server_manager or ServerManager()
        # Linux interface names are limited to 15 bytes. Per-run names avoid
        # collisions with resources that belong to the user or another process.
        suffix = secrets.token_hex(4)
        self.IFACE_A = f"ja{suffix}"
        self.IFACE_B = f"jb{suffix}"
        self.PEER_NETNS = f"jaro{suffix}"

    def planned_privileged_operations(self) -> List[str]:
        """Returns the exact isolated commands required so the user can review before authorizing."""
        return [
            f"ip link add dev {self.IFACE_A} type wireguard",
            f"ip link add dev {self.IFACE_B} type wireguard",
            f"wg setconf {self.IFACE_A} <temp_0600_wg0.conf>  # ListenPort loopback, AllowedIPs {self.IP_B}/32 ONLY",
            f"wg setconf {self.IFACE_B} <temp_0600_wg1.conf>  # ListenPort loopback, AllowedIPs {self.IP_A}/32 ONLY",
            f"ip netns add {self.PEER_NETNS}",
            f"ip link set {self.IFACE_B} netns {self.PEER_NETNS}",
            f"ip addr add {self.ADDR_A} dev {self.IFACE_A} && ip link set {self.IFACE_A} up",
            f"ip -n {self.PEER_NETNS} link set lo up && ip -n {self.PEER_NETNS} addr add {self.ADDR_B} dev {self.IFACE_B} && ip -n {self.PEER_NETNS} link set {self.IFACE_B} up",
            f"Cleanup only for resources created by this run: ip link del {self.IFACE_A}; ip netns del {self.PEER_NETNS}",
        ]

    @staticmethod
    def _run_priv(cmd: List[str], use_sudo: bool, timeout: float = 6.0) -> subprocess.CompletedProcess[str]:
        full_cmd = (["sudo", "-n"] + cmd) if (use_sudo and os.geteuid() != 0) else cmd
        return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)

    def run(
        self,
        *,
        authorize_privileged_lab: bool = False,
    ) -> Dict[str, Any]:
        """Executes the two-peer WireGuard kernel lab ONLY if explicitly authorized."""
        t_suite = time.perf_counter()
        res_before = measure_process_resources()
        records: List[LabTestRecord] = []
        remote_readiness = self.server_manager.evaluate_remote_tunnel_readiness("wireguard")
        tools = detect_wireguard_tooling()

        gate = PrivilegePolicyGate(
            allow_privileged_commands=authorize_privileged_lab,
            authorize_interface_changes=authorize_privileged_lab,
            authorize_route_changes=authorize_privileged_lab,
            allow_global_routes=False,
        )
        perm = gate.check_interface_mutation(
            f"create isolated loopback WireGuard peers {self.IFACE_A}/{self.IFACE_B}",
            requires_root=True,
        )
        if not perm["allowed"]:
            records.append(
                LabTestRecord(
                    test_id="wg_local_two_peer_lab",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server=self.IFACE_A,
                    protocol="wireguard",
                    timestamp_utc=_utc_now(),
                    duration_ms=round((time.perf_counter() - t_suite) * 1000, 2),
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason=perm["reason"],
                    details={"planned_operations": self.planned_privileged_operations()},
                )
            )
            return {
                "lab": "LOCAL_WIREGUARD_LOOPBACK_LAB",
                "status": "AUTHORIZATION_REQUIRED",
                "authorization_required": True,
                "planned_operations": self.planned_privileged_operations(),
                "remote_wireguard_status": remote_readiness["status"],
                "records": [r.to_dict() for r in records],
            }

        if not tools["wg_binary"] or not tools["ip_binary"]:
            records.append(
                LabTestRecord(
                    test_id="wg_local_two_peer_lab",
                    execution_scope=ExecutionScope.SKIPPED_MISSING_PREREQUISITE,
                    server=self.IFACE_A,
                    protocol="wireguard",
                    timestamp_utc=_utc_now(),
                    duration_ms=round((time.perf_counter() - t_suite) * 1000, 2),
                    bytes_estimated=0,
                    verified_real=False,
                    result="SKIPPED",
                    reason="Missing 'wg' (wireguard-tools) or 'ip' binary on host",
                    details={"tooling": tools},
                )
            )
            return {
                "lab": "LOCAL_WIREGUARD_LOOPBACK_LAB",
                "status": "SKIPPED_MISSING_PREREQUISITE",
                "remote_wireguard_status": remote_readiness["status"],
                "records": [r.to_dict() for r in records],
            }

        ip_bin = str(tools["ip_binary"])
        wg_bin = str(tools["wg_binary"])
        use_sudo = os.geteuid() != 0
        baseline_routes = inspect_routing_table(self.IFACE_A)

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            os.chmod(tmpdir, 0o700)
            pki = _generate_lab_pki(tmpdir)
            trusted_ctx = ssl.create_default_context(cafile=str(pki["ca"]))
            trusted_ctx.check_hostname = True
            trusted_ctx.verify_mode = ssl.CERT_REQUIRED

            priv_a, pub_a = generate_ephemeral_wg_keypair()
            priv_b, pub_b = generate_ephemeral_wg_keypair()
            port_a = _free_udp_port("127.0.0.1")
            port_b = _free_udp_port("127.0.0.1")
            while port_b == port_a:
                port_b = _free_udp_port("127.0.0.1")

            # wg setconf files (no Address line — wg setconf only takes WireGuard crypto directives)
            wg0_setconf = tmpdir / "wg0_setconf.conf"
            wg0_setconf.write_text(
                f"[Interface]\nPrivateKey = {priv_a}\nListenPort = {port_a}\n\n"
                f"[Peer]\nPublicKey = {pub_b}\nEndpoint = 127.0.0.1:{port_b}\nAllowedIPs = {self.IP_B}/32\n",
                encoding="utf-8",
            )
            protect_sensitive_file(wg0_setconf, 0o600)

            wg1_setconf = tmpdir / "wg1_setconf.conf"
            wg1_setconf.write_text(
                f"[Interface]\nPrivateKey = {priv_b}\nListenPort = {port_b}\n\n"
                f"[Peer]\nPublicKey = {pub_a}\nEndpoint = 127.0.0.1:{port_a}\nAllowedIPs = {self.IP_A}/32\n",
                encoding="utf-8",
            )
            protect_sensitive_file(wg1_setconf, 0o600)

            # Full wg-quick-compatible profile for our validator audit
            wg0_full_profile = tmpdir / "wg0_profile.conf"
            wg0_full_profile.write_text(
                f"[Interface]\nPrivateKey = {priv_a}\nAddress = {self.ADDR_A}\nListenPort = {port_a}\n\n"
                f"[Peer]\nPublicKey = {pub_b}\nEndpoint = 127.0.0.1:{port_b}\nAllowedIPs = {self.IP_B}/32\n",
                encoding="utf-8",
            )
            protect_sensitive_file(wg0_full_profile, 0o600)

            netns_https_proc: Optional[subprocess.Popen[str]] = None
            https_port = 18443

            # Helper script executed inside jaro_wg_ns to serve TLS 1.3 HTTPS on 10.199.77.2:18443
            ns_srv_script = tmpdir / "ns_https_server.py"
            ns_srv_script.write_text(
                "import socket, ssl, sys\n"
                "bind_ip, port, cert_f, key_f = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]\n"
                "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
                "ctx.load_cert_chain(cert_f, key_f)\n"
                "srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                "srv.bind((bind_ip, port))\n"
                "srv.listen(5)\n"
                "print('READY', flush=True)\n"
                "for _ in range(4):\n"
                "    conn, _ = srv.accept()\n"
                "    try:\n"
                "        with ctx.wrap_socket(conn, server_side=True) as tc:\n"
                "            tc.recv(2048)\n"
                "            body = b'JARO-PHASE5-WIREGUARD-KERNEL-VERIFIED'\n"
                "            tc.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: ' + str(len(body)).encode() + b'\\r\\nConnection: close\\r\\n\\r\\n' + body)\n"
                "    except Exception:\n"
                "        conn.close()\n",
                encoding="utf-8",
            )

            created_iface_a = False
            created_iface_b = False
            created_peer_netns = False
            iface_b_moved_to_netns = False
            try:
                t0 = time.perf_counter()
                setup_steps = [
                    [ip_bin, "link", "add", "dev", self.IFACE_A, "type", "wireguard"],
                    [ip_bin, "link", "add", "dev", self.IFACE_B, "type", "wireguard"],
                    [wg_bin, "setconf", self.IFACE_A, str(wg0_setconf)],
                    [wg_bin, "setconf", self.IFACE_B, str(wg1_setconf)],
                    [ip_bin, "netns", "add", self.PEER_NETNS],
                    [ip_bin, "link", "set", self.IFACE_B, "netns", self.PEER_NETNS],
                    [ip_bin, "addr", "add", self.ADDR_A, "dev", self.IFACE_A],
                    [ip_bin, "link", "set", "mtu", "1420", "up", "dev", self.IFACE_A],
                    [ip_bin, "-n", self.PEER_NETNS, "link", "set", "lo", "up"],
                    [ip_bin, "-n", self.PEER_NETNS, "addr", "add", self.ADDR_B, "dev", self.IFACE_B],
                    [ip_bin, "-n", self.PEER_NETNS, "link", "set", "mtu", "1420", "up", "dev", self.IFACE_B],
                ]
                for step_cmd in setup_steps:
                    r = self._run_priv(step_cmd, use_sudo=use_sudo)
                    if r.returncode != 0:
                        raise RuntimeError(
                            f"WireGuard setup command failed ({step_cmd[0]} {step_cmd[1]}): "
                            f"{redact_secrets(r.stderr.strip())}"
                        )
                    if step_cmd[1:3] == ["link", "add"] and step_cmd[-1] == "wireguard":
                        if step_cmd[4] == self.IFACE_A:
                            created_iface_a = True
                        elif step_cmd[4] == self.IFACE_B:
                            created_iface_b = True
                    elif step_cmd[1:3] == ["netns", "add"]:
                        created_peer_netns = True
                    elif step_cmd[1:3] == ["link", "set"] and self.IFACE_B in step_cmd and "netns" in step_cmd:
                        iface_b_moved_to_netns = True

                records.append(
                    LabTestRecord(
                        test_id="wg_local_interface_creation_and_route_isolation",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=f"{self.IFACE_A} <-> {self.IFACE_B}",
                        protocol="wireguard",
                        timestamp_utc=_utc_now(),
                        duration_ms=(time.perf_counter() - t0) * 1000,
                        bytes_estimated=0,
                        verified_real=True,
                        result="PASS",
                        reason=None,
                    )
                )

                # Verify route isolation BEFORE traffic (default route untouched!)
                t_rt = time.perf_counter()
                active_routes = inspect_routing_table(self.IFACE_A)
                rt_audit = verify_route_isolation(
                    baseline_routes,
                    active_routes,
                    self.IFACE_A,
                    allow_global_routes=False,
                )
                records.append(
                    LabTestRecord(
                        test_id="wg_local_routing_table_safety",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=self.IFACE_A,
                        protocol="wireguard_routing",
                        timestamp_utc=_utc_now(),
                        duration_ms=(time.perf_counter() - t_rt) * 1000,
                        bytes_estimated=0,
                        verified_real=bool(rt_audit["routes_isolated_and_safe"] and rt_audit["default_route_unchanged"]),
                        result="PASS" if rt_audit["routes_isolated_and_safe"] else "FAIL",
                        reason=rt_audit.get("error"),
                        details={
                            "default_route_unchanged": rt_audit["default_route_unchanged"],
                            "tunnel_routes": rt_audit["tunnel_routes"],
                        },
                    )
                )

                # Launch TLS HTTPS server inside jaro_wg_ns bound to 10.199.77.2:18443
                ns_cmd = [
                    ip_bin,
                    "netns",
                    "exec",
                    self.PEER_NETNS,
                    sys.executable,
                    str(ns_srv_script),
                    self.IP_B,
                    str(https_port),
                    str(pki["valid_cert"]),
                    str(pki["valid_key"]),
                ]
                if use_sudo:
                    ns_cmd = ["sudo", "-n"] + ns_cmd
                netns_https_proc = subprocess.Popen(
                    ns_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                ready_line = netns_https_proc.stdout.readline().strip() if netns_https_proc.stdout else ""
                if ready_line != "READY":
                    err_s = netns_https_proc.stderr.read() if netns_https_proc.stderr else ""
                    raise RuntimeError(f"Netns HTTPS server failed to become READY: {redact_secrets(err_s)}")

                # Inspect & verify handshake + bidirectional RX/TX + HTTPS over WireGuard!
                eng = WireGuardTunnelEngine(
                    interface_name=self.IFACE_A,
                    config_path=wg0_full_profile,
                    authorized=True,
                    allow_global_routes=False,
                    privilege_gate=gate,
                )
                t_probe = time.perf_counter()
                state = eng.inspect_state(
                    verify_internet_egress=True,
                    egress_url=f"https://localhost:{https_port}/",
                    connect_host=self.IP_B,
                    sni_hostname="localhost",
                    expected_status=200,
                    expected_substring="JARO-PHASE5-WIREGUARD-KERNEL-VERIFIED",
                    ssl_context=trusted_ctx,
                )
                dur_probe = (time.perf_counter() - t_probe) * 1000

                hs_and_xfer_ok = bool(
                    state["handshake_verified"]
                    and state["data_transfer_verified"]
                    and state["rx_bytes_delta"] > 0
                    and state["tx_bytes_delta"] > 0
                    and state["https_egress_verified"]
                    and state["routes_safe"]
                )
                records.append(
                    LabTestRecord(
                        test_id="wg_local_handshake_rx_tx_and_https",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=f"{self.IP_A} -> {self.IP_B}:{https_port}",
                        protocol="wireguard_https",
                        timestamp_utc=_utc_now(),
                        duration_ms=dur_probe,
                        bytes_estimated=int(state.get("bytes_estimated", 2400)),
                        verified_real=hs_and_xfer_ok,
                        result="PASS" if hs_and_xfer_ok else "FAIL",
                        reason=state.get("note"),
                        details={
                            "handshake_verified": state["handshake_verified"],
                            "data_transfer_verified": state["data_transfer_verified"],
                            "rx_bytes_delta": state["rx_bytes_delta"],
                            "tx_bytes_delta": state["tx_bytes_delta"],
                            "egress_latency_ms": state["egress_latency_ms"],
                            "peers": state["peers"],
                        },
                    )
                )

                # Test WireGuard link interruption & recovery (link down -> fail -> link up + re-sync -> pass)
                t_rec = time.perf_counter()
                self._run_priv([ip_bin, "link", "set", "down", "dev", self.IFACE_A], use_sudo=use_sudo)
                down_state = eng.inspect_state(
                    verify_internet_egress=True,
                    egress_url=f"https://localhost:{https_port}/",
                    connect_host=self.IP_B,
                    sni_hostname="localhost",
                    expected_status=200,
                    expected_substring="JARO-PHASE5-WIREGUARD-KERNEL-VERIFIED",
                    ssl_context=trusted_ctx,
                )
                # Restore interface & routes cleanly
                self._run_priv([ip_bin, "link", "set", "up", "dev", self.IFACE_A], use_sudo=use_sudo)
                rec_state = eng.inspect_state(
                    verify_internet_egress=True,
                    egress_url=f"https://localhost:{https_port}/",
                    connect_host=self.IP_B,
                    sni_hostname="localhost",
                    expected_status=200,
                    expected_substring="JARO-PHASE5-WIREGUARD-KERNEL-VERIFIED",
                    ssl_context=trusted_ctx,
                )
                rec_ok = (not down_state["https_egress_verified"]) and bool(
                    rec_state["https_egress_verified"] and rec_state["rx_bytes_delta"] > 0
                )
                records.append(
                    LabTestRecord(
                        test_id="wg_local_link_drop_and_recovery",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=self.IFACE_A,
                        protocol="wireguard",
                        timestamp_utc=_utc_now(),
                        duration_ms=(time.perf_counter() - t_rec) * 1000,
                        bytes_estimated=int(rec_state.get("bytes_estimated", 2400)),
                        verified_real=rec_ok,
                        result="PASS" if rec_ok else "FAIL",
                        reason=None if rec_ok else f"Recovery check failed: down={down_state}, rec={rec_state}",
                        details={
                            "down_egress_ok": down_state["https_egress_verified"],
                            "recovered_egress_ok": rec_state["https_egress_verified"],
                            "recovered_latency_ms": rec_state["egress_latency_ms"],
                        },
                    )
                )

            except Exception as exc:
                records.append(
                    LabTestRecord(
                        test_id="wg_local_runtime_error",
                        execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                        server=self.IFACE_A,
                        protocol="wireguard",
                        timestamp_utc=_utc_now(),
                        duration_ms=(time.perf_counter() - t_suite) * 1000,
                        bytes_estimated=0,
                        verified_real=False,
                        result="FAIL",
                        reason=redact_secrets(f"{exc.__class__.__name__}: {exc}"),
                    )
                )
            finally:
                if netns_https_proc is not None:
                    try:
                        netns_https_proc.terminate()
                        netns_https_proc.wait(timeout=2.0)
                    except Exception:
                        pass
                if created_iface_a:
                    self._run_priv([ip_bin, "link", "del", self.IFACE_A], use_sudo=use_sudo)
                if created_peer_netns:
                    self._run_priv([ip_bin, "netns", "del", self.PEER_NETNS], use_sudo=use_sudo)
                if created_iface_b and not iface_b_moved_to_netns:
                    self._run_priv([ip_bin, "link", "del", self.IFACE_B], use_sudo=use_sudo)

        # Verify complete cleanup & restored routing table
        t_cln = time.perf_counter()
        post_cleanup_routes = inspect_routing_table(self.IFACE_A)
        chk_iface = subprocess.run(
            [ip_bin, "-j", "link", "show", "dev", self.IFACE_A],
            capture_output=True,
            text=True,
            timeout=3,
        )
        cleanup_ok = (
            chk_iface.returncode != 0
            and verify_route_isolation(baseline_routes, post_cleanup_routes, self.IFACE_A)["default_route_unchanged"]
        )
        records.append(
            LabTestRecord(
                test_id="wg_local_clean_interface_and_netns_removal",
                execution_scope=ExecutionScope.LOCAL_LOOPBACK,
                server=self.IFACE_A,
                protocol="wireguard",
                timestamp_utc=_utc_now(),
                duration_ms=(time.perf_counter() - t_cln) * 1000,
                bytes_estimated=0,
                verified_real=cleanup_ok,
                result="PASS" if cleanup_ok else "FAIL",
                reason=None if cleanup_ok else "wg_jaro0 or route modification persisted after cleanup",
            )
        )

        res_after = measure_process_resources()
        all_passed = len(records) > 0 and all(r.result == "PASS" for r in records)
        return {
            "lab": "LOCAL_WIREGUARD_LOOPBACK_LAB",
            "status": "LOCAL_VERIFIED" if all_passed else "FAILED",
            "remote_wireguard_status": remote_readiness["status"],
            "remote_wireguard_detail": remote_readiness,
            "counts": {
                "total": len(records),
                "passed": sum(1 for r in records if r.result == "PASS"),
                "failed": sum(1 for r in records if r.result == "FAIL"),
            },
            "external_bytes_consumed": 0,
            "loopback_bytes_estimated": sum(r.bytes_estimated for r in records),
            "resources": {
                "vm_rss_mb": res_after["vm_rss_mb"],
                "vm_hwm_mb": res_after["vm_hwm_mb"],
                "cpu_seconds_used": round(res_after["cpu_total_s"] - res_before["cpu_total_s"], 4),
            },
            "records": [r.to_dict() for r in records],
        }
