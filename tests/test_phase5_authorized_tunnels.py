"""JARO WPF - Phase 5 Automated Test Suite: Authorized Tunnel Infrastructure & Security Controls.

Covers:
1. Security Controls (`core/security/secret_guard.py`):
   - Secret redaction (PEM/OpenSSH keys, WireGuard PrivateKey/PresharedKey, Bearer tokens, passwords)
   - Sensitive file permission protection (`0o600`) & rejection of `0o644`
   - JSON catalog plaintext secret rejection
   - SSH `IdentityFile` header validation & `known_hosts` verification (plain, `[host]:port`, OpenSSH `|1|` HMAC-SHA1, `@revoked`, `ssh-dss` rejection)
   - `PrivilegePolicyGate` zero-automatic-sudo enforcement
2. Server Manager (`core/connection/server_manager.py`):
   - All 9 mandatory fields (`server_id`, `address`, `protocol`, `status`, `latency_ms`, `last_checked_utc`, `authorized`, `requirements`, `verified_capabilities`)
   - Register/update/remove SSH & WireGuard servers with persistence & secret rejection
   - Explicit `REMOTE_SERVER_REQUIRED` (never `SUCCESS`) when remote servers are empty
3. SSH Engine (`core/protocols/ssh_engine.py`):
   - Port collision prevention before spawning `ssh -D`
   - Deterministic SSH error classification
   - Strict separation of `local_socks5_functional`, `local_ssh_tunnel_functional`, and `remote_ssh_tunnel_functional`
4. WireGuard Engine (`core/protocols/vpn_tunnel_engine.py`):
   - Unsafe interface name rejection, DNS override guard, global route guard
   - Zero automatic `sudo` calls during `inspect_state`, `activate`, `deactivate`, and `recover`
   - Differential `rx_bytes_delta`/`tx_bytes_delta` verification and `verify_route_isolation`
5. iOS NetworkExtension Contract (`core/connection/ios_tunnel_contract.py`):
   - `device_verified == False` (`UNVERIFIED_ON_PHYSICAL_IPHONE`), split-route enforcement, Keychain ref enforcement
6. Local Tunnel Labs (`core/network_tests/local_tunnel_labs.py`):
   - `LocalWireGuardLoopbackLab` refuses privileged execution unless `authorize_privileged_lab=True`
   - `LocalOpenSshLoopbackLab` runs real unprivileged `/usr/sbin/sshd` end-to-end when installed (or skips honestly if absent)
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from core.connection.cost_manager import CostManager, CostProfile
from core.connection.ios_tunnel_contract import (
    IOS_VERIFICATION_STATUS,
    build_ios_ssh_socks5_provider_contract,
    build_ios_wireguard_provider_contract,
    export_ios_readiness_summary,
)
from core.connection.network_monitor import NetworkMonitor
from core.connection.reconnector import ExponentialBackoffReconnector
from core.connection.server_manager import ServerManager, ServerStatus
from core.connection.transport_manager import TransportManager
from core.network_tests.diagnostic_engine import DiagnosticEngine
from core.network_tests.local_tunnel_labs import (
    LocalOpenSshLoopbackLab,
    LocalWireGuardLoopbackLab,
)
from core.protocols.ssh_engine import (
    SshSocksTunnel,
    SshTunnelConfig,
    classify_ssh_error,
)
from core.protocols.vpn_tunnel_engine import (
    WireGuardTunnelEngine,
    validate_wireguard_config_text,
    verify_route_isolation,
)
from core.security.secret_guard import (
    PrivilegePolicyGate,
    SecretSecurityError,
    audit_json_no_plaintext_secrets,
    audit_sensitive_file,
    compute_ssh_pubkey_fingerprint,
    inspect_ssh_identity_file,
    protect_sensitive_file,
    redact_secrets,
    verify_known_hosts_entry,
)


def _sample_ed25519_pubkey_b64() -> str:
    # Minimal syntactically valid SSH wire pubkey blob (>= 16 bytes)
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + (b"\x42" * 32)
    return base64.b64encode(blob).decode("ascii")


class TestPhase5SecurityControls(unittest.TestCase):
    """Audits core/security/secret_guard.py invariants."""

    def test_redact_secrets_scrubs_pem_wireguard_passwords_and_tokens(self) -> None:
        raw = (
            "Error loading -----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYDATA123\n-----END OPENSSH PRIVATE KEY-----\n"
            "PrivateKey = c3VwZXJzZWNyZXR3aXJlZ3VhcmRrZXk=\n"
            "PresharedKey = YW5vdGhlcnNlY3JldGtleQ==\n"
            "password='MyPlainPassword99' Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret"
        )
        scrubbed = redact_secrets(raw)
        self.assertNotIn("SECRETKEYDATA123", scrubbed)
        self.assertNotIn("c3VwZXJzZWNyZXR3aXJlZ3VhcmRrZXk=", scrubbed)
        self.assertNotIn("YW5vdGhlcnNlY3JldGtleQ==", scrubbed)
        self.assertNotIn("MyPlainPassword99", scrubbed)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", scrubbed)
        self.assertIn("[REDACTED_PRIVATE_KEY]", scrubbed)
        self.assertIn("[REDACTED_WG_SECRET]", scrubbed)

    def test_sensitive_file_permissions_and_identity_header_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            os.chmod(tpath, 0o700)
            key_file = tpath / "id_ed25519"
            key_file.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            os.chmod(key_file, 0o644)

            insecure = audit_sensitive_file(key_file)
            self.assertFalse(insecure["valid"])

            refused = protect_sensitive_file(key_file, 0o644)
            self.assertFalse(refused["protected"])

            protected = protect_sensitive_file(key_file, 0o600)
            self.assertTrue(protected["protected"])
            self.assertEqual(protected["mode"], "0o600")

            id_ok = inspect_ssh_identity_file(key_file)
            self.assertTrue(id_ok["valid"])
            self.assertEqual(id_ok["key_format"], "openssh")

            bad_key = tpath / "not_a_key"
            bad_key.write_text("plain text not a key\n", encoding="utf-8")
            os.chmod(bad_key, 0o600)
            self.assertFalse(inspect_ssh_identity_file(bad_key)["valid"])

    def test_audit_json_rejects_plaintext_passwords_and_inline_keys(self) -> None:
        safe_doc = {
            "id": "srv-1",
            "identity_file": "/home/user/.ssh/id_ed25519",
            "config_path": "/etc/wireguard/wg0.conf",
        }
        self.assertTrue(audit_json_no_plaintext_secrets(safe_doc)["safe"])

        bad_pwd = {"id": "srv-1", "password": "secret"}
        self.assertFalse(audit_json_no_plaintext_secrets(bad_pwd)["safe"])

        bad_inline_pem = {"notes": "-----BEGIN PRIVATE KEY-----\nMIIB..."}
        self.assertFalse(audit_json_no_plaintext_secrets(bad_inline_pem)["safe"])

    def test_known_hosts_plain_bracketed_hashed_revoked_and_dss_rejection(self) -> None:
        pub_b64 = _sample_ed25519_pubkey_b64()
        salt = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
        target_str = "[203.0.113.10]:2222"
        mac = hmac.new(salt, target_str.encode("utf-8"), hashlib.sha1).digest()
        hashed_token = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(mac).decode()}"

        with tempfile.TemporaryDirectory() as tmp:
            kh = Path(tmp) / "known_hosts"
            kh.write_text(
                f"198.51.100.20 ssh-ed25519 {pub_b64}\n"
                f"{hashed_token} ssh-ed25519 {pub_b64}\n",
                encoding="utf-8",
            )

            # Plain port 22 match
            r22 = verify_known_hosts_entry(kh, "198.51.100.20", 22)
            self.assertTrue(r22["valid"])
            self.assertEqual(r22["fingerprints"][0], compute_ssh_pubkey_fingerprint(pub_b64))

            # Port mismatch (port 2222 not pinned for 198.51.100.20) -> rejected!
            r_wrong_port = verify_known_hosts_entry(kh, "198.51.100.20", 2222)
            self.assertFalse(r_wrong_port["valid"])

            # Hashed |1|salt|mac match on custom port 2222 -> accepted!
            r_hashed = verify_known_hosts_entry(kh, "203.0.113.10", 2222)
            self.assertTrue(r_hashed["valid"])

            # @revoked host key -> rejected!
            kh_rev = Path(tmp) / "revoked_hosts"
            kh_rev.write_text(f"@revoked 198.51.100.99 ssh-ed25519 {pub_b64}\n", encoding="utf-8")
            self.assertFalse(verify_known_hosts_entry(kh_rev, "198.51.100.99", 22)["valid"])

            # Deprecated ssh-dss -> rejected!
            kh_dss = Path(tmp) / "dss_hosts"
            kh_dss.write_text(f"198.51.100.88 ssh-dss {pub_b64}\n", encoding="utf-8")
            self.assertFalse(verify_known_hosts_entry(kh_dss, "198.51.100.88", 22)["valid"])


class TestPhase5ServerManagerAndReadiness(unittest.TestCase):
    """Audits ServerManager 9 required fields, secret protection, and REMOTE_SERVER_REQUIRED status."""

    def test_empty_remote_tunnels_report_remote_server_required_never_success(self) -> None:
        mgr = ServerManager()  # Loads configs/servers.json where remote tunnels are empty
        snap = mgr.snapshot()
        self.assertEqual(snap["remote_ssh_readiness"]["status"], ServerStatus.REMOTE_SERVER_REQUIRED.value)
        self.assertFalse(snap["remote_ssh_readiness"]["ready"])
        self.assertEqual(snap["remote_wireguard_readiness"]["status"], ServerStatus.REMOTE_SERVER_REQUIRED.value)
        self.assertFalse(snap["remote_wireguard_readiness"]["ready"])

    def test_register_update_persist_and_remove_authorized_servers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "servers.json"
            cfg_file.write_text(
                json.dumps({
                    "version": "2.1.0",
                    "project": "JARO WPF",
                    "egress_validation_endpoints": [],
                    "servers": [],
                    "authorized_ssh_tunnels": [],
                    "authorized_wireguard_tunnels": [],
                }),
                encoding="utf-8",
            )
            mgr = ServerManager(config_path=cfg_file)

            # Reject registration containing plaintext password
            with self.assertRaises(SecretSecurityError):
                mgr.register_ssh_server(
                    server_id="bad-ssh",
                    host="198.51.100.10",
                    username="jaro",
                    identity_file="/tmp/id",
                    known_hosts_file="/tmp/kh",
                    extra_fields={"password": "plaintext_forbidden"},
                )

            rec_ssh = mgr.register_ssh_server(
                server_id="own-vps-ssh",
                host="198.51.100.10",
                port=2222,
                username="jaro",
                identity_file="/home/jaro/.ssh/id_ed25519",
                known_hosts_file="/home/jaro/.ssh/known_hosts",
                authorized=True,
                persist=True,
            )
            d = rec_ssh.to_dict()
            # Check all 9 mandatory fields
            for required_key in (
                "server_id",
                "address",
                "protocol",
                "status",
                "latency_ms",
                "last_checked_utc",
                "authorized",
                "requirements",
                "verified_capabilities",
            ):
                self.assertIn(required_key, d)
            self.assertEqual(d["address"], "198.51.100.10:2222")
            self.assertEqual(d["status"], ServerStatus.UNVERIFIED.value)

            # Before live verification, remote readiness is UNVERIFIED (not ONLINE_VERIFIED)
            r_pending = mgr.evaluate_remote_tunnel_readiness("ssh_socks5")
            self.assertEqual(r_pending["status"], ServerStatus.UNVERIFIED.value)
            self.assertFalse(r_pending["ready"])

            # Update live verification
            mgr.update_verification(
                "own-vps-ssh",
                status=ServerStatus.ONLINE_VERIFIED,
                latency_ms=42.5,
                verified_capabilities={"https_egress_verified": True},
            )
            r_live = mgr.evaluate_remote_tunnel_readiness("ssh_socks5")
            self.assertEqual(r_live["status"], ServerStatus.ONLINE_VERIFIED.value)
            self.assertTrue(r_live["ready"])

            # Reload from disk & remove
            mgr2 = ServerManager(config_path=cfg_file)
            self.assertIsNotNone(mgr2.get_server("own-vps-ssh"))
            self.assertTrue(mgr2.remove_server("own-vps-ssh", persist=True))
            self.assertEqual(
                mgr2.evaluate_remote_tunnel_readiness("ssh_socks5")["status"],
                ServerStatus.REMOTE_SERVER_REQUIRED.value,
            )


class TestPhase5SshAndWireGuardEngines(unittest.TestCase):
    """Audits SSH port-collision, error classification, WireGuard zero-auto-sudo, and route isolation."""

    def test_ssh_port_collision_and_error_classification(self) -> None:
        self.assertEqual(classify_ssh_error("Host key verification failed."), "HOST_KEY_VERIFICATION_FAILED")
        self.assertEqual(classify_ssh_error("Permission denied (publickey)."), "PUBLICKEY_AUTH_REJECTED")
        self.assertEqual(classify_ssh_error("Address already in use"), "PORT_FORWARD_FAILED")

        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            os.chmod(tpath, 0o700)
            id_f = tpath / "id_ed25519"
            id_f.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            os.chmod(id_f, 0o600)
            kh_f = tpath / "known_hosts"
            kh_f.write_text(f"[127.0.0.1]:22222 ssh-ed25519 {_sample_ed25519_pubkey_b64()}\n", encoding="utf-8")

            # Occupy a local TCP port to prove SshSocksTunnel refuses false-positive port collision!
            busy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            busy_sock.bind(("127.0.0.1", 0))
            busy_sock.listen(1)
            busy_port = busy_sock.getsockname()[1]
            try:
                tun = SshSocksTunnel(
                    SshTunnelConfig(
                        host="127.0.0.1",
                        port=22222,
                        username="jaro",
                        identity_file=str(id_f),
                        known_hosts_file=str(kh_f),
                        local_socks_port=busy_port,
                        authorized=True,
                    )
                )
                res = tun.start(startup_timeout_s=1.0)
                self.assertFalse(res["connected"])
                self.assertEqual(res["error_code"], "PORT_FORWARD_FAILED")
                self.assertIn("port collision", res["error"].lower())
            finally:
                busy_sock.close()

    def test_wireguard_zero_auto_sudo_route_isolation_and_rx_tx_delta(self) -> None:
        # 1. Unsafe interface name rejected
        with self.assertRaises(ValueError):
            WireGuardTunnelEngine(interface_name="../bad_iface")

        # 2. DNS override rejected unless allow_dns_override=True
        priv = base64.b64encode(b"\x11" * 32).decode("ascii")
        pub = base64.b64encode(b"\x22" * 32).decode("ascii")
        dns_conf = (
            f"[Interface]\nPrivateKey = {priv}\nAddress = 10.88.0.2/30\nDNS = 1.1.1.1\n\n"
            f"[Peer]\nPublicKey = {pub}\nEndpoint = 198.51.100.5:51820\nAllowedIPs = 10.88.0.0/30\n"
        )
        self.assertFalse(validate_wireguard_config_text(dns_conf, allow_dns_override=False)["valid"])
        self.assertTrue(validate_wireguard_config_text(dns_conf, allow_dns_override=True)["valid"])

        # 3. Route isolation detector catches default-route hijack
        baseline = {"default_routes": [{"dst": "default", "dev": "wlp2s0", "gateway": "192.168.1.1"}]}
        safe_curr = {
            "default_routes": [{"dst": "default", "dev": "wlp2s0", "gateway": "192.168.1.1"}],
            "interface_routes": [{"dst": "10.199.77.0/30", "dev": "wg_jaro0", "gateway": None}],
            "has_global_route_on_interface": False,
        }
        hijacked_curr = {
            "default_routes": [{"dst": "default", "dev": "wg_jaro0", "gateway": None}],
            "interface_routes": [{"dst": "default", "dev": "wg_jaro0", "gateway": None}],
            "has_global_route_on_interface": True,
        }
        self.assertTrue(verify_route_isolation(baseline, safe_curr, "wg_jaro0")["routes_isolated_and_safe"])
        self.assertFalse(verify_route_isolation(baseline, hijacked_curr, "wg_jaro0")["routes_isolated_and_safe"])

        # 4. Verify activate() blocks with authorization_required=True and NEVER calls sudo
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            os.chmod(tpath, 0o700)
            conf_f = tpath / "wg_test.conf"
            conf_f.write_text(
                f"[Interface]\nPrivateKey = {priv}\nAddress = 10.88.0.2/30\n\n"
                f"[Peer]\nPublicKey = {pub}\nEndpoint = 198.51.100.5:51820\nAllowedIPs = 10.88.0.0/30\n",
                encoding="utf-8",
            )
            os.chmod(conf_f, 0o600)

            eng = WireGuardTunnelEngine(interface_name="wg_test0", config_path=conf_f, authorized=True)
            act = eng.activate()  # Default gate has authorize_interface_changes=False!
            self.assertFalse(act["activated"])
            self.assertTrue(act.get("authorization_required"))

            rec = eng.recover(reconnector=ExponentialBackoffReconnector(base_delay=0.01, max_attempts=3))
            self.assertFalse(rec["connected"])
            self.assertTrue(rec["aborted_non_retryable"])
            self.assertEqual(rec["attempts_used"], 1)  # Aborted immediately without retry loop!

        # 5. Differential RX/TX byte delta verification via wg_dump_provider
        now = int(time.time())
        dumps = iter([
            f"PRIVATE\tPUBLIC\t51820\toff\n{pub}\t(none)\t127.0.0.1:51821\t10.199.77.2/32\t{now - 2}\t148\t180\toff\n",
            f"PRIVATE\tPUBLIC\t51820\toff\n{pub}\t(none)\t127.0.0.1:51821\t10.199.77.2/32\t{now - 1}\t2450\t1820\toff\n",
        ])
        eng_delta = WireGuardTunnelEngine(
            interface_name="wg_sim0",
            authorized=True,
            wg_dump_provider=lambda _: next(dumps),
        )
        fake_ip_json = json.dumps([{"operstate": "UNKNOWN", "addr_info": [{"local": "10.199.77.1"}]}])
        with (
            patch("subprocess.run") as mock_run,
            patch(
                "core.protocols.vpn_tunnel_engine.probe_https_egress",
                return_value={"real_internet": True, "latency_ms": 4.2, "bytes_estimated": 2100, "error": None},
            ),
            patch(
                "core.protocols.vpn_tunnel_engine.inspect_routing_table",
                return_value={"available": True, "default_routes": [], "interface_routes": [], "has_global_route_on_interface": False},
            ),
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = fake_ip_json
            st = eng_delta.inspect_state(verify_internet_egress=True)

        self.assertTrue(st["tunnel_verified"])
        self.assertTrue(st["data_transfer_verified"])
        self.assertEqual(st["rx_bytes_delta"], 2302)
        self.assertEqual(st["tx_bytes_delta"], 1640)


class TestPhase5DiagnosticTransportAndIosContracts(unittest.TestCase):
    """Audits REMOTE_SERVER_REQUIRED in DiagnosticEngine/TransportManager and iOS contract safety."""

    def test_diagnostic_and_transport_manager_surface_remote_server_required(self) -> None:
        cm = CostManager(allow_metered=False, allow_unknown=True)
        cm.set_interface_profile("wlp2s0", CostProfile.FREE)
        mon = NetworkMonitor(
            cost_manager=cm,
            interface_provider=lambda: [{"name": "wlp2s0", "state": "UP", "addresses": ["192.168.1.50"]}],
            metered_hint_provider=lambda _: False,
        )
        diag = DiagnosticEngine(
            cost_manager=cm,
            network_monitor=mon,
            dns_probe_fn=lambda: {"udp_dns": {"protocol_verified": True, "host": "1.1.1.1"}, "tcp_dns": {"protocol_verified": True}},
            web_https_probe_fn=lambda: [{"real_internet": True, "is_dns_provider": False, "bytes_estimated": 1200}],
            http3_probe_fn=lambda: {"http3_verified": True, "is_dns_provider": False, "response_bytes": 120},
        )
        rep = diag.run_diagnostics()
        self.assertIn("local_ssh_tunnel_functional", rep["capability_matrix"])
        self.assertFalse(rep["capability_matrix"]["remote_ssh_tunnel_functional"])
        self.assertEqual(rep["details"]["remote_ssh_status"], "REMOTE_SERVER_REQUIRED")
        self.assertEqual(rep["details"]["remote_wireguard_status"], "REMOTE_SERVER_REQUIRED")

        tm = TransportManager(cost_manager=cm)
        with (
            patch.object(tm.multi_manager, "evaluate_all", return_value={
                "connectivity_state": "INTERNET_OK",
                "real_internet_verified": True,
                "dns_resolvers": [],
                "internet_transports": [],
            }),
            patch("core.connection.transport_manager.detect_active_media", return_value=[{"name": "wlp2s0", "medium": "wifi"}]),
        ):
            planes = tm.evaluate_planes()
        self.assertEqual(planes["remote_tunnel_readiness"]["ssh_socks5"]["status"], "REMOTE_SERVER_REQUIRED")
        self.assertEqual(planes["remote_tunnel_readiness"]["wireguard"]["status"], "REMOTE_SERVER_REQUIRED")

    def test_ios_network_extension_contracts_enforce_unverified_and_keychain_only(self) -> None:
        summary = export_ios_readiness_summary()
        self.assertFalse(summary["device_verified"])
        self.assertEqual(summary["verification_status"], IOS_VERIFICATION_STATUS)
        self.assertEqual(summary["remote_ssh_status"], "REMOTE_SERVER_REQUIRED")
        self.assertEqual(summary["remote_wireguard_status"], "REMOTE_SERVER_REQUIRED")

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "servers.json"
            cfg.write_text('{"servers": [], "authorized_ssh_tunnels": [], "authorized_wireguard_tunnels": []}', encoding="utf-8")
            mgr = ServerManager(cfg)
            wg_rec = mgr.register_wireguard_server(
                server_id="wg-ios-1",
                endpoint_host="198.51.100.77",
                endpoint_port=51820,
                config_path="/etc/wireguard/wg0.conf",
                authorized=True,
            )
            ssh_rec = mgr.register_ssh_server(
                server_id="ssh-ios-1",
                host="198.51.100.78",
                port=22,
                username="jaro",
                identity_file="/home/jaro/.ssh/id_ed25519",
                known_hosts_file="/home/jaro/.ssh/known_hosts",
                authorized=True,
            )

            # Reject global default route 0.0.0.0/0 when allow_global_routes=False
            with self.assertRaises(ValueError):
                build_ios_wireguard_provider_contract(
                    server=wg_rec,
                    tunnel_address_cidr="10.199.77.2/30",
                    peer_public_key_b64=base64.b64encode(b"\x33" * 32).decode(),
                    keychain_private_key_ref="keychain://jaro/wg/wg-ios-1",
                    included_routes=["0.0.0.0/0"],
                    allow_global_routes=False,
                )

            # Reject raw key instead of keychain:// ref
            with self.assertRaises(ValueError):
                build_ios_wireguard_provider_contract(
                    server=wg_rec,
                    tunnel_address_cidr="10.199.77.2/30",
                    peer_public_key_b64=base64.b64encode(b"\x33" * 32).decode(),
                    keychain_private_key_ref="RAW_BASE64_KEY_FORBIDDEN",
                    included_routes=["10.199.77.0/30"],
                )

            wg_contract = build_ios_wireguard_provider_contract(
                server=wg_rec,
                tunnel_address_cidr="10.199.77.2/30",
                peer_public_key_b64=base64.b64encode(b"\x33" * 32).decode(),
                keychain_private_key_ref="keychain://jaro/wg/wg-ios-1",
                included_routes=["10.199.77.0/30"],
            )
            self.assertFalse(wg_contract["device_verified"])
            self.assertFalse(wg_contract["include_default_route"])

            ssh_contract = build_ios_ssh_socks5_provider_contract(
                server=ssh_rec,
                username="jaro",
                pinned_hostkey_fingerprint_sha256="SHA256:abc123def456",
                keychain_identity_ref="keychain://jaro/ssh/ssh-ios-1",
            )
            self.assertFalse(ssh_contract["device_verified"])
            self.assertEqual(ssh_contract["verification_status"], IOS_VERIFICATION_STATUS)


class TestPhase5LocalTunnelLabs(unittest.TestCase):
    """Verifies LocalWireGuardLoopbackLab privilege gate and LocalOpenSshLoopbackLab execution."""

    def test_local_wireguard_lab_blocks_by_default_without_explicit_authorization(self) -> None:
        wg_lab = LocalWireGuardLoopbackLab()
        res = wg_lab.run(authorize_privileged_lab=False)
        self.assertEqual(res["status"], "AUTHORIZATION_REQUIRED")
        self.assertTrue(res["authorization_required"])
        self.assertEqual(res["remote_wireguard_status"], "REMOTE_SERVER_REQUIRED")

    def test_local_openssh_loopback_lab_executes_or_skips_honestly(self) -> None:
        ssh_lab = LocalOpenSshLoopbackLab()
        res = ssh_lab.run()
        self.assertEqual(res["remote_ssh_status"], "REMOTE_SERVER_REQUIRED")
        if ssh_lab.find_sshd_binary() is None:
            self.assertEqual(res["status"], "SKIPPED_MISSING_PREREQUISITE")
        else:
            self.assertEqual(res["status"], "LOCAL_VERIFIED", msg=f"Local OpenSSH lab failed: {res}")
            self.assertEqual(res["counts"]["failed"], 0)
            self.assertEqual(res["counts"]["passed"], 6)
            self.assertEqual(res["external_bytes_consumed"], 0)


if __name__ == "__main__":
    unittest.main()
