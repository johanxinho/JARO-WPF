"""JARO WPF - Phase 6 Automated Test Suite:
1. Cross-Platform `.jaroprofile` v1.0 & WireGuard `.conf` Importer (`JaroProfileManager` <-> Swift `JaroPortableProfile` schema parity).
2. Real End-to-End Dual Proxy (`SOCKS5` RFC 1928 + `HTTP CONNECT` RFC 9110 for iOS `NEProxySettings.httpsServer`)
   over real unprivileged OpenSSH `sshd` `direct-tcpip` + verified TLS X.509 HTTPS (`0 B` external traffic).
3. Windows 10/11 OpenSSH & WireGuard Service Adapters (`icacls` ACL audit, zero-auto-UAC gate, `Get-NetRoute` isolation).
4. Native iOS Swift 7-Module Project Structural, Entitlement, API & Security Invariant Audit (`ios/`).
"""
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import ssl
import tempfile
import unittest

from core.connection.server_manager import ServerManager, ServerStatus
from core.network_tests.local_tunnel_labs import (
    LocalOpenSshLoopbackLab,
    _LoopbackHttpsServer,
    _free_tcp_port,
    generate_ephemeral_wg_keypair,
)
from core.network_tests.network_lab import _generate_lab_pki
from core.platform.windows_tunnel_adapter import (
    WINDOWS_CREATE_NEW_PROCESS_GROUP,
    WindowsOpenSshAdapter,
    WindowsWireGuardServiceAdapter,
    audit_windows_icacls_output,
    parse_windows_net_routes_json,
    parse_windows_netsh_wlan_metered,
)
from core.profiles.jaro_profile_manager import (
    DEFAULT_IOS_APP_GROUP,
    DEFAULT_IOS_EXTENSION_BUNDLE_ID,
    JaroProfileError,
    JaroProfileManager,
    JaroTunnelProfile,
)
from core.protocols.dual_proxy_bridge import (
    JaroDualProxyBridge,
    probe_https_over_http_connect,
)
from core.protocols.ssh_engine import (
    SshSocksTunnel,
    SshTunnelConfig,
    probe_https_over_socks5,
)
from core.protocols.vpn_tunnel_engine import verify_route_isolation
from core.security.secret_guard import (
    PrivilegePolicyGate,
    SecretSecurityError,
    protect_sensitive_file,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
IOS_ROOT = REPO_ROOT / "ios"


def _strip_swift_comments_and_strings(source: str) -> str:
    """Strips Swift line/block comments and string literals so delimiter balance checks never false-positive."""
    out = []
    i = 0
    n = len(source)
    while i < n:
        if source.startswith("//", i):
            nl = source.find("\n", i)
            if nl == -1:
                break
            i = nl
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = n if end == -1 else end + 2
        elif source.startswith('"""', i):
            end = source.find('"""', i + 3)
            i = n if end == -1 else end + 3
        elif source[i] == '"':
            i += 1
            while i < n and source[i] != '"':
                if source[i] == "\\":
                    i += 2
                else:
                    i += 1
            i += 1
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


class TestPhase6ProfilesAndSchemaParity(unittest.TestCase):
    def test_default_registries_empty_and_return_remote_server_required(self) -> None:
        mgr = JaroProfileManager()
        self.assertEqual(mgr.list_profiles(), [])
        readiness = mgr.evaluate_remote_status()
        self.assertEqual(readiness["status"], ServerStatus.REMOTE_SERVER_REQUIRED.value)
        self.assertFalse(readiness["ready"])

        # Also verify repository configs/servers.json remains empty for remote tunnels
        srv_mgr = ServerManager(REPO_ROOT / "configs" / "servers.json")
        self.assertEqual(
            srv_mgr.evaluate_remote_tunnel_readiness("ssh_socks5")["status"],
            ServerStatus.REMOTE_SERVER_REQUIRED.value,
        )
        self.assertEqual(
            srv_mgr.evaluate_remote_tunnel_readiness("wireguard")["status"],
            ServerStatus.REMOTE_SERVER_REQUIRED.value,
        )

    def test_wireguard_conf_import_isolates_secrets_blocks_global_routes_and_matches_swift_schema(self) -> None:
        priv_b64, _ = generate_ephemeral_wg_keypair()
        _, peer_pub_b64 = generate_ephemeral_wg_keypair()
        psk_b64, _ = generate_ephemeral_wg_keypair()

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            profiles_dir = tmpdir / "profiles"
            vault_dir = tmpdir / "vault"
            mgr = JaroProfileManager(storage_dir=profiles_dir)

            # 1. Global route 0.0.0.0/0 must be blocked when allow_global_routes=False
            global_conf = (
                f"[Interface]\n"
                f"PrivateKey = {priv_b64}\n"
                f"Address = 10.88.0.2/24\n\n"
                f"[Peer]\n"
                f"PublicKey = {peer_pub_b64}\n"
                f"Endpoint = 198.51.100.25:51820\n"
                f"AllowedIPs = 0.0.0.0/0\n"
            )
            with self.assertRaises(JaroProfileError):
                mgr.import_wireguard_conf_text(
                    profile_id="wg-global-denied",
                    display_name="Denied Global",
                    conf_text=global_conf,
                    vault_dir=vault_dir,
                    authorized=True,
                    allow_global_routes=False,
                )

            # 2. Split-tunnel import succeeds, isolates secrets in 0o600 vault, and exports clean .jaroprofile
            split_conf = (
                f"[Interface]\n"
                f"PrivateKey = {priv_b64}\n"
                f"Address = 10.88.0.2/24\n"
                f"MTU = 1420\n\n"
                f"[Peer]\n"
                f"PublicKey = {peer_pub_b64}\n"
                f"PresharedKey = {psk_b64}\n"
                f"Endpoint = 198.51.100.25:51820\n"
                f"AllowedIPs = 10.88.0.0/24\n"
                f"PersistentKeepalive = 25\n"
            )
            prof = mgr.import_wireguard_conf_text(
                profile_id="wg-authorized-split",
                display_name="Authorized Split WG",
                conf_text=split_conf,
                vault_dir=vault_dir,
                authorized=True,
                allow_global_routes=False,
                persist=True,
            )
            self.assertFalse(prof.include_default_route)
            self.assertIsNotNone(prof.local_secret_file)
            vault_file = Path(prof.local_secret_file)  # type: ignore[arg-type]
            self.assertEqual(vault_file.stat().st_mode & 0o777, 0o600)

            ios_bundle_path = tmpdir / "exported_ios.jaroprofile"
            mgr.export_profile_file("wg-authorized-split", ios_bundle_path, include_local_paths=False)
            exported_text = ios_bundle_path.read_text(encoding="utf-8")
            self.assertNotIn(priv_b64, exported_text)
            self.assertNotIn(psk_b64, exported_text)

            exported_dict = json.loads(exported_text)
            self.assertEqual(exported_dict["organization"], "JARO COMPLEMETS")
            self.assertEqual(exported_dict["ios_targets"]["app_group"], DEFAULT_IOS_APP_GROUP)
            self.assertEqual(exported_dict["ios_targets"]["extension_bundle_id"], DEFAULT_IOS_EXTENSION_BUNDLE_ID)
            self.assertFalse(exported_dict["ios_targets"]["device_verified"])
            self.assertEqual(exported_dict["ios_targets"]["verification_status"], "UNVERIFIED_ON_PHYSICAL_IPHONE")

            # Verify exact top-level JSON key parity with Swift `JaroPortableProfile.CodingKeys`
            swift_models = (IOS_ROOT / "Sources" / "JaroCore" / "JaroModels.swift").read_text(encoding="utf-8")
            for json_key in exported_dict.keys():
                self.assertIn(
                    json_key,
                    swift_models,
                    f"JSON key {json_key!r} from Python .jaroprofile must exist in Swift JaroModels.swift",
                )

            # 3. Round-trip import and verify plaintext PEM injection is rejected
            mgr2 = JaroProfileManager()
            reimported = mgr2.import_profile_file(ios_bundle_path)
            self.assertEqual(reimported.profile_id, "wg-authorized-split")
            self.assertEqual(mgr2.evaluate_remote_status("wireguard")["status"], ServerStatus.UNVERIFIED.value)

            tampered = dict(exported_dict)
            tampered["crypto_references"] = {
                "keychain_secret_ref": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
            }
            with self.assertRaises(SecretSecurityError):
                JaroTunnelProfile.from_portable_dict(tampered)


class TestPhase6DualProxyOverRealOpenSshLoopback(unittest.TestCase):
    def test_dual_socks5_and_http_connect_over_real_sshd_direct_tcpip_https(self) -> None:
        sshd_bin = LocalOpenSshLoopbackLab.find_sshd_binary()
        keygen_bin = shutil.which("ssh-keygen")
        ssh_bin = shutil.which("ssh")
        if not sshd_bin or not keygen_bin or not ssh_bin:
            self.skipTest("OpenSSH server/client binaries not available on host")

        lab_helper = LocalOpenSshLoopbackLab()
        strict_parent = lab_helper._select_strictmodes_parent()
        strict_modes = "yes" if strict_parent is not None else "no"
        current_user = getpass.getuser()

        with tempfile.TemporaryDirectory(prefix=".jaro_p6_dual_", dir=strict_parent) as tmp:
            tmpdir = Path(tmp)
            os.chmod(tmpdir, 0o700)

            pki = _generate_lab_pki(tmpdir)
            trusted_ctx = ssl.create_default_context(cafile=str(pki["ca"]))
            trusted_ctx.check_hostname = True
            trusted_ctx.verify_mode = ssl.CERT_REQUIRED

            host_key = tmpdir / "ssh_host_ed25519"
            client_key = tmpdir / "client_ed25519"
            lab_helper._generate_openssh_key(keygen_bin, host_key, "jaro-p6-host")
            lab_helper._generate_openssh_key(keygen_bin, client_key, "jaro-p6-client")

            auth_keys = tmpdir / "authorized_keys"
            auth_keys.write_text(Path(f"{client_key}.pub").read_text(encoding="utf-8"), encoding="utf-8")
            protect_sensitive_file(auth_keys, 0o600)

            host_pub_tokens = Path(f"{host_key}.pub").read_text(encoding="utf-8").strip().split()
            wire_bytes = base64.b64decode(host_pub_tokens[1])
            fp_sha256 = "SHA256:" + base64.b64encode(hashlib.sha256(wire_bytes).digest()).decode("ascii").rstrip("=")

            sshd_port = _free_tcp_port("127.0.0.1")
            ssh_socks_port = _free_tcp_port("127.0.0.1")
            known_hosts = tmpdir / "known_hosts"
            known_hosts.write_text(
                f"[127.0.0.1]:{sshd_port} {host_pub_tokens[0]} {host_pub_tokens[1]}\n",
                encoding="utf-8",
            )

            # Build and validate a portable SSH `.jaroprofile` for this loopback session
            ssh_profile = JaroTunnelProfile(
                profile_id="local-sshd-p6",
                display_name="Loopback OpenSSH Phase 6",
                protocol="ssh_socks5",
                host="127.0.0.1",
                port=sshd_port,
                authorized=True,
                ssh_username=current_user,
                pinned_hostkey_sha256=fp_sha256,
                local_proxy_port=ssh_socks_port,
                keychain_secret_ref=f"keychain://{DEFAULT_IOS_APP_GROUP}/ssh/local-sshd-p6/identity",
            )
            self.assertTrue(ssh_profile.is_loopback)

            sshd_cfg = tmpdir / "sshd_config"
            sshd_cfg.write_text(
                f"Port {sshd_port}\n"
                f"ListenAddress 127.0.0.1\n"
                f"HostKey {host_key}\n"
                f"PidFile {tmpdir / 'sshd.pid'}\n"
                f"AuthorizedKeysFile {auth_keys}\n"
                f"StrictModes {strict_modes}\n"
                f"UsePAM no\n"
                f"PasswordAuthentication no\n"
                f"KbdInteractiveAuthentication no\n"
                f"PubkeyAuthentication yes\n"
                f"AllowUsers {current_user}\n"
                f"AllowTcpForwarding yes\n"
                f"X11Forwarding no\n"
                f"PrintMotd no\n",
                encoding="utf-8",
            )

            https_srv = _LoopbackHttpsServer(pki["valid_cert"], pki["valid_key"])
            https_srv.start()
            sshd_proc = None
            ssh_tunnel = None
            dual_bridge = None

            try:
                sshd_proc = lab_helper._start_unprivileged_sshd(sshd_bin, sshd_cfg, sshd_port)
                ssh_tunnel = SshSocksTunnel(
                    SshTunnelConfig(
                        host=ssh_profile.host,
                        port=ssh_profile.port,
                        username=ssh_profile.ssh_username or current_user,
                        identity_file=str(client_key),
                        known_hosts_file=str(known_hosts),
                        local_bind_host="127.0.0.1",
                        local_socks_port=ssh_socks_port,
                        connect_timeout_s=4,
                        authorized=True,
                    )
                )
                start_res = ssh_tunnel.start()
                self.assertTrue(start_res["connected"], f"SSH tunnel failed: {start_res}")

                dual_bridge = JaroDualProxyBridge(
                    bind_host="127.0.0.1",
                    bind_port=0,
                    upstream_socks5_host="127.0.0.1",
                    upstream_socks5_port=ssh_socks_port,
                )
                bridge_port = dual_bridge.start()

                # Path A: RFC 1928 SOCKS5 -> Dual Bridge -> SSH direct-tcpip -> TLS 1.3 HTTPS
                socks_probe = probe_https_over_socks5(
                    socks_host="127.0.0.1",
                    socks_port=bridge_port,
                    target_host="localhost",
                    target_port=https_srv.port,
                    expected_substring="JARO-PHASE5-SSH-DIRECT-TCPIP-VERIFIED",
                    ssl_context=trusted_ctx,
                )
                self.assertTrue(socks_probe["tls_verified"], f"SOCKS5 TLS failed: {socks_probe}")
                self.assertTrue(socks_probe["real_internet"], f"SOCKS5 HTTPS failed: {socks_probe}")

                # Path B: RFC 9110 HTTP CONNECT (iOS NEProxySettings.httpsServer framing!) -> Dual Bridge -> SSH -> HTTPS
                connect_probe = probe_https_over_http_connect(
                    proxy_host="127.0.0.1",
                    proxy_port=bridge_port,
                    target_host="localhost",
                    target_port=https_srv.port,
                    expected_substring="JARO-PHASE5-SSH-DIRECT-TCPIP-VERIFIED",
                    ssl_context=trusted_ctx,
                )
                self.assertTrue(connect_probe["connect_tunnel_established"], f"HTTP CONNECT failed: {connect_probe}")
                self.assertTrue(connect_probe["tls_verified"])
                self.assertTrue(connect_probe["https_verified"])
                self.assertEqual(connect_probe["status_code"], 200)

                stats = dual_bridge.stats_snapshot()
                self.assertGreater(stats["rx_bytes"], 0)
                self.assertGreater(stats["tx_bytes"], 0)
                self.assertEqual(stats["socks5_connections"], 1)
                self.assertEqual(stats["http_connect_connections"], 1)
            finally:
                if dual_bridge is not None:
                    dual_bridge.stop()
                if ssh_tunnel is not None:
                    ssh_tunnel.stop()
                lab_helper._stop_proc(sshd_proc)
                https_srv.stop()


class TestPhase6WindowsAdapters(unittest.TestCase):
    def test_windows_icacls_audit_and_ssh_command_builder(self) -> None:
        good_acl = (
            r"C:\Users\jaro\.ssh\id_ed25519 NT AUTHORITY\SYSTEM:(F)" + "\n"
            r"                             DESKTOP-JARO\jaro:(R,W)" + "\n"
            "Successfully processed 1 files; Failed processing 0 files\n"
        )
        self.assertTrue(audit_windows_icacls_output(good_acl)["valid"])

        bad_acl = (
            r"C:\Users\jaro\.ssh\id_ed25519 Everyone:(R)" + "\n"
            r"                             BUILTIN\Users:(R)" + "\n"
        )
        bad_res = audit_windows_icacls_output(bad_acl)
        self.assertFalse(bad_res["valid"])
        self.assertGreaterEqual(len(bad_res["violations"]), 2)

        adapter = WindowsOpenSshAdapter(system_root=r"C:\Windows")
        cmd = adapter.build_ssh_socks5_command(
            ssh_exe=r"C:\Windows\System32\OpenSSH\ssh.exe",
            host="198.51.100.40",
            port=22,
            username="jarouser",
            identity_file=r"C:\Users\jaro\.ssh\id_ed25519",
            known_hosts_file=r"C:\Users\jaro\.ssh\known_hosts",
            local_socks_port=1080,
        )
        self.assertIn("GlobalKnownHostsFile=NUL", cmd)
        self.assertIn("PasswordAuthentication=no", cmd)
        self.assertEqual(WINDOWS_CREATE_NEW_PROCESS_GROUP, 0x00000200)

    def test_windows_wireguard_privilege_gate_and_route_isolation(self) -> None:
        priv_b64, _ = generate_ephemeral_wg_keypair()
        _, pub_b64 = generate_ephemeral_wg_keypair()

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "wg_win0.conf"
            cfg.write_text(
                f"[Interface]\nPrivateKey = {priv_b64}\nAddress = 10.99.0.2/24\n\n"
                f"[Peer]\nPublicKey = {pub_b64}\nEndpoint = 198.51.100.50:51820\nAllowedIPs = 10.99.0.0/24\n",
                encoding="utf-8",
            )
            protect_sensitive_file(cfg, 0o600)

            # Default unapproved gate -> strictly refuses automatic UAC elevation
            locked_adapter = WindowsWireGuardServiceAdapter(privilege_gate=PrivilegePolicyGate())
            denied = locked_adapter.prepare_install_service_command(
                tunnel_name="wg_win0",
                config_path=cfg,
                authorized=True,
            )
            self.assertFalse(denied["ready"])
            self.assertTrue(denied["authorization_required"])

            # Explicitly authorized gate -> returns exact Windows service install/uninstall commands
            approved_gate = PrivilegePolicyGate(
                allow_privileged_commands=True,
                authorize_interface_changes=True,
            )
            approved_adapter = WindowsWireGuardServiceAdapter(privilege_gate=approved_gate)
            ready = approved_adapter.prepare_install_service_command(
                tunnel_name="wg_win0",
                config_path=cfg,
                authorized=True,
                wireguard_exe_override=r"C:\Program Files\WireGuard\wireguard.exe",
            )
            self.assertTrue(ready["ready"])
            self.assertEqual(ready["command"][1], "/installtunnelservice")
            self.assertEqual(ready["uninstall_command"], [r"C:\Program Files\WireGuard\wireguard.exe", "/uninstalltunnelservice", "wg_win0"])

        # Windows PowerShell Get-NetRoute JSON -> verify_route_isolation()
        baseline_json = json.dumps([
            {"DestinationPrefix": "0.0.0.0/0", "InterfaceAlias": "Wi-Fi", "NextHop": "192.168.1.1"},
        ])
        isolated_after_json = json.dumps([
            {"DestinationPrefix": "0.0.0.0/0", "InterfaceAlias": "Wi-Fi", "NextHop": "192.168.1.1"},
            {"DestinationPrefix": "10.99.0.0/24", "InterfaceAlias": "wg_win0", "NextHop": "0.0.0.0"},
        ])
        hijacked_after_json = json.dumps([
            {"DestinationPrefix": "0.0.0.0/0", "InterfaceAlias": "wg_win0", "NextHop": "0.0.0.0"},
        ])

        snap_before = parse_windows_net_routes_json(baseline_json, "wg_win0")
        snap_ok = parse_windows_net_routes_json(isolated_after_json, "wg_win0")
        snap_bad = parse_windows_net_routes_json(hijacked_after_json, "wg_win0")

        self.assertTrue(
            verify_route_isolation(snap_before, snap_ok, "wg_win0", allow_global_routes=False)[
                "routes_isolated_and_safe"
            ]
        )
        self.assertFalse(
            verify_route_isolation(snap_before, snap_bad, "wg_win0", allow_global_routes=False)[
                "routes_isolated_and_safe"
            ]
        )

        self.assertTrue(parse_windows_netsh_wlan_metered("Cost : Fixed"))
        self.assertFalse(parse_windows_netsh_wlan_metered("Cost : Unrestricted"))


class TestPhase6NativeIOSSwiftProjectAudit(unittest.TestCase):
    def test_seven_modular_targets_entitlements_and_plists_valid(self) -> None:
        required_dirs = [
            IOS_ROOT / "Sources" / "JaroCore",
            IOS_ROOT / "Sources" / "JaroSecurity",
            IOS_ROOT / "Sources" / "JaroProfiles",
            IOS_ROOT / "Sources" / "JaroTunnelEngine",
            IOS_ROOT / "Sources" / "JaroDiagnostics",
            IOS_ROOT / "Sources" / "JaroPacketTunnel",
            IOS_ROOT / "Sources" / "JaroApp",
            IOS_ROOT / "Tests" / "JaroCoreTests",
        ]
        for d in required_dirs:
            self.assertTrue(d.is_dir(), f"Missing required iOS module directory: {d}")

        self.assertTrue((IOS_ROOT / "Package.swift").is_file())
        self.assertTrue((IOS_ROOT / "project.yml").is_file())

        # Validate Apple plist & entitlement XML syntax and required keys
        for ent_path in (
            IOS_ROOT / "Config" / "JaroApp.entitlements",
            IOS_ROOT / "Config" / "JaroPacketTunnel.entitlements",
        ):
            with ent_path.open("rb") as fp:
                ent = plistlib.load(fp)
            self.assertEqual(
                ent.get("com.apple.developer.networking.networkextension"),
                ["packet-tunnel-provider"],
            )
            self.assertIn(DEFAULT_IOS_APP_GROUP, ent.get("com.apple.security.application-groups", []))

        with (IOS_ROOT / "Sources" / "JaroPacketTunnel" / "Info.plist").open("rb") as fp:
            ext_plist = plistlib.load(fp)
        self.assertEqual(
            ext_plist["NSExtension"]["NSExtensionPointIdentifier"],
            "com.apple.networkextension.packet-tunnel",
        )
        self.assertEqual(
            ext_plist["NSExtension"]["NSExtensionPrincipalClass"],
            "$(PRODUCT_MODULE_NAME).PacketTunnelProvider",
        )

    def test_swift_sources_delimiter_balance_and_security_invariants(self) -> None:
        swift_files = sorted(IOS_ROOT.rglob("*.swift"))
        self.assertGreaterEqual(len(swift_files), 13)

        pairs = {"{": "}", "(": ")", "[": "]"}
        closing = set(pairs.values())

        combined_prod_sources = []
        for sf in swift_files:
            raw = sf.read_text(encoding="utf-8")
            cleaned = _strip_swift_comments_and_strings(raw)
            stack: list[str] = []
            for ch in cleaned:
                if ch in pairs:
                    stack.append(pairs[ch])
                elif ch in closing:
                    self.assertTrue(stack and stack[-1] == ch, f"Unbalanced delimiter {ch!r} in {sf}")
                    stack.pop()
            self.assertEqual(stack, [], f"Unclosed delimiters {stack} in {sf}")

            # iOS sandbox forbids spawning external ssh/wg binaries
            self.assertNotIn("posix_spawn(", cleaned, f"Forbidden posix_spawn in {sf}")
            self.assertNotRegex(cleaned, r"\bProcess\s*\(", f"Forbidden external Process() spawn in {sf}")
            self.assertNotIn("AcceptAllHostKeys", cleaned, f"Insecure SSH host-key bypass forbidden in {sf}")

            if "Sources" in sf.parts:
                combined_prod_sources.append(raw)

        all_prod = "\n".join(combined_prod_sources)
        # Confirm core native iOS APIs and honesty invariants are wired in production modules
        for required_symbol in (
            "NEPacketTunnelProvider",
            "WireGuardAdapter",
            "NIOSSHHandler",
            "SSHChannelType.DirectTCPIP",
            "SecTrustEvaluateWithError",
            "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
            "NWPathMonitor",
            "UNVERIFIED_ON_PHYSICAL_IPHONE",
            "REMOTE_SERVER_REQUIRED",
        ):
            self.assertIn(required_symbol, all_prod, f"Expected native iOS symbol {required_symbol!r} in Sources/")

        # Confirm zero hardcoded public server IPv4 addresses in production Swift sources
        ipv4_hits = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _strip_swift_comments_and_strings(all_prod)))
        allowed_ips = {"127.0.0.1", "0.0.0.0", "198.18.0.2", "255.255.255.252"}
        # Extract string-literal IPs too for strict check
        all_literal_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", all_prod))
        unexpected_ips = all_literal_ips - allowed_ips - {"128.0.0.0"}
        self.assertEqual(
            unexpected_ips,
            set(),
            f"Production Swift sources must not contain hardcoded remote server IPs: {unexpected_ips}",
        )


if __name__ == "__main__":
    unittest.main()
