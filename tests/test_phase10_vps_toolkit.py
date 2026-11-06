"""Pruebas del toolkit de VPS externo (fase 4)."""

from __future__ import annotations

import importlib.util
import os
import stat
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLKIT = REPO / "tools" / "vps" / "vps_wireguard_config.py"

spec = importlib.util.spec_from_file_location("vps_wireguard_config", TOOLKIT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Claves de PRUEBA (44 chars base64 valido); no son secretos reales.
KEY_A = "A" * 42 + "A="
KEY_B = "c" * 42 + "c="


class TestServerConfig(unittest.TestCase):
    def test_valid_dual_stack_with_peer(self):
        conf = mod.build_server_config(
            KEY_A, "10.66.66.1/24", "fd00:6:6::1/64", 51820, "eth0",
            peer_public_key=KEY_B, peer_ipv4="10.66.66.2/32",
            peer_ipv6="fd00:6:6::2/128",
        )
        self.assertIn("[Peer]", conf)
        self.assertIn("ListenPort = 51820", conf)
        self.assertIn("MASQUERADE", conf)

    def test_rejects_bad_key(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_server_config("corto", "10.66.66.1/24", None, 51820, "eth0")

    def test_rejects_peer_without_allowedips(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_server_config(KEY_A, "10.66.66.1/24", None, 51820, "eth0",
                                    peer_public_key=KEY_B)

    def test_rejects_bad_wan_interface(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_server_config(KEY_A, "10.66.66.1/24", None, 51820, "eth0; rm -rf /")


class TestClientConfig(unittest.TestCase):
    def test_split_tunnel(self):
        conf = mod.build_client_config(
            KEY_A, "10.66.66.2/32", KEY_B, "vps.example:51820",
            allowed_ips=["10.66.66.0/24"], keepalive=25,
        )
        self.assertIn("AllowedIPs = 10.66.66.0/24", conf)
        self.assertIn("PersistentKeepalive = 25", conf)
        self.assertIn("Endpoint = vps.example:51820", conf)
        self.assertNotIn("DNS =", conf)

    def test_full_tunnel_requires_dns(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_client_config(KEY_A, "10.66.66.2/32", KEY_B,
                                    "vps.example:51820", full_tunnel=True)

    def test_full_tunnel_canonical_dual_stack(self):
        conf = mod.build_client_config(
            KEY_A, "10.66.66.2/32", KEY_B, "vps.example:51820",
            dns_servers=["10.66.66.1"], full_tunnel=True,
        )
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)
        self.assertIn("DNS = 10.66.66.1", conf)

    def test_rejects_bad_dns(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_client_config(KEY_A, "10.66.66.2/32", KEY_B,
                                    "vps.example:51820", dns_servers=["dns.midominio"],
                                    allowed_ips=["10.66.66.0/24"])

    def test_rejects_bad_endpoint(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_client_config(KEY_A, "10.66.66.2/32", KEY_B, "sin_puerto")

    def test_rejects_same_key_material(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_client_config(KEY_A, "10.66.66.2/32", KEY_A,
                                    "vps.example:51820", allowed_ips=["10.0.0.0/8"])

    def test_invalid_port(self):
        with self.assertRaises(mod.ConfigError):
            mod.build_client_config(KEY_A, "10.66.66.2/32", KEY_B,
                                    "vps.example:70000", allowed_ips=["10.0.0.0/8"])


class TestToolkitContracts(unittest.TestCase):
    """Contratos estructurales: sin secretos en el repo y scripts seguros."""

    def test_provision_script_hardened(self):
        text = (REPO / "tools/vps/provision_wireguard_server.sh").read_text()
        self.assertIn("set -euo pipefail", text)
        self.assertIn("wg genkey", text)  # claves solo en el VPS
        self.assertIn("chmod 0600", text)

    def test_verify_script_requires_peer_filter(self):
        text = (REPO / "tools/vps/verify_vps_evidence.sh").read_text()
        self.assertIn("--peer-public-key", text)
        self.assertIn("latest-handshakes", text)
        # La ausencia de peer debe degradar la evidencia, no reportar exito.
        self.assertIn("evidencia mas debil", text)

    def test_no_key_material_in_repo_tools(self):
        for path in (REPO / "tools" / "vps").iterdir():
            if path.suffix in {".conf", ".key"}:
                self.fail(f"Archivo con posible secreto en el repo: {path}")

    def test_executable_bits(self):
        for name in ("provision_wireguard_server.sh", "verify_vps_evidence.sh"):
            mode = os.stat(REPO / "tools" / "vps" / name).st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{name} debe ser ejecutable")


if __name__ == "__main__":
    unittest.main()
