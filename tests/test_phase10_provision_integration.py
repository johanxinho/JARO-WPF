"""Pruebas de integracion del aprovisionamiento VPS en entorno aislado (fase 4).

Ejecutan provision_wireguard_server.sh con --prefix (sin systemd real, sin
red real) y binarios sustitutos en PATH. Todas las claves usadas son de
PRUEBA y se descartan al terminar.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "tools" / "vps" / "provision_wireguard_server.sh"
GENERATOR = REPO / "tools" / "vps" / "vps_wireguard_config.py"

# Claves de PRUEBA (base64 de 44 caracteres validos); no son secretos reales.
TEST_PRIV = "ERERERERERERERERERERERERERERERERERERERERERE="
TEST_PUB = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="

STUBS = {
    "wg": """#!/bin/sh
case "$1" in
  genkey) printf '%s\\n' 'ERERERERERERERERERERERERERERERERERERERERERE=' ;;
  pubkey) head -c 44 >/dev/null; printf '%s\\n' 'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=' ;;
  *) exit 1 ;;
esac
""",
    "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$JARO_TEST_LOG"\nexit 0\n',
    "sysctl": '#!/bin/sh\nexit 0\n',
    "apt-get": '#!/bin/sh\nexit 0\n',
    "unbound-checkconf": '#!/bin/sh\nexit 0\n',
    "ufw": '#!/bin/sh\necho "ufw $*" >> "$JARO_TEST_LOG"\nexit 0\n',
    "ip": """#!/bin/sh
if [ "$1" = "-4" ] && [ "$2" = "route" ]; then
  echo "default via 10.0.0.1 dev eth0"
fi
exit 0
""",
}


class ProvisionIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="jaro-vps-test-"))
        self.stub = self.tmp / "stubs"
        self.stub.mkdir()
        for name, body in STUBS.items():
            p = self.stub / name
            p.write_text(body)
            p.chmod(0o755)
        self.log = self.tmp / "log"
        self.log.touch()
        self.prefix = self.tmp / "env"
        self.prefix.mkdir()

    def _read(self, path: Path) -> str:
        """Leer archivos creados por root (sudo cat); sin depender de permisos."""
        return subprocess.run(
            ["sudo", "-n", "cat", str(path)], capture_output=True, text=True, check=True
        ).stdout

    def _exists(self, path: Path) -> bool:
        return subprocess.run(["sudo", "-n", "test", "-e", str(path)]).returncode == 0

    def _mode(self, path: Path) -> int:
        out = subprocess.run(
            ["sudo", "-n", "stat", "-c", "%a", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        return int(out, 8)

    def tearDown(self):
        import shutil

        subprocess.run(["sudo", "-n", "rm", "-rf", str(self.tmp)], capture_output=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *extra: str) -> subprocess.CompletedProcess:
        env = {
            "PATH": f"{self.stub}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "JARO_TEST_LOG": str(self.log),
            "HOME": "/root",
        }
        cmd = [
            "sudo", "-n", "env", f"PATH={env['PATH']}", f"JARO_TEST_LOG={self.log}",
            "HOME=/root", "bash", str(SCRIPT), "--prefix", str(self.prefix),
            "--endpoint-host", "vps.example", "--tunnel-ipv4", "10.66.66.0/24",
            "--tunnel-ipv6", "fd00:6:6::/64", "--client-name", "iphone12",
            *extra,
        ]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    def _conf(self) -> Path:
        return self.prefix / "etc" / "wireguard" / "wg0.conf"

    def _client_conf(self) -> Path:
        return self.prefix / "root" / "jaro-wireguard" / "iphone12.conf"

    def test_01_split_tunnel_defaults_and_permissions(self):
        r = self._run("--assume-dns-resolver", "--dns", "10.66.66.1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self._exists(self._conf()))
        self.assertTrue(self._exists(self._client_conf()))
        self.assertEqual(self._mode(self._conf()), 0o600)
        self.assertEqual(self._mode(self._client_conf()), 0o600)
        self.assertEqual(self._mode(self._client_conf().parent), 0o700)
        body = self._read(self._conf())
        self.assertIn("MASQUERADE", body)
        self.assertIn("ip6tables -t nat -A POSTROUTING", body)  # IPv6 declarado -> NAT66
        cbody = self._read(self._client_conf())
        self.assertIn("AllowedIPs = 10.66.66.0/24, fd00:6:6::/64", cbody)
        self.assertNotIn("0.0.0.0/0", cbody)
        self.assertIn("DNS = 10.66.66.1", cbody)
        self.assertIn("PersistentKeepalive = 25", cbody)
        # Ningun stdout/log contiene la clave privada de prueba.
        self.assertNotIn(TEST_PRIV, r.stdout)
        self.assertNotIn(TEST_PRIV, r.stderr)
        # Sin --manage-firewall no se toca UFW (ni en plan).
        self.assertNotIn("ufw ", self.log.read_text())
        self.assertNotIn("[dry-run] ufw", r.stdout)
        # La clave del servidor via archivo, no argv.
        self.assertNotIn("--private-key ", SCRIPT.read_text())

    def test_02_full_tunnel_requires_dns_and_consistency(self):
        r = self._run("--full-tunnel", "--assume-dns-resolver", "--dns", "10.66.66.1")
        self.assertEqual(r.returncode, 0, r.stderr)
        cbody = self._read(self._client_conf())
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", cbody)
        self.assertIn("DNS = 10.66.66.1", cbody)

    def test_03_full_tunnel_without_dns_fails_closed(self):
        r = self._run("--full-tunnel", "--assume-dns-resolver")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exige DNS", r.stderr)
        self.assertFalse(self._exists(self._client_conf()))

    def test_04_dns_without_resolver_fails_closed(self):
        r = self._run("--dns", "10.66.66.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("resolver", r.stderr)

    def test_05_firewall_authorized_but_ssh_not_global(self):
        self._run("--manage-firewall")
        self.log.write_text("")
        r = self._run("--manage-firewall", "--ssh-source", "192.168.1.0/24")
        self.assertEqual(r.returncode, 0, r.stderr)
        # En modo prefix solo se planifica: nada toca el firewall real.
        self.assertNotIn("ufw ", self.log.read_text())
        plan = r.stdout
        self.assertIn("[dry-run] ufw allow 51820/udp", plan)
        self.assertIn("[dry-run] ufw allow from 192.168.1.0/24 to any port 22", plan)
        self.assertNotIn("ufw allow 22/tcp", plan)

    def test_06_idempotency_second_run_preserves_keys_and_content(self):
        self._run("--assume-dns-resolver", "--dns", "10.66.66.1")
        conf1 = self._read(self._conf())
        client1 = self._read(self._client_conf())
        key1 = self._read(self.prefix / "etc" / "wireguard" / "wg0.key")
        r2 = self._run("--assume-dns-resolver", "--dns", "10.66.66.1")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(conf1, self._read(self._conf()))
        self.assertEqual(client1, self._read(self._client_conf()))
        self.assertEqual(key1, self._read(self.prefix / "etc" / "wireguard" / "wg0.key"))

    def test_07_cli_rejects_world_readable_key_file(self):
        kf = self.tmp / "bad.key"
        kf.write_text(TEST_PRIV + "\n")
        kf.chmod(0o644)
        r = subprocess.run(
            ["python3", str(GENERATOR), "client-conf", "--private-key-file", str(kf),
             "--address-ipv4", "10.66.66.2/32", "--server-public-key", TEST_PUB,
             "--endpoint", "vps.example:51820", "--allowed-ips", "10.66.66.0/24"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("0600", r.stderr)
        self.assertNotIn(TEST_PRIV, r.stderr)

    def test_08_cli_accepts_key_via_file_and_stdin_never_argv(self):
        kf = self.tmp / "good.key"
        kf.write_text(TEST_PRIV + "\n")
        kf.chmod(0o600)
        proc = subprocess.Popen(
            ["python3", str(GENERATOR), "client-conf", "--private-key-file", str(kf),
             "--address-ipv4", "10.66.66.2/32", "--server-public-key", TEST_PUB,
             "--endpoint", "vps.example:51820", "--allowed-ips", "10.66.66.0/24"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        # Mientras corre, argv del proceso no debe contener la clave.
        cmdline = Path(f"/proc/{proc.pid}/cmdline").read_bytes().decode()
        self.assertNotIn(TEST_PRIV, cmdline)
        out, _ = proc.communicate(timeout=30)
        self.assertIn("AllowedIPs = 10.66.66.0/24", out)
        # stdin '-' tambien funciona y no aparece en argv.
        r = subprocess.run(
            ["python3", str(GENERATOR), "client-conf", "--private-key", "-",
             "--address-ipv4", "10.66.66.2/32", "--server-public-key", TEST_PUB,
             "--endpoint", "vps.example:51820", "--allowed-ips", "10.66.66.0/24"],
            input=TEST_PRIV + "\n", capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PersistentKeepalive", r.stdout)

    def test_09_no_secret_material_committed_to_git(self):
        tracked = subprocess.run(
            ["git", "ls-files", "tools/vps"], cwd=REPO, capture_output=True, text=True
        ).stdout.split()
        for rel in tracked:
            self.assertFalse(rel.endswith((".key", ".conf")),
                             f"Posible secreto versionado: {rel}")


if __name__ == "__main__":
    unittest.main()
