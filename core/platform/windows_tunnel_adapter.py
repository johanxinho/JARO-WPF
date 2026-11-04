"""JARO WPF - Windows 10/11 Native OpenSSH & WireGuard Tunnel Service Adapters (Phase 6).

Prepares clean, non-invasive Windows compatibility alongside the verified Linux Python core and
native iOS Swift engine:
1. `WindowsOpenSshAdapter`:
   - Resolves built-in Windows OpenSSH client (`%SystemRoot%\\System32\\OpenSSH\\ssh.exe`).
   - Audits Windows NTFS ACL output (`icacls`) to ensure private keys do not grant access to
     `Everyone`, `BUILTIN\\Users`, or `Authenticated Users`.
   - Builds `CREATE_NEW_PROCESS_GROUP` subprocess arguments for clean non-POSIX process termination.
2. `WindowsWireGuardServiceAdapter`:
   - Resolves official WireGuard for Windows binaries (`wireguard.exe`, `wg.exe`).
   - Strictly enforces `PrivilegePolicyGate` (zero automatic UAC elevation; `/installtunnelservice`
     and `/uninstalltunnelservice` are blocked unless explicitly authorized).
   - Parses PowerShell `Get-NetRoute` JSON output into JARO WPF's canonical `verify_route_isolation()`
     format so default-route protection (`0.0.0.0/0`, `::/0`) works identically on Windows.
   - Parses `netsh wlan show interfaces` / cost hints for `CostManager` integration.
"""
import json
import os
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional

from core.protocols.vpn_tunnel_engine import validate_interface_name, validate_wireguard_config_file
from core.security.secret_guard import PrivilegePolicyGate, redact_secrets

WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
FORBIDDEN_WINDOWS_ACL_PRINCIPALS = (
    "everyone:",
    "todos:",
    "builtin\\users:",
    "nt authority\\authenticated users:",
)


def audit_windows_icacls_output(icacls_stdout: str) -> Dict[str, Any]:
    """Audits `icacls <identity_file>` output to reject overly permissive NTFS key ACLs on Windows."""
    lines = [ln.strip() for ln in (icacls_stdout or "").splitlines() if ln.strip()]
    if not lines:
        return {"valid": False, "error": "Empty icacls ACL output"}

    violations: List[str] = []
    for ln in lines:
        lower = ln.lower()
        if lower.startswith("successfully processed") or lower.startswith("se procesaron"):
            continue
        for bad in FORBIDDEN_WINDOWS_ACL_PRINCIPALS:
            if bad in lower:
                violations.append(f"Broad NTFS principal permitted on private key: {ln}")
    return {
        "valid": len(violations) == 0,
        "violations": violations,
        "error": "; ".join(violations) if violations else None,
    }


def parse_windows_net_routes_json(
    powershell_json: str,
    tunnel_interface_alias: Optional[str] = None,
) -> Dict[str, Any]:
    """Converts Windows `Get-NetRoute | Select DestinationPrefix,InterfaceAlias,NextHop | ConvertTo-Json`
    into JARO WPF's canonical routing snapshot compatible with `verify_route_isolation()`.
    """
    if not powershell_json or not powershell_json.strip():
        return {
            "available": False,
            "default_routes": [],
            "interface_routes": [],
            "has_global_route_on_interface": False,
            "error": "Empty Windows Get-NetRoute JSON output",
        }
    try:
        parsed = json.loads(powershell_json)
    except json.JSONDecodeError as exc:
        return {
            "available": False,
            "default_routes": [],
            "interface_routes": [],
            "has_global_route_on_interface": False,
            "error": f"Invalid Get-NetRoute JSON: {exc}",
        }

    rows = parsed if isinstance(parsed, list) else [parsed]
    default_routes: List[Dict[str, Any]] = []
    interface_routes: List[Dict[str, Any]] = []
    has_global = False

    for r in rows:
        if not isinstance(r, dict):
            continue
        dst = str(r.get("DestinationPrefix", "")).strip()
        dev = str(r.get("InterfaceAlias", "")).strip()
        nh = str(r.get("NextHop", "")).strip()
        gw = None if nh in ("", "0.0.0.0", "::") else nh
        is_def = dst in ("0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")
        entry = {"dst": "default" if dst in ("0.0.0.0/0", "::/0") else dst, "dev": dev, "gateway": gw}
        if is_def:
            default_routes.append(entry)
        if tunnel_interface_alias and dev.lower() == tunnel_interface_alias.lower():
            interface_routes.append(entry)
            if is_def:
                has_global = True

    return {
        "available": True,
        "default_routes": default_routes,
        "interface_routes": interface_routes,
        "has_global_route_on_interface": has_global,
        "error": None,
    }


def parse_windows_netsh_wlan_metered(netsh_output: str) -> Optional[bool]:
    """Parses Windows `netsh wlan show profile` / cost output without assuming Wi-Fi is free."""
    lower = (netsh_output or "").lower()
    if not lower:
        return None
    if "fixed" in lower or "variable" in lower or "medido" in lower or "fijo" in lower:
        if "unrestricted" not in lower and "sin restricciones" not in lower:
            return True
    if "unrestricted" in lower or "sin restricciones" in lower:
        return False
    return None


class WindowsOpenSshAdapter:
    """Prepares native Windows 10/11 `ssh.exe` tunnel execution parameters."""

    def __init__(self, system_root: Optional[str] = None) -> None:
        self.system_root = system_root or os.environ.get("SystemRoot", r"C:\Windows")

    def locate_ssh_exe(self) -> Optional[str]:
        if os.name == "nt":
            sys_ssh = Path(self.system_root) / "System32" / "OpenSSH" / "ssh.exe"
            if sys_ssh.is_file():
                return str(sys_ssh)
            return shutil.which("ssh.exe") or shutil.which("ssh")
        return None

    @staticmethod
    def subprocess_creation_kwargs() -> Dict[str, Any]:
        if os.name == "nt":
            return {"creationflags": WINDOWS_CREATE_NEW_PROCESS_GROUP}
        return {"start_new_session": True}

    def build_ssh_socks5_command(
        self,
        *,
        ssh_exe: str,
        host: str,
        port: int,
        username: str,
        identity_file: str,
        known_hosts_file: str,
        local_bind_host: str = "127.0.0.1",
        local_socks_port: int = 1080,
    ) -> List[str]:
        if local_bind_host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("Windows local SOCKS5 bind host must be loopback")
        return [
            ssh_exe,
            "-N",
            "-T",
            "-D",
            f"{local_bind_host}:{int(local_socks_port)}",
            "-p",
            str(int(port)),
            "-i",
            identity_file,
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts_file}",
            "-o",
            "GlobalKnownHostsFile=NUL",
            "-o",
            "ExitOnForwardFailure=yes",
            f"{username}@{host}",
        ]


class WindowsWireGuardServiceAdapter:
    """Prepares privilege-gated WireGuard for Windows (`wireguard.exe` / `wg.exe`) tunnel operations."""

    def __init__(
        self,
        program_files: Optional[str] = None,
        privilege_gate: Optional[PrivilegePolicyGate] = None,
    ) -> None:
        self.program_files = program_files or os.environ.get("ProgramFiles", r"C:\Program Files")
        self.privilege_gate = privilege_gate or PrivilegePolicyGate()

    def detect_binaries(self) -> Dict[str, Optional[str]]:
        wg_dir = Path(self.program_files) / "WireGuard"
        wg_ui = str(wg_dir / "wireguard.exe") if (os.name == "nt" and (wg_dir / "wireguard.exe").is_file()) else shutil.which("wireguard.exe")
        wg_cli = str(wg_dir / "wg.exe") if (os.name == "nt" and (wg_dir / "wg.exe").is_file()) else shutil.which("wg.exe")
        return {
            "wireguard_exe": wg_ui if os.name == "nt" else None,
            "wg_exe": wg_cli if os.name == "nt" else None,
        }

    def prepare_install_service_command(
        self,
        *,
        tunnel_name: str,
        config_path: str | Path,
        authorized: bool = False,
        allow_global_routes: bool = False,
        wireguard_exe_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates config and returns the exact Windows service command ONLY if authorized by PrivilegePolicyGate."""
        if not validate_interface_name(tunnel_name):
            return {"ready": False, "error": f"Invalid Windows tunnel service name: {tunnel_name!r}"}

        cval = validate_wireguard_config_file(
            config_path,
            authorized=authorized,
            allow_global_routes=allow_global_routes,
        )
        if not cval["valid"]:
            return {"ready": False, "error": redact_secrets(str(cval["error"]))}

        perm = self.privilege_gate.check_interface_mutation(
            f"install Windows WireGuard tunnel service '{tunnel_name}'",
            requires_root=False,  # Checked separately via allow_privileged_commands below
        )
        if not perm["allowed"] or not self.privilege_gate.allow_privileged_commands:
            return {
                "ready": False,
                "authorization_required": True,
                "error": (
                    "Explicit Administrator/UAC authorization required before installing Windows WireGuard "
                    "tunnel service (automatic privilege elevation is disabled by policy)"
                ),
            }

        exe = wireguard_exe_override or self.detect_binaries()["wireguard_exe"] or r"C:\Program Files\WireGuard\wireguard.exe"
        return {
            "ready": True,
            "authorization_required": False,
            "command": [exe, "/installtunnelservice", str(Path(config_path))],
            "uninstall_command": [exe, "/uninstalltunnelservice", tunnel_name],
            "error": None,
        }
