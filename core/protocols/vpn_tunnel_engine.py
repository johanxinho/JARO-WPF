"""JARO WPF - WireGuard IP Tunnel Engine, Route Isolation Verifier & Safe Lifecycle Manager (Phase 5).

Security & Policy Invariants:
- Never generates third-party server profiles or uses unauthorized VPN endpoints.
- NEVER executes sudo/pkexec automatically; requires explicit PrivilegePolicyGate authorization
  before creating/removing interfaces or executing privileged commands.
- Blocks global default-route modification (0.0.0.0/0, ::/0, /1 split-default) unless
  allow_global_routes=True is explicitly granted, and blocks DNS overrides unless allow_dns_override=True.
- Verifies routing isolation via unprivileged `ip -j route show` snapshots (guaranteeing default
  routes remain untouched).
- Separates interface existence, fresh cryptographic handshake, bidirectional RX/TX payload transfer
  (both static threshold and live delta), and interface-bound HTTPS egress.
"""
import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional

from core.connection.reconnector import ExponentialBackoffReconnector
from core.network_tests.connectivity_prober import probe_https_egress
from core.security.secret_guard import (
    PrivilegePolicyGate,
    audit_sensitive_file,
    redact_secrets,
)

GLOBAL_ROUTE_NETWORKS = {
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("0.0.0.0/1"),
    ipaddress.ip_network("128.0.0.0/1"),
    ipaddress.ip_network("::/0"),
    ipaddress.ip_network("::/1"),
    ipaddress.ip_network("8000::/1"),
}
MAX_HANDSHAKE_AGE_SECONDS = 180
# Noise_IKpsk2 initiation (148 B) + response (92 B); >180 B RX & TX indicates encapsulated payload data
MIN_DATA_TRANSFER_BYTES = 180
_SAFE_IFNAME_RE = re.compile(r"^[a-zA-Z0-9_=+.-]{1,15}$")


def validate_interface_name(ifname: str) -> bool:
    """Validates Linux/POSIX IFNAMSIZ (<=15 chars) safe WireGuard interface identifier."""
    return bool(ifname and _SAFE_IFNAME_RE.match(ifname))


def detect_wireguard_tooling() -> Dict[str, Any]:
    """Detects available WireGuard userland binaries and kernel module availability without privileges."""
    wg_bin = shutil.which("wg") or ("/usr/bin/wg" if Path("/usr/bin/wg").is_file() else None)
    wg_quick_bin = shutil.which("wg-quick") or ("/usr/bin/wg-quick" if Path("/usr/bin/wg-quick").is_file() else None)
    ip_bin = shutil.which("ip") or ("/usr/sbin/ip" if Path("/usr/sbin/ip").is_file() else None)
    nmcli_bin = shutil.which("nmcli") or ("/usr/bin/nmcli" if Path("/usr/bin/nmcli").is_file() else None)
    win_wg_bin = shutil.which("wireguard") if os.name == "nt" else None

    kernel_module_loaded = False
    kernel_module_available = False
    if os.name == "posix":
        kernel_module_loaded = Path("/sys/module/wireguard").exists()
        krel = platform.release()
        mod_dir = Path(f"/lib/modules/{krel}/kernel/drivers/net/wireguard")
        kernel_module_available = kernel_module_loaded or (
            mod_dir.is_dir() and any(mod_dir.glob("wireguard.ko*"))
        )

    return {
        "os_name": os.name,
        "wg_binary": wg_bin,
        "wg_quick_binary": wg_quick_bin,
        "ip_binary": ip_bin,
        "nmcli_binary": nmcli_bin,
        "windows_wireguard_binary": win_wg_bin,
        "kernel_module_loaded": kernel_module_loaded,
        "kernel_module_available": kernel_module_available,
        "running_as_root": (os.geteuid() == 0) if os.name == "posix" else False,
        "cli_ready": bool((wg_bin and wg_quick_bin) or win_wg_bin),
        "wg_core_ready": bool(wg_bin and ip_bin and kernel_module_available),
    }


def _is_valid_wg_key(value: str) -> bool:
    """Validates a standard 32-byte base64-encoded Curve25519 / PSK WireGuard key."""
    val = value.strip()
    if len(val) != 44 or not val.endswith("="):
        return False
    try:
        decoded = base64.b64decode(val, validate=True)
        return len(decoded) == 32
    except (binascii.Error, ValueError):
        return False


def _parse_endpoint(endpoint: str) -> Optional[Dict[str, Any]]:
    """Parses host:port or [ipv6]:port WireGuard Endpoint syntax."""
    ep = endpoint.strip()
    if not ep:
        return None
    if ep.startswith("["):
        if "]:" not in ep:
            return None
        host_part, port_part = ep[1:].rsplit("]:", 1)
    else:
        if ":" not in ep:
            return None
        host_part, port_part = ep.rsplit(":", 1)

    if not host_part or not port_part.isdigit():
        return None
    port = int(port_part)
    if not (1 <= port <= 65535):
        return None
    return {"host": host_part, "port": port}


def validate_wireguard_config_text(
    config_text: str,
    allow_global_routes: bool = False,
    allow_dns_override: bool = False,
) -> Dict[str, Any]:
    """Validates a WireGuard configuration without logging or leaking key material."""
    section: Optional[str] = None
    interface_data: Dict[str, List[str]] = {}
    interface_seen = False
    peers: List[Dict[str, List[str]]] = []
    current_peer: Optional[Dict[str, List[str]]] = None
    allowed_interface_keys = {"privatekey", "address", "dns", "mtu"}
    allowed_peer_keys = {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}

    for line_no, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith("[") and line.endswith("]"):
            sec_name = line[1:-1].strip().lower()
            if sec_name == "interface":
                if interface_seen:
                    return {"valid": False, "error": f"Duplicate [Interface] section at line {line_no}"}
                interface_seen = True
                section = "interface"
                current_peer = None
            elif sec_name == "peer":
                section = "peer"
                current_peer = {}
                peers.append(current_peer)
            else:
                return {"valid": False, "error": f"Unknown WireGuard section [{sec_name}] at line {line_no}"}
            continue

        if "=" not in line or section is None:
            return {"valid": False, "error": f"Malformed WireGuard directive at line {line_no}"}

        key, val = line.split("=", 1)
        k_lower = key.strip().lower()
        v_clean = val.strip()

        if section == "interface":
            if k_lower not in allowed_interface_keys:
                return {"valid": False, "error": f"Unsupported Interface directive '{k_lower}' at line {line_no}"}
            if k_lower in interface_data:
                return {"valid": False, "error": f"Duplicate Interface directive '{k_lower}' at line {line_no}"}
            interface_data.setdefault(k_lower, []).append(v_clean)
        elif section == "peer" and current_peer is not None:
            if k_lower not in allowed_peer_keys:
                return {"valid": False, "error": f"Unsupported Peer directive '{k_lower}' at line {line_no}"}
            if k_lower in current_peer:
                return {"valid": False, "error": f"Duplicate Peer directive '{k_lower}' at line {line_no}"}
            current_peer.setdefault(k_lower, []).append(v_clean)

    # Validate [Interface]
    if not interface_data:
        return {"valid": False, "error": "Missing [Interface] section"}

    priv_keys = interface_data.get("privatekey", [])
    if len(priv_keys) != 1 or not _is_valid_wg_key(priv_keys[0]):
        return {"valid": False, "error": "Invalid or missing Interface PrivateKey (expected 32-byte base64 key)"}

    addresses = interface_data.get("address", [])
    if not addresses:
        return {"valid": False, "error": "Missing Interface Address CIDR"}

    parsed_addresses: List[str] = []
    for addr_group in addresses:
        for item in addr_group.split(","):
            item_s = item.strip()
            if not item_s:
                continue
            try:
                iface_ip = ipaddress.ip_interface(item_s)
                parsed_addresses.append(str(iface_ip))
            except ValueError:
                return {"valid": False, "error": f"Invalid Interface Address CIDR: {item_s}"}
    if not parsed_addresses:
        return {"valid": False, "error": "Interface Address must contain at least one valid IP CIDR"}

    if "mtu" in interface_data:
        mtu_str = interface_data["mtu"][0]
        if not mtu_str.isdigit() or not (1280 <= int(mtu_str) <= 1500):
            return {"valid": False, "error": f"Invalid WireGuard MTU '{mtu_str}' (JARO supports 1280..1500)"}

    modifies_dns = "dns" in interface_data
    dns_servers: List[str] = []
    if modifies_dns:
        for group in interface_data["dns"]:
            for raw_server in group.split(","):
                server = raw_server.strip()
                if not server:
                    return {"valid": False, "modifies_dns": True, "error": "Empty DNS server in Interface DNS directive"}
                try:
                    dns_servers.append(str(ipaddress.ip_address(server)))
                except ValueError:
                    return {"valid": False, "modifies_dns": True, "error": f"Invalid DNS server IP address '{server}'"}
        if not dns_servers or len(set(dns_servers)) != len(dns_servers):
            return {"valid": False, "modifies_dns": True, "error": "DNS must contain unique IPv4/IPv6 address literals"}
    if modifies_dns and not allow_dns_override:
        return {
            "valid": False,
            "modifies_dns": True,
            "error": "Profile modifies system DNS without explicit allow_dns_override=True authorization",
        }

    table_setting = "auto"

    # Validate [Peer] sections
    if len(peers) != 1:
        return {"valid": False, "error": "JARO profile import requires exactly one [Peer] section"}

    modifies_global_routes = False
    parsed_peers_summary: List[Dict[str, Any]] = []

    for idx, peer in enumerate(peers, start=1):
        pub_keys = peer.get("publickey", [])
        if len(pub_keys) != 1 or not _is_valid_wg_key(pub_keys[0]):
            return {"valid": False, "error": f"Invalid or missing PublicKey in Peer #{idx}"}

        if "presharedkey" in peer:
            psks = peer["presharedkey"]
            if len(psks) != 1 or not _is_valid_wg_key(psks[0]):
                return {"valid": False, "error": f"Invalid PresharedKey in Peer #{idx}"}

        if "persistentkeepalive" in peer:
            pka = peer["persistentkeepalive"][0]
            if pka.lower() != "off" and (not pka.isdigit() or not (0 <= int(pka) <= 65535)):
                return {"valid": False, "error": f"Invalid PersistentKeepalive in Peer #{idx}"}

        endpoints = peer.get("endpoint", [])
        parsed_ep = _parse_endpoint(endpoints[0]) if endpoints else None
        if endpoints and parsed_ep is None:
            return {"valid": False, "error": f"Invalid Endpoint format in Peer #{idx}"}

        allowed_raw = peer.get("allowedips", [])
        if not allowed_raw:
            return {"valid": False, "error": f"Missing AllowedIPs in Peer #{idx}"}

        peer_networks: List[str] = []
        for group in allowed_raw:
            for cidr in group.split(","):
                cidr_s = cidr.strip()
                if not cidr_s:
                    continue
                try:
                    net = ipaddress.ip_network(cidr_s, strict=False)
                except ValueError:
                    return {"valid": False, "error": f"Invalid AllowedIPs CIDR '{cidr_s}' in Peer #{idx}"}
                peer_networks.append(str(net))
                if net.prefixlen <= 1:
                    modifies_global_routes = True

        parsed_peers_summary.append({
            "endpoint": parsed_ep,
            "allowed_ips": peer_networks,
        })

    risky_routes = {
        ipaddress.ip_network(cidr)
        for peer_summary in parsed_peers_summary
        for cidr in peer_summary["allowed_ips"]
        if ipaddress.ip_network(cidr).prefixlen <= 1
    }
    dual_stack_defaults = {
        ipaddress.ip_network("0.0.0.0/0"),
        ipaddress.ip_network("::/0"),
    }
    if modifies_global_routes and not allow_global_routes:
        return {
            "valid": False,
            "modifies_global_routes": True,
            "error": (
                "Profile modifies global default routes (0.0.0.0/0, ::/0, or /1) "
                "without explicit allow_global_routes=True authorization"
            ),
        }
    if modifies_global_routes and risky_routes != dual_stack_defaults:
        return {
            "valid": False,
            "modifies_global_routes": True,
            "error": "Full-tunnel consent requires exactly both canonical defaults (0.0.0.0/0 and ::/0); /1 or single-stack defaults are rejected",
        }
    if modifies_global_routes:
        families = {ipaddress.ip_interface(addr).version for addr in parsed_addresses}
        if families != {4, 6}:
            return {"valid": False, "modifies_global_routes": True, "error": "Full tunnel requires both IPv4 and IPv6 interface addresses"}
        if not dns_servers:
            return {"valid": False, "modifies_global_routes": True, "error": "Full tunnel requires an explicitly authorized DNS server to avoid using the physical-network resolver"}

    return {
        "valid": True,
        "modifies_global_routes": modifies_global_routes,
        "modifies_dns": modifies_dns,
        "table": table_setting,
        "addresses": parsed_addresses,
        "dns_servers": dns_servers,
        "peer_count": len(peers),
        "peers": parsed_peers_summary,
        "error": None,
    }


def validate_wireguard_config_file(
    config_path: str | Path,
    authorized: bool = False,
    allow_global_routes: bool = False,
    allow_dns_override: bool = False,
) -> Dict[str, Any]:
    """Validates an on-disk WireGuard .conf file, checking authorization and 0o600 permissions."""
    if not authorized:
        return {"valid": False, "error": "WireGuard profile is not marked as authorized"}

    path = Path(config_path)
    if not path.exists():
        return {"valid": False, "error": f"WireGuard config file not found: {path}"}

    perm_check = audit_sensitive_file(path, require_owner_only=True)
    if not perm_check["valid"]:
        return {
            "valid": False,
            "error": (
                f"Insecure permissions ({perm_check.get('mode', 'invalid')}) on WireGuard config "
                f"containing PrivateKey; expected 0o600 ({perm_check['error']})"
            ),
        }

    text = path.read_text(encoding="utf-8")
    return validate_wireguard_config_text(
        text,
        allow_global_routes=allow_global_routes,
        allow_dns_override=allow_dns_override,
    )


def parse_wg_dump_output(dump_text: str, now_epoch: Optional[int] = None) -> Dict[str, Any]:
    """Parses `wg show <iface> dump` output to determine handshake recency and payload data transfer."""
    now = int(time.time()) if now_epoch is None else now_epoch
    lines = [ln.strip() for ln in dump_text.splitlines() if ln.strip()]
    if not lines:
        return {
            "has_peers": False,
            "handshake_verified": False,
            "data_transfer_verified": False,
            "total_rx_bytes": 0,
            "total_tx_bytes": 0,
            "peers": [],
        }

    # Line 0 is interface: private-key, public-key, listen-port, fwmark (NEVER expose private-key!)
    peer_entries: List[Dict[str, Any]] = []
    any_fresh_handshake = False
    any_data_transfer = False
    total_rx = 0
    total_tx = 0

    for ln in lines[1:]:
        parts = ln.split("\t")
        if len(parts) < 8:
            continue
        pub_key = parts[0]
        endpoint = parts[2] if parts[2] != "(none)" else None
        allowed_ips = parts[3]
        latest_hs = int(parts[4]) if parts[4].isdigit() else 0
        rx_bytes = int(parts[5]) if parts[5].isdigit() else 0
        tx_bytes = int(parts[6]) if parts[6].isdigit() else 0

        total_rx += rx_bytes
        total_tx += tx_bytes

        hs_age = (now - latest_hs) if latest_hs > 0 else None
        is_fresh = hs_age is not None and -2 <= hs_age <= MAX_HANDSHAKE_AGE_SECONDS and rx_bytes > 0
        has_payload_data = (
            is_fresh
            and rx_bytes > MIN_DATA_TRANSFER_BYTES
            and tx_bytes > MIN_DATA_TRANSFER_BYTES
        )
        if is_fresh:
            any_fresh_handshake = True
        if has_payload_data:
            any_data_transfer = True

        peer_entries.append({
            "peer_public_key_prefix": pub_key[:8] + "...",
            "endpoint": endpoint,
            "allowed_ips": allowed_ips,
            "latest_handshake_epoch": latest_hs,
            "handshake_age_s": hs_age,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "handshake_fresh": is_fresh,
            "data_transfer_verified": has_payload_data,
        })

    return {
        "has_peers": len(peer_entries) > 0,
        "handshake_verified": any_fresh_handshake,
        "data_transfer_verified": any_data_transfer,
        "total_rx_bytes": total_rx,
        "total_tx_bytes": total_tx,
        "peers": peer_entries,
    }


def inspect_routing_table(interface_name: Optional[str] = None) -> Dict[str, Any]:
    """Reads OS IPv4/IPv6 routing table unprivileged via `ip -j route` to verify route isolation."""
    tools = detect_wireguard_tooling()
    ip_bin = tools["ip_binary"]
    if not ip_bin:
        return {
            "available": False,
            "default_routes": [],
            "interface_routes": [],
            "has_global_route_on_interface": False,
            "error": "System 'ip' binary not found",
        }

    default_routes: List[Dict[str, Any]] = []
    interface_routes: List[Dict[str, Any]] = []
    has_global_on_iface = False
    family_errors: List[str] = []

    for family_flag in ([], ["-6"]):
        try:
            res = subprocess.run(
                [ip_bin, *family_flag, "-j", "route", "show"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode != 0:
                family = "IPv6" if family_flag else "IPv4"
                family_errors.append(f"{family} route query failed: {res.stderr.strip() or res.returncode}")
                continue
            entries = json.loads(res.stdout or "[]")
            if not isinstance(entries, list):
                family_errors.append("Route query returned a non-list JSON value")
                continue
            for r in entries:
                dst = str(r.get("dst", ""))
                dev = str(r.get("dev", ""))
                gw = r.get("gateway")
                is_default = dst in ("default", "0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")
                summary = {"dst": dst, "dev": dev, "gateway": gw, "protocol": r.get("protocol")}
                if is_default:
                    default_routes.append(summary)
                if interface_name and dev == interface_name:
                    interface_routes.append(summary)
                    if is_default:
                        has_global_on_iface = True
        except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            family_errors.append(redact_secrets(str(exc)))

    return {
        "available": not family_errors,
        "default_routes": default_routes,
        "interface_routes": interface_routes,
        "has_global_route_on_interface": has_global_on_iface,
        "error": "; ".join(family_errors) if family_errors else None,
    }


def verify_route_isolation(
    baseline_routes: Dict[str, Any],
    current_routes: Dict[str, Any],
    tunnel_interface: str,
    allow_global_routes: bool = False,
) -> Dict[str, Any]:
    """Proves that a tunnel did not hijack or alter the host's default routes without authorization."""
    base_defaults = sorted(
        (r.get("dst"), r.get("dev"), r.get("gateway"))
        for r in baseline_routes.get("default_routes", [])
    )
    curr_defaults = sorted(
        (r.get("dst"), r.get("dev"), r.get("gateway"))
        for r in current_routes.get("default_routes", [])
    )
    default_unchanged = base_defaults == curr_defaults
    global_on_tunnel = bool(current_routes.get("has_global_route_on_interface", False))
    tunnel_routes = current_routes.get("interface_routes", [])

    snapshots_available = baseline_routes.get("available") is True and current_routes.get("available") is True
    isolated_ok = snapshots_available and ((default_unchanged and not global_on_tunnel) or allow_global_routes)
    error = None
    if not snapshots_available:
        error = (
            "Cannot verify route isolation: baseline/current IPv4+IPv6 route snapshot is unavailable "
            f"(baseline={baseline_routes.get('error')}, current={current_routes.get('error')})"
        )
    elif not isolated_ok:
        error = (
            f"Route isolation violation on '{tunnel_interface}': "
            f"default_unchanged={default_unchanged}, global_on_tunnel={global_on_tunnel}"
        )

    return {
        "routes_isolated_and_safe": isolated_ok,
        "default_route_unchanged": default_unchanged,
        "has_global_route_on_tunnel": global_on_tunnel,
        "tunnel_routes": tunnel_routes,
        "route_snapshots_available": snapshots_available,
        "error": error,
    }


def _select_tunnel_ipv4(addresses: List[str]) -> Optional[str]:
    """Selects the first non-loopback IPv4 address assigned to the WireGuard interface."""
    for addr in addresses:
        try:
            ip_obj = ipaddress.ip_address(addr)
            if ip_obj.version == 4 and not ip_obj.is_loopback:
                return str(ip_obj)
        except ValueError:
            continue
    return None


class WireGuardTunnelEngine:
    """Integrates WireGuard validation, route-safe state inspection, and privilege-gated management."""

    def __init__(
        self,
        interface_name: str = "wg0",
        config_path: Optional[str | Path] = None,
        authorized: bool = False,
        allow_global_routes: bool = False,
        allow_dns_override: bool = False,
        privilege_gate: Optional[PrivilegePolicyGate] = None,
        wg_dump_provider: Optional[Callable[[str], Optional[str]]] = None,
    ) -> None:
        if not validate_interface_name(interface_name):
            raise ValueError(f"Unsafe or invalid WireGuard interface name: {interface_name!r}")
        self.interface_name = interface_name
        self.config_path = Path(config_path) if config_path else None
        self.authorized = authorized
        self.allow_global_routes = allow_global_routes
        self.allow_dns_override = allow_dns_override
        self.privilege_gate = privilege_gate or PrivilegePolicyGate(
            allow_privileged_commands=False,
            authorize_interface_changes=False,
            authorize_route_changes=False,
            allow_global_routes=allow_global_routes,
        )
        self._wg_dump_provider = wg_dump_provider

    def _query_wg_dump(self, tools: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        """Reads `wg show <iface> dump` NEVER invoking sudo automatically."""
        if self._wg_dump_provider is not None:
            try:
                out = self._wg_dump_provider(self.interface_name)
                return out, (None if out is not None else "wg_dump_provider returned None")
            except Exception as exc:
                return None, redact_secrets(str(exc))

        if not tools["wg_binary"]:
            return None, "System 'wg' binary is not installed"

        if os.name == "posix" and os.geteuid() != 0:
            if not self.privilege_gate.allow_privileged_commands:
                return (
                    None,
                    "Reading live WireGuard kernel peer state requires root/CAP_NET_ADMIN; "
                    "automatic sudo is disabled by policy (allow_privileged_commands=False)",
                )
            sudo_bin = shutil.which("sudo")
            if not sudo_bin:
                return None, "sudo binary not available for explicitly authorized wg dump"
            cmd = [sudo_bin, "-n", tools["wg_binary"], "show", self.interface_name, "dump"]
        else:
            cmd = [tools["wg_binary"], "show", self.interface_name, "dump"]

        try:
            wg_res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if wg_res.returncode == 0:
                return wg_res.stdout, None
            return None, redact_secrets(wg_res.stderr.strip() or "Insufficient privileges to query wg dump")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, redact_secrets(str(exc))

    def inspect_state(
        self,
        verify_internet_egress: bool = False,
        egress_url: str = "https://example.com/",
        connect_host: Optional[str] = None,
        sni_hostname: Optional[str] = None,
        expected_status: int = 200,
        expected_substring: str = "Example Domain",
        ssl_context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Inspects OS interface, WireGuard handshake, bidirectional RX/TX delta, routes, and HTTPS egress."""
        tools = detect_wireguard_tooling()
        iface_exists = False
        operstate = "DOWN"
        addresses: List[str] = []

        if tools["ip_binary"]:
            try:
                res = subprocess.run(
                    [tools["ip_binary"], "-j", "address", "show", "dev", self.interface_name],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if res.returncode == 0 and res.stdout.strip():
                    info = json.loads(res.stdout)
                    if info:
                        iface_exists = True
                        operstate = info[0].get("operstate", "UNKNOWN")
                        addresses = [a.get("local") for a in info[0].get("addr_info", []) if a.get("local")]
            except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired):
                pass

        wg_handshake_verified = False
        wg_data_transfer_verified = False
        rx_before = 0
        tx_before = 0
        wg_peers: List[Dict[str, Any]] = []
        wg_query_note: Optional[str] = None

        if iface_exists:
            raw_dump, wg_query_note = self._query_wg_dump(tools)
            if raw_dump is not None:
                parsed_dump = parse_wg_dump_output(raw_dump)
                wg_handshake_verified = parsed_dump["handshake_verified"]
                wg_data_transfer_verified = parsed_dump["data_transfer_verified"]
                rx_before = parsed_dump["total_rx_bytes"]
                tx_before = parsed_dump["total_tx_bytes"]
                wg_peers = parsed_dump["peers"]
        elif not tools["wg_binary"]:
            wg_query_note = "System 'wg' binary is not installed"

        route_info = inspect_routing_table(self.interface_name)
        routes_safe = bool(route_info.get("available")) and (
            (not route_info["has_global_route_on_interface"]) or self.allow_global_routes
        )

        https_egress_verified = False
        egress_latency_ms: Optional[float] = None
        egress_error: Optional[str] = None
        bytes_estimated = 0
        rx_delta = 0
        tx_delta = 0

        if iface_exists and verify_internet_egress:
            wg_ipv4 = _select_tunnel_ipv4(addresses)
            if not wg_ipv4:
                egress_error = (
                    f"WireGuard interface '{self.interface_name}' has no IPv4 address for bound HTTPS egress probe"
                )
            elif operstate == "DOWN":
                egress_error = f"WireGuard interface '{self.interface_name}' operstate is DOWN"
            elif not routes_safe:
                egress_error = (
                    f"WireGuard interface '{self.interface_name}' carries an unauthorized global route"
                )
            else:
                egress_probe = probe_https_egress(
                    url=egress_url,
                    expected_status=expected_status,
                    expected_substring=expected_substring,
                    connect_host=connect_host,
                    sni_hostname=sni_hostname,
                    source_address=(wg_ipv4, 0),
                    ssl_context=ssl_context,
                )
                https_egress_verified = bool(egress_probe["real_internet"])
                egress_latency_ms = egress_probe.get("latency_ms") if https_egress_verified else None
                bytes_estimated = int(egress_probe.get("bytes_estimated", 0))
                egress_error = egress_probe.get("error")

                # Re-sample wg dump after live HTTPS probe to measure real bidirectional RX/TX byte delta
                post_dump, _ = self._query_wg_dump(tools)
                if post_dump is not None:
                    post_parsed = parse_wg_dump_output(post_dump)
                    wg_handshake_verified = post_parsed["handshake_verified"]
                    rx_delta = max(0, post_parsed["total_rx_bytes"] - rx_before)
                    tx_delta = max(0, post_parsed["total_tx_bytes"] - tx_before)
                    wg_data_transfer_verified = bool(
                        post_parsed["data_transfer_verified"] or (rx_delta > 0 and tx_delta > 0)
                    )
                    wg_peers = post_parsed["peers"]

        if verify_internet_egress:
            tunnel_verified = bool(
                iface_exists and wg_handshake_verified and https_egress_verified and routes_safe
            )
        else:
            tunnel_verified = bool(iface_exists and wg_handshake_verified and routes_safe)

        return {
            "category": "ip_tunnel",
            "protocol": "wireguard",
            "interface": self.interface_name,
            "tooling": tools,
            "interface_exists": iface_exists,
            "operstate": operstate,
            "addresses": addresses,
            "handshake_verified": wg_handshake_verified,
            "data_transfer_verified": wg_data_transfer_verified,
            "rx_bytes_delta": rx_delta,
            "tx_bytes_delta": tx_delta,
            "routes_safe": routes_safe,
            "interface_routes": route_info["interface_routes"],
            "https_egress_verified": https_egress_verified,
            "real_internet_verified": https_egress_verified,
            "egress_latency_ms": egress_latency_ms,
            "bytes_estimated": bytes_estimated,
            "tunnel_verified": tunnel_verified,
            "peers": wg_peers,
            "egress_error": egress_error,
            "note": wg_query_note or egress_error or route_info.get("error"),
        }

    def activate(
        self,
        *,
        authorize_interface_changes: Optional[bool] = None,
        authorize_route_changes: Optional[bool] = None,
        allow_privileged_commands: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Brings up an authorized WireGuard profile ONLY when explicitly authorized by policy."""
        if self.config_path is None:
            return {"activated": False, "error": "No WireGuard config_path provided"}

        validation = validate_wireguard_config_file(
            self.config_path,
            authorized=self.authorized,
            allow_global_routes=self.allow_global_routes,
            allow_dns_override=self.allow_dns_override,
        )
        if not validation["valid"]:
            return {"activated": False, "error": validation["error"]}

        eff_gate = PrivilegePolicyGate(
            allow_privileged_commands=(
                self.privilege_gate.allow_privileged_commands
                if allow_privileged_commands is None
                else allow_privileged_commands
            ),
            authorize_interface_changes=(
                self.privilege_gate.authorize_interface_changes
                if authorize_interface_changes is None
                else authorize_interface_changes
            ),
            authorize_route_changes=(
                self.privilege_gate.authorize_route_changes
                if authorize_route_changes is None
                else authorize_route_changes
            ),
            allow_global_routes=self.allow_global_routes,
        )

        mut_check = eff_gate.check_interface_mutation(f"activate WireGuard interface {self.interface_name}")
        if not mut_check["allowed"]:
            return {
                "activated": False,
                "authorization_required": True,
                "error": mut_check["reason"],
            }

        route_check = eff_gate.check_route_mutation(modifies_global_default=self.allow_global_routes)
        if not route_check["allowed"]:
            return {
                "activated": False,
                "authorization_required": True,
                "error": route_check["reason"],
            }

        tools = detect_wireguard_tooling()
        if not tools["wg_quick_binary"]:
            return {
                "activated": False,
                "error": "WireGuard 'wg-quick' tool is not installed on this system",
                "tooling": tools,
            }

        baseline_routes = inspect_routing_table(self.interface_name)
        if not baseline_routes.get("available"):
            return {
                "activated": False,
                "error": (
                    "Cannot safely activate WireGuard without complete IPv4/IPv6 route snapshot: "
                    f"{baseline_routes.get('error')}"
                ),
            }
        cmd = [tools["wg_quick_binary"], "up", str(self.config_path)]
        if os.name == "posix" and os.geteuid() != 0:
            sudo_bin = shutil.which("sudo")
            if not sudo_bin:
                return {"activated": False, "error": "Root privileges required to create WireGuard interface"}
            cmd = [sudo_bin, "-n"] + cmd

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode != 0:
                return {
                    "activated": False,
                    "error": redact_secrets(res.stderr.strip() or f"wg-quick up failed with code {res.returncode}"),
                }

            post_routes = inspect_routing_table(self.interface_name)
            route_audit = verify_route_isolation(
                baseline_routes,
                post_routes,
                self.interface_name,
                allow_global_routes=self.allow_global_routes,
            )
            if not route_audit["routes_isolated_and_safe"]:
                self.deactivate(
                    authorize_interface_changes=True,
                    authorize_route_changes=eff_gate.authorize_route_changes,
                    allow_privileged_commands=eff_gate.allow_privileged_commands,
                )
                return {
                    "activated": False,
                    "error": route_audit["error"],
                }

            state = self.inspect_state(verify_internet_egress=True)
            return {
                "activated": True,
                "tunnel_verified": state["tunnel_verified"],
                "route_isolation": route_audit,
                "state": state,
                "error": None,
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"activated": False, "error": redact_secrets(str(exc))}

    def deactivate(
        self,
        *,
        authorize_interface_changes: Optional[bool] = None,
        authorize_route_changes: Optional[bool] = None,
        allow_privileged_commands: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Tears down the WireGuard interface cleanly ONLY when authorized."""
        if self.config_path is None:
            return {"deactivated": False, "error": "No WireGuard config_path provided"}

        eff_gate = PrivilegePolicyGate(
            allow_privileged_commands=(
                self.privilege_gate.allow_privileged_commands
                if allow_privileged_commands is None
                else allow_privileged_commands
            ),
            authorize_interface_changes=(
                self.privilege_gate.authorize_interface_changes
                if authorize_interface_changes is None
                else authorize_interface_changes
            ),
            authorize_route_changes=(
                self.privilege_gate.authorize_route_changes
                if authorize_route_changes is None
                else authorize_route_changes
            ),
            allow_global_routes=self.allow_global_routes,
        )
        mut_check = eff_gate.check_interface_mutation(f"deactivate WireGuard interface {self.interface_name}")
        if not mut_check["allowed"]:
            return {
                "deactivated": False,
                "authorization_required": True,
                "error": mut_check["reason"],
            }
        route_check = eff_gate.check_route_mutation(modifies_global_default=self.allow_global_routes)
        if not route_check["allowed"]:
            return {
                "deactivated": False,
                "authorization_required": True,
                "error": route_check["reason"],
            }

        tools = detect_wireguard_tooling()
        if not tools["wg_quick_binary"]:
            return {"deactivated": False, "error": "WireGuard 'wg-quick' tool is not installed"}

        cmd = [tools["wg_quick_binary"], "down", str(self.config_path)]
        if os.name == "posix" and os.geteuid() != 0:
            sudo_bin = shutil.which("sudo")
            if not sudo_bin:
                return {"deactivated": False, "error": "Root privileges required to remove WireGuard interface"}
            cmd = [sudo_bin, "-n"] + cmd

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {
                "deactivated": res.returncode == 0,
                "error": None if res.returncode == 0 else redact_secrets(res.stderr.strip()),
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"deactivated": False, "error": redact_secrets(str(exc))}

    def recover(
        self,
        reconnector: Optional[ExponentialBackoffReconnector] = None,
        authorize_interface_changes: Optional[bool] = None,
        allow_privileged_commands: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Controlled tear-down and re-activation using ExponentialBackoffReconnector."""
        mgr = reconnector or ExponentialBackoffReconnector(
            base_delay=1.0,
            max_delay=15.0,
            max_attempts=2,
        )

        def _step() -> Dict[str, Any]:
            self.deactivate(
                authorize_interface_changes=authorize_interface_changes,
                allow_privileged_commands=allow_privileged_commands,
            )
            return self.activate(
                authorize_interface_changes=authorize_interface_changes,
                allow_privileged_commands=allow_privileged_commands,
            )

        def _abort(res: Dict[str, Any]) -> bool:
            if res.get("authorization_required"):
                return True
            err = str(res.get("error") or "")
            return (
                "not marked as authorized" in err
                or "Insecure permissions" in err
                or "global default routes" in err
                or "not installed" in err
                or "No WireGuard config_path" in err
            )

        return mgr.execute_with_retry(
            connect_fn=_step,
            is_success_fn=lambda r: bool(r.get("activated") and r.get("tunnel_verified")),
            should_abort_fn=_abort,
        )


def main() -> None:
    engine = WireGuardTunnelEngine(interface_name="wg0")
    print(json.dumps({"module": "JARO WPF WIREGUARD ENGINE", "state": engine.inspect_state()}, indent=4))


if __name__ == "__main__":
    main()
