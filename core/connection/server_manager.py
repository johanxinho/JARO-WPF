"""JARO WPF - Authorized Server & Tunnel Registry Manager (Phase 5).

Manages server records across DNS, HTTPS/HTTP3, SSH/SOCKS5, and WireGuard with all 9 required fields:
  1. server_id
  2. address (host + port)
  3. protocol
  4. status (including explicit REMOTE_SERVER_REQUIRED when no remote server is configured)
  5. latency_ms
  6. last_checked_utc
  7. authorized
  8. requirements
  9. verified_capabilities

Security & Honesty Invariants:
- Rejects any configuration containing plaintext passwords, private keys, or inline secrets.
- Never invents free servers or marks unauthorized infrastructure as usable.
- Returns REMOTE_SERVER_REQUIRED (never SUCCESS) when evaluating remote SSH/WireGuard without an authorized remote server.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.security.secret_guard import (
    SecretSecurityError,
    audit_json_no_plaintext_secrets,
    redact_secrets,
)

DEFAULT_SERVERS_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "servers.json"


class ServerStatus(str, Enum):
    """Canonical lifecycle states for registered servers and tunnel endpoints."""
    UNVERIFIED = "UNVERIFIED"
    LOCAL_VERIFIED = "LOCAL_VERIFIED"
    ONLINE_VERIFIED = "ONLINE_VERIFIED"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    REMOTE_SERVER_REQUIRED = "REMOTE_SERVER_REQUIRED"
    SKIPPED_MISSING_PREREQUISITE = "SKIPPED_MISSING_PREREQUISITE"
    BLOCKED_UNAUTHORIZED = "BLOCKED_UNAUTHORIZED"
    BLOCKED_COST_POLICY = "BLOCKED_COST_POLICY"


def is_loopback_host(host: str) -> bool:
    """Returns True if host resolves syntactically to loopback (127.0.0.0/8, ::1, localhost)."""
    h = (host or "").strip().lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_requirements_for_protocol(protocol: str) -> List[str]:
    """Returns mandatory technical prerequisites for a given protocol."""
    proto = protocol.lower()
    if proto == "ssh_socks5":
        return [
            "openssh_client_binary",
            "identity_file_permissions_0600",
            "known_hosts_pinned_hostkey",
            "explicit_server_authorization",
        ]
    if proto == "wireguard":
        return [
            "wireguard_kernel_support",
            "wireguard_tools_wg_binary",
            "config_file_permissions_0600",
            "isolated_routes_or_explicit_global_route_auth",
            "explicit_interface_mutation_auth",
        ]
    if proto in ("http3", "doq"):
        return ["aioquic_tls13", "x509_ca_validation", "udp_egress"]
    if proto in ("https", "dot", "tls"):
        return ["x509_ca_validation", "tcp_egress"]
    return ["socket_egress"]


def default_capabilities_for_protocol(protocol: str) -> Dict[str, bool]:
    """Initializes all capabilities to False until verified by real end-to-end probes."""
    proto = protocol.lower()
    if proto == "ssh_socks5":
        return {
            "host_key_verified": False,
            "publickey_auth_verified": False,
            "local_socks5_functional": False,
            "direct_tcpip_channel_verified": False,
            "https_egress_verified": False,
        }
    if proto == "wireguard":
        return {
            "config_valid": False,
            "interface_active": False,
            "handshake_verified": False,
            "bidirectional_transfer_verified": False,
            "routes_isolated_and_safe": False,
            "https_egress_verified": False,
        }
    if proto in ("https", "http3"):
        return {
            "tls_verified": False,
            "general_internet_egress_verified": False,
        }
    return {
        "protocol_response_verified": False,
    }


@dataclass
class ServerRecord:
    """Typed registry record for an authorized (or pending) server/tunnel endpoint."""
    server_id: str
    host: str
    port: int
    protocol: str
    authorized: bool = False
    status: ServerStatus = ServerStatus.UNVERIFIED
    latency_ms: Optional[float] = None
    last_checked_utc: Optional[str] = None
    requirements: List[str] = field(default_factory=list)
    verified_capabilities: Dict[str, bool] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_error: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.requirements:
            self.requirements = default_requirements_for_protocol(self.protocol)
        if not self.verified_capabilities:
            self.verified_capabilities = default_capabilities_for_protocol(self.protocol)
        if not self.authorized:
            self.status = ServerStatus.BLOCKED_UNAUTHORIZED

    @property
    def is_loopback(self) -> bool:
        return is_loopback_host(self.host)

    @property
    def is_remote(self) -> bool:
        return bool(self.host and not self.is_loopback)

    @property
    def address(self) -> str:
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_id": self.server_id,
            "host": self.host,
            "port": self.port,
            "address": self.address,
            "protocol": self.protocol,
            "scope": "local_loopback" if self.is_loopback else "remote",
            "status": self.status.value if isinstance(self.status, ServerStatus) else str(self.status),
            "latency_ms": round(float(self.latency_ms), 2) if self.latency_ms is not None else None,
            "last_checked_utc": self.last_checked_utc,
            "authorized": bool(self.authorized),
            "requirements": list(self.requirements),
            "verified_capabilities": dict(self.verified_capabilities),
            "metadata": dict(self.metadata),
            "last_error": redact_secrets(self.last_error) if self.last_error else None,
        }


class ServerManager:
    """Centralized, secret-safe registry for DNS, Web, SSH, and WireGuard servers."""

    def __init__(self, config_path: Path = DEFAULT_SERVERS_CONFIG_PATH) -> None:
        self.config_path = Path(config_path)
        self._records: Dict[str, ServerRecord] = {}
        self._raw_catalog: Dict[str, Any] = {}
        if self.config_path.is_file():
            self.reload()

    def reload(self) -> None:
        """Loads and security-audits configs/servers.json without modifying legacy fields."""
        raw_text = self.config_path.read_text(encoding="utf-8")
        parsed = json.loads(raw_text)
        sec_audit = audit_json_no_plaintext_secrets(parsed)
        if not sec_audit["safe"]:
            raise SecretSecurityError(f"Plaintext secret rejected in {self.config_path}: {sec_audit['error']}")

        self._raw_catalog = parsed
        self._records.clear()

        # 1. Load catalog servers (DNS / HTTPS / HTTP3)
        for srv in parsed.get("servers", []):
            base_id = srv.get("id", "unknown")
            host = srv.get("host", "")
            authorized = bool(srv.get("authorized", False))
            for proto_name, proto_cfg in srv.get("protocols", {}).items():
                if not proto_cfg.get("enabled", True):
                    continue
                rec_id = f"{base_id}:{proto_name}"
                port = int(proto_cfg.get("port", 443))
                self._records[rec_id] = ServerRecord(
                    server_id=rec_id,
                    host=host,
                    port=port,
                    protocol=proto_name,
                    authorized=authorized,
                    metadata={
                        "name": srv.get("name", base_id),
                        "hostname": srv.get("hostname"),
                        "sni": proto_cfg.get("sni"),
                        "category": proto_cfg.get("category", "unknown"),
                    },
                )

        # 2. Load authorized_ssh_tunnels
        for idx, ssh_item in enumerate(parsed.get("authorized_ssh_tunnels", []), start=1):
            sid = ssh_item.get("id") or f"ssh-{idx}"
            self._records[sid] = ServerRecord(
                server_id=sid,
                host=ssh_item.get("host", ""),
                port=int(ssh_item.get("port", 22)),
                protocol="ssh_socks5",
                authorized=bool(ssh_item.get("authorized", False)),
                metadata={
                    "username": ssh_item.get("username", ""),
                    "identity_file": ssh_item.get("identity_file", ""),
                    "known_hosts_file": ssh_item.get("known_hosts_file", ""),
                    "local_bind_host": ssh_item.get("local_bind_host", "127.0.0.1"),
                    "local_socks_port": int(ssh_item.get("local_socks_port", 1080)),
                },
            )

        # 3. Load authorized_wireguard_tunnels
        for idx, wg_item in enumerate(parsed.get("authorized_wireguard_tunnels", []), start=1):
            sid = wg_item.get("id") or f"wg-{wg_item.get('interface', 'wg0')}-{idx}"
            self._records[sid] = ServerRecord(
                server_id=sid,
                host=wg_item.get("endpoint_host", ""),
                port=int(wg_item.get("endpoint_port", 51820)),
                protocol="wireguard",
                authorized=bool(wg_item.get("authorized", False)),
                metadata={
                    "interface": wg_item.get("interface", "wg0"),
                    "config_path": wg_item.get("config_path", ""),
                },
            )

    def register_ssh_server(
        self,
        *,
        server_id: str,
        host: str,
        port: int = 22,
        username: str,
        identity_file: str,
        known_hosts_file: str,
        local_bind_host: str = "127.0.0.1",
        local_socks_port: int = 1080,
        authorized: bool = False,
        persist: bool = False,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> ServerRecord:
        """Registers an SSH tunnel endpoint (rejecting any inline password or private key)."""
        candidate_payload = {
            "id": server_id,
            "host": host.strip(),
            "port": int(port),
            "username": username.strip(),
            "identity_file": identity_file,
            "known_hosts_file": known_hosts_file,
            "local_bind_host": local_bind_host,
            "local_socks_port": int(local_socks_port),
            "authorized": bool(authorized),
            **(extra_fields or {}),
        }
        sec_check = audit_json_no_plaintext_secrets(candidate_payload, path_prefix=f"ssh[{server_id}]")
        if not sec_check["safe"]:
            raise SecretSecurityError(f"Rejected SSH server registration: {sec_check['error']}")
        if not candidate_payload["host"] or not candidate_payload["username"]:
            raise ValueError("SSH host and username are required")
        if not (1 <= candidate_payload["port"] <= 65535):
            raise ValueError(f"Invalid SSH port: {port}")

        rec = ServerRecord(
            server_id=server_id,
            host=candidate_payload["host"],
            port=candidate_payload["port"],
            protocol="ssh_socks5",
            authorized=bool(authorized),
            metadata={
                "username": candidate_payload["username"],
                "identity_file": identity_file,
                "known_hosts_file": known_hosts_file,
                "local_bind_host": local_bind_host,
                "local_socks_port": int(local_socks_port),
            },
        )
        self._records[server_id] = rec
        if persist:
            self._persist_tunnel_lists()
        return rec

    def register_wireguard_server(
        self,
        *,
        server_id: str,
        endpoint_host: str,
        endpoint_port: int = 51820,
        interface_name: str = "wg0",
        config_path: str,
        authorized: bool = False,
        persist: bool = False,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> ServerRecord:
        """Registers a WireGuard tunnel endpoint by file reference (never inline PrivateKey)."""
        candidate_payload = {
            "id": server_id,
            "endpoint_host": endpoint_host.strip(),
            "endpoint_port": int(endpoint_port),
            "interface": interface_name.strip(),
            "config_path": config_path,
            "authorized": bool(authorized),
            **(extra_fields or {}),
        }
        sec_check = audit_json_no_plaintext_secrets(candidate_payload, path_prefix=f"wg[{server_id}]")
        if not sec_check["safe"]:
            raise SecretSecurityError(f"Rejected WireGuard registration: {sec_check['error']}")
        if not candidate_payload["endpoint_host"] or not candidate_payload["config_path"]:
            raise ValueError("WireGuard endpoint_host and config_path are required")
        if not (1 <= candidate_payload["endpoint_port"] <= 65535):
            raise ValueError(f"Invalid WireGuard port: {endpoint_port}")

        rec = ServerRecord(
            server_id=server_id,
            host=candidate_payload["endpoint_host"],
            port=candidate_payload["endpoint_port"],
            protocol="wireguard",
            authorized=bool(authorized),
            metadata={
                "interface": candidate_payload["interface"],
                "config_path": config_path,
            },
        )
        self._records[server_id] = rec
        if persist:
            self._persist_tunnel_lists()
        return rec

    def remove_server(self, server_id: str, persist: bool = False) -> bool:
        """Removes a registered server by ID."""
        existed = self._records.pop(server_id, None) is not None
        if existed and persist:
            self._persist_tunnel_lists()
        return existed

    def _persist_tunnel_lists(self) -> None:
        """Safely writes authorized_ssh_tunnels and authorized_wireguard_tunnels to servers.json."""
        catalog = dict(self._raw_catalog) if self._raw_catalog else {
            "version": "2.1.0",
            "project": "JARO WPF",
            "egress_validation_endpoints": [],
            "servers": [],
        }
        ssh_list: List[Dict[str, Any]] = []
        wg_list: List[Dict[str, Any]] = []
        for rec in self._records.values():
            if rec.protocol == "ssh_socks5":
                ssh_list.append({
                    "id": rec.server_id,
                    "host": rec.host,
                    "port": rec.port,
                    "username": rec.metadata.get("username", ""),
                    "identity_file": rec.metadata.get("identity_file", ""),
                    "known_hosts_file": rec.metadata.get("known_hosts_file", ""),
                    "local_bind_host": rec.metadata.get("local_bind_host", "127.0.0.1"),
                    "local_socks_port": int(rec.metadata.get("local_socks_port", 1080)),
                    "authorized": rec.authorized,
                })
            elif rec.protocol == "wireguard":
                wg_list.append({
                    "id": rec.server_id,
                    "endpoint_host": rec.host,
                    "endpoint_port": rec.port,
                    "interface": rec.metadata.get("interface", "wg0"),
                    "config_path": rec.metadata.get("config_path", ""),
                    "authorized": rec.authorized,
                })

        catalog["authorized_ssh_tunnels"] = ssh_list
        catalog["authorized_wireguard_tunnels"] = wg_list
        sec_check = audit_json_no_plaintext_secrets(catalog)
        if not sec_check["safe"]:
            raise SecretSecurityError(f"Refusing to persist catalog with secrets: {sec_check['error']}")

        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self._raw_catalog = catalog

    def get_server(self, server_id: str) -> Optional[ServerRecord]:
        return self._records.get(server_id)

    def list_servers(
        self,
        protocol: Optional[str] = None,
        authorized_only: bool = False,
        remote_only: bool = False,
    ) -> List[ServerRecord]:
        items = list(self._records.values())
        if protocol is not None:
            items = [r for r in items if r.protocol == protocol]
        if authorized_only:
            items = [r for r in items if r.authorized]
        if remote_only:
            items = [r for r in items if r.is_remote]
        return items

    def update_verification(
        self,
        server_id: str,
        *,
        status: ServerStatus,
        latency_ms: Optional[float] = None,
        verified_capabilities: Optional[Dict[str, bool]] = None,
        error: Optional[str] = None,
    ) -> ServerRecord:
        """Updates live verification telemetry for a registered server."""
        rec = self._records.get(server_id)
        if rec is None:
            raise KeyError(f"Unknown server_id: {server_id}")
        rec.last_checked_utc = _utc_now_iso()
        if not rec.authorized:
            rec.status = ServerStatus.BLOCKED_UNAUTHORIZED
            rec.latency_ms = None
            rec.last_error = "Server is not marked as authorized"
            return rec

        rec.status = status
        rec.latency_ms = latency_ms
        if verified_capabilities:
            for cap_k, cap_v in verified_capabilities.items():
                rec.verified_capabilities[cap_k] = bool(cap_v)
        rec.last_error = redact_secrets(error) if error else None
        return rec

    def evaluate_remote_tunnel_readiness(self, protocol: str) -> Dict[str, Any]:
        """Evaluates remote tunnel availability; explicitly returns REMOTE_SERVER_REQUIRED (never SUCCESS) when empty."""
        if protocol not in ("ssh_socks5", "wireguard"):
            raise ValueError(f"Unsupported tunnel protocol for remote readiness check: {protocol}")

        remote_authorized = self.list_servers(protocol=protocol, authorized_only=True, remote_only=True)
        if not remote_authorized:
            return {
                "protocol": protocol,
                "status": ServerStatus.REMOTE_SERVER_REQUIRED.value,
                "ready": False,
                "verified_end_to_end": False,
                "configured_remote_count": 0,
                "reason": (
                    f"REMOTE_SERVER_REQUIRED: No authorized remote {protocol} server is registered in "
                    f"{self.config_path.name}. Policy forbids inventing free or third-party servers."
                ),
            }

        verified = [
            r for r in remote_authorized
            if r.status == ServerStatus.ONLINE_VERIFIED
            and r.verified_capabilities.get("https_egress_verified", False)
        ]
        if verified:
            best = min(verified, key=lambda r: r.latency_ms if r.latency_ms is not None else 999999.0)
            return {
                "protocol": protocol,
                "status": ServerStatus.ONLINE_VERIFIED.value,
                "ready": True,
                "verified_end_to_end": True,
                "configured_remote_count": len(remote_authorized),
                "active_server_id": best.server_id,
                "latency_ms": best.latency_ms,
                "reason": None,
            }

        return {
            "protocol": protocol,
            "status": ServerStatus.UNVERIFIED.value,
            "ready": False,
            "verified_end_to_end": False,
            "configured_remote_count": len(remote_authorized),
            "reason": f"{len(remote_authorized)} authorized remote {protocol} server(s) registered, pending live end-to-end verification",
        }

    def snapshot(self) -> Dict[str, Any]:
        """Returns a complete, secret-redacted inventory snapshot including remote readiness states."""
        return {
            "module": "JARO WPF SERVER MANAGER",
            "timestamp_utc": _utc_now_iso(),
            "total_registered": len(self._records),
            "remote_ssh_readiness": self.evaluate_remote_tunnel_readiness("ssh_socks5"),
            "remote_wireguard_readiness": self.evaluate_remote_tunnel_readiness("wireguard"),
            "servers": [r.to_dict() for r in self._records.values()],
        }
