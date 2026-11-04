"""JARO WPF - Cross-Platform Profile Manager (`.jaroprofile` v1.0 for Linux, Windows & iOS).

Implements Priority A of Phase 6 (`JaroProfiles`), sharing a single deterministic, secret-free
JSON schema (`schema_version = "1.0.0"`) across:
- Linux & Windows Python core (`core/profiles/jaro_profile_manager.py`)
- iOS Swift `JaroProfiles` module (`ios/Sources/JaroProfiles/JaroProfileManager.swift`)

Security & Policy Invariants:
- NEVER stores plaintext passwords, SSH private keys, or WireGuard PrivateKeys/PresharedKeys in
  `.jaroprofile` JSON bundles.
- When importing a standard WireGuard `.conf` file, extracts `PrivateKey` and optional `PresharedKey`
  into an isolated `0o600` local vault entry while writing only `keychain://group.com.jarocomplements.jarowpf/...`
  references into the exported `.jaroprofile` bundle.
- Enforces `include_default_route = False` by default, rejecting `0.0.0.0/0`, `::/0`, and `/1`
  split-default routes unless `allow_global_routes=True` is explicitly authorized.
- Keeps remote server registries empty by default and reports `REMOTE_SERVER_REQUIRED` (never `SUCCESS`)
  when no authorized remote profile exists.
"""
import base64
import binascii
import configparser
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from core.connection.server_manager import ServerStatus, is_loopback_host
from core.protocols.vpn_tunnel_engine import (
    GLOBAL_ROUTE_NETWORKS,
    validate_wireguard_config_text,
)
from core.security.secret_guard import (
    SecretSecurityError,
    audit_json_no_plaintext_secrets,
    protect_sensitive_file,
    redact_secrets,
)

JARO_PROFILE_SCHEMA_VERSION = "1.0.0"
DEFAULT_IOS_APP_GROUP = "group.com.jarocomplements.jarowpf"
DEFAULT_IOS_EXTENSION_BUNDLE_ID = "com.jarocomplements.jarowpf.PacketTunnel"
_PROFILE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$")


class JaroProfileError(Exception):
    """Raised on invalid profile syntax, unauthorized global routes, or secret policy violations."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_valid_wg_pubkey_b64(key_b64: str) -> bool:
    val = (key_b64 or "").strip()
    if len(val) != 44 or not val.endswith("="):
        return False
    try:
        return len(base64.b64decode(val, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _validate_profile_id(profile_id: str) -> str:
    pid = (profile_id or "").strip()
    if not _PROFILE_ID_RE.match(pid):
        raise JaroProfileError(
            f"Invalid profile_id {profile_id!r}; must match [a-zA-Z0-9][a-zA-Z0-9._-]{{1,63}}"
        )
    return pid


@dataclass
class JaroTunnelProfile:
    """Portable, secret-free tunnel profile shared across Linux, Windows, and iOS (`JaroProfiles`)."""
    profile_id: str
    display_name: str
    protocol: str  # "wireguard" | "ssh_socks5"
    host: str
    port: int
    authorized: bool = False
    include_default_route: bool = False
    included_routes: List[str] = field(default_factory=list)
    mtu: int = 1420
    # WireGuard non-secret metadata + Keychain reference
    tunnel_address_cidr: Optional[str] = None
    peer_public_key_b64: Optional[str] = None
    persistent_keepalive_s: Optional[int] = None
    keychain_secret_ref: str = ""
    keychain_psk_ref: Optional[str] = None
    # SSH/SOCKS5 non-secret metadata + Keychain reference
    ssh_username: Optional[str] = None
    pinned_hostkey_sha256: Optional[str] = None
    local_proxy_port: int = 1080
    # Cross-platform local vault references (not exported when targeting pure iOS bundle)
    local_secret_file: Optional[str] = None
    created_utc: str = field(default_factory=_utc_now_iso)

    def __post_init__(self) -> None:
        self.profile_id = _validate_profile_id(self.profile_id)
        self.protocol = self.protocol.strip().lower()
        if self.protocol not in ("wireguard", "ssh_socks5"):
            raise JaroProfileError(f"Unsupported tunnel protocol: {self.protocol!r}")
        self.host = self.host.strip()
        if not self.host:
            raise JaroProfileError("Profile host must not be empty")
        if not (1 <= int(self.port) <= 65535):
            raise JaroProfileError(f"Invalid port: {self.port}")
        if not (1280 <= int(self.mtu) <= 1500):
            raise JaroProfileError(f"Invalid MTU {self.mtu}; expected 1280..1500")
        if not self.keychain_secret_ref.startswith("keychain://"):
            raise JaroProfileError(
                "keychain_secret_ref must be a 'keychain://' identifier (plaintext keys are forbidden)"
            )

        # Validate route isolation invariant
        normalized_routes: List[str] = []
        for raw_cidr in self.included_routes:
            try:
                net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
            except ValueError as exc:
                raise JaroProfileError(f"Invalid CIDR in included_routes ({raw_cidr!r}): {exc}") from exc
            if net in GLOBAL_ROUTE_NETWORKS and not self.include_default_route:
                raise JaroProfileError(
                    f"Global route {net} rejected because include_default_route is False"
                )
            normalized_routes.append(str(net))
        self.included_routes = normalized_routes

        if self.protocol == "wireguard":
            if not self.tunnel_address_cidr:
                raise JaroProfileError("WireGuard profile requires tunnel_address_cidr")
            try:
                ipaddress.ip_interface(self.tunnel_address_cidr.strip())
            except ValueError as exc:
                raise JaroProfileError(f"Invalid tunnel_address_cidr: {exc}") from exc
            if not self.peer_public_key_b64 or not _is_valid_wg_pubkey_b64(self.peer_public_key_b64):
                raise JaroProfileError("WireGuard profile requires a valid 32-byte Base64 peer_public_key_b64")
        elif self.protocol == "ssh_socks5":
            if not self.ssh_username or not self.ssh_username.strip():
                raise JaroProfileError("SSH profile requires ssh_username")
            if not self.pinned_hostkey_sha256 or not self.pinned_hostkey_sha256.startswith("SHA256:"):
                raise JaroProfileError(
                    "SSH profile requires pinned_hostkey_sha256 starting with 'SHA256:'"
                )
            if not (1024 <= int(self.local_proxy_port) <= 65535):
                raise JaroProfileError(f"Invalid local_proxy_port {self.local_proxy_port}; expected 1024..65535")

    @property
    def is_loopback(self) -> bool:
        return is_loopback_host(self.host)

    @property
    def is_remote(self) -> bool:
        return not self.is_loopback

    def to_portable_dict(self, include_local_paths: bool = False) -> Dict[str, Any]:
        """Serializes to the canonical `.jaroprofile` v1.0 JSON schema shared with iOS Swift."""
        payload: Dict[str, Any] = {
            "schema_version": JARO_PROFILE_SCHEMA_VERSION,
            "organization": "JARO COMPLEMETS",
            "project": "JARO WPF",
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            "protocol": self.protocol,
            "host": self.host,
            "port": int(self.port),
            "scope": "local_loopback" if self.is_loopback else "remote",
            "authorized": bool(self.authorized),
            "include_default_route": bool(self.include_default_route),
            "included_routes": list(self.included_routes),
            "mtu": int(self.mtu),
            "ios_targets": {
                "app_group": DEFAULT_IOS_APP_GROUP,
                "extension_bundle_id": DEFAULT_IOS_EXTENSION_BUNDLE_ID,
                "extension_memory_ceiling_mb": 15,
                "device_verified": False,
                "verification_status": "UNVERIFIED_ON_PHYSICAL_IPHONE",
            },
            "crypto_references": {
                "keychain_secret_ref": self.keychain_secret_ref,
                "keychain_psk_ref": self.keychain_psk_ref,
                "keychain_accessibility": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
            },
            "wireguard": (
                {
                    "tunnel_address_cidr": self.tunnel_address_cidr,
                    "peer_public_key_b64": self.peer_public_key_b64,
                    "persistent_keepalive_s": self.persistent_keepalive_s,
                }
                if self.protocol == "wireguard"
                else None
            ),
            "ssh_socks5": (
                {
                    "username": self.ssh_username,
                    "pinned_hostkey_sha256": self.pinned_hostkey_sha256,
                    "local_proxy_port": int(self.local_proxy_port),
                    "supports_http_connect_bridge": True,
                }
                if self.protocol == "ssh_socks5"
                else None
            ),
            "created_utc": self.created_utc,
        }
        if include_local_paths and self.local_secret_file:
            payload["local_vault"] = {"config_path": self.local_secret_file}

        sec_audit = audit_json_no_plaintext_secrets(payload, path_prefix=f"profile[{self.profile_id}]")
        if not sec_audit["safe"]:
            raise SecretSecurityError(f"Refusing to serialize profile with secret: {sec_audit['error']}")
        return payload

    @classmethod
    def from_portable_dict(cls, data: Dict[str, Any]) -> "JaroTunnelProfile":
        """Deserializes and validates a `.jaroprofile` v1.0 JSON object."""
        sec_audit = audit_json_no_plaintext_secrets(data, path_prefix="imported_profile")
        if not sec_audit["safe"]:
            raise SecretSecurityError(f"Rejected `.jaroprofile` containing plaintext secret: {sec_audit['error']}")

        if data.get("schema_version") != JARO_PROFILE_SCHEMA_VERSION:
            raise JaroProfileError(
                f"Unsupported `.jaroprofile` schema_version: {data.get('schema_version')!r}"
            )

        proto = str(data.get("protocol", "")).strip().lower()
        crypto = data.get("crypto_references") or {}
        wg_block = data.get("wireguard") or {}
        ssh_block = data.get("ssh_socks5") or {}
        local_vault = data.get("local_vault") or {}

        return cls(
            profile_id=str(data.get("profile_id", "")),
            display_name=str(data.get("display_name") or data.get("profile_id") or ""),
            protocol=proto,
            host=str(data.get("host", "")),
            port=int(data.get("port", 0)),
            authorized=bool(data.get("authorized", False)),
            include_default_route=bool(data.get("include_default_route", False)),
            included_routes=list(data.get("included_routes") or []),
            mtu=int(data.get("mtu", 1420)),
            tunnel_address_cidr=wg_block.get("tunnel_address_cidr"),
            peer_public_key_b64=wg_block.get("peer_public_key_b64"),
            persistent_keepalive_s=wg_block.get("persistent_keepalive_s"),
            keychain_secret_ref=str(crypto.get("keychain_secret_ref", "")),
            keychain_psk_ref=crypto.get("keychain_psk_ref"),
            ssh_username=ssh_block.get("username"),
            pinned_hostkey_sha256=ssh_block.get("pinned_hostkey_sha256"),
            local_proxy_port=int(ssh_block.get("local_proxy_port", 1080)),
            local_secret_file=local_vault.get("config_path"),
            created_utc=str(data.get("created_utc") or _utc_now_iso()),
        )


class JaroProfileManager:
    """Manages import, export, secret-separation, and readiness checks for JARO profiles."""

    def __init__(self, storage_dir: Optional[Path] = None) -> None:
        self.storage_dir = Path(storage_dir) if storage_dir else None
        self._profiles: Dict[str, JaroTunnelProfile] = {}
        if self.storage_dir and self.storage_dir.is_dir():
            self.reload()

    def reload(self) -> None:
        if not self.storage_dir or not self.storage_dir.is_dir():
            return
        self._profiles.clear()
        for p_file in sorted(self.storage_dir.glob("*.jaroprofile")):
            raw = json.loads(p_file.read_text(encoding="utf-8"))
            prof = JaroTunnelProfile.from_portable_dict(raw)
            self._profiles[prof.profile_id] = prof

    def add_profile(self, profile: JaroTunnelProfile, persist: bool = False) -> JaroTunnelProfile:
        self._profiles[profile.profile_id] = profile
        if persist:
            if not self.storage_dir:
                raise JaroProfileError("storage_dir required to persist `.jaroprofile`")
            self.export_profile_file(
                profile.profile_id,
                self.storage_dir / f"{profile.profile_id}.jaroprofile",
                include_local_paths=True,
            )
        return profile

    def remove_profile(self, profile_id: str) -> bool:
        existed = self._profiles.pop(profile_id, None) is not None
        if existed and self.storage_dir:
            target = self.storage_dir / f"{profile_id}.jaroprofile"
            if target.is_file():
                target.unlink()
        return existed

    def get_profile(self, profile_id: str) -> Optional[JaroTunnelProfile]:
        return self._profiles.get(profile_id)

    def list_profiles(
        self,
        protocol: Optional[str] = None,
        authorized_only: bool = False,
        remote_only: bool = False,
    ) -> List[JaroTunnelProfile]:
        items = list(self._profiles.values())
        if protocol:
            items = [p for p in items if p.protocol == protocol]
        if authorized_only:
            items = [p for p in items if p.authorized]
        if remote_only:
            items = [p for p in items if p.is_remote]
        return items

    def export_profile_json(self, profile_id: str, include_local_paths: bool = False) -> str:
        prof = self._profiles.get(profile_id)
        if prof is None:
            raise KeyError(f"Unknown profile_id: {profile_id}")
        return json.dumps(prof.to_portable_dict(include_local_paths=include_local_paths), indent=2, ensure_ascii=False)

    def export_profile_file(
        self,
        profile_id: str,
        target_path: Path,
        include_local_paths: bool = False,
    ) -> Path:
        out_path = Path(target_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            self.export_profile_json(profile_id, include_local_paths=include_local_paths) + "\n",
            encoding="utf-8",
        )
        return out_path

    def import_profile_file(self, source_path: Path, persist: bool = False) -> JaroTunnelProfile:
        raw = json.loads(Path(source_path).read_text(encoding="utf-8"))
        prof = JaroTunnelProfile.from_portable_dict(raw)
        return self.add_profile(prof, persist=persist)

    def import_wireguard_conf_text(
        self,
        *,
        profile_id: str,
        display_name: str,
        conf_text: str,
        vault_dir: Path,
        authorized: bool = False,
        allow_global_routes: bool = False,
        persist: bool = False,
    ) -> JaroTunnelProfile:
        """Safely imports a WireGuard `.conf`, isolating secrets into a `0o600` vault file and returning a secret-free profile."""
        pid = _validate_profile_id(profile_id)
        val = validate_wireguard_config_text(
            conf_text,
            allow_global_routes=allow_global_routes,
            allow_dns_override=False,
        )
        if not val["valid"]:
            raise JaroProfileError(redact_secrets(str(val["error"])))

        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.optionxform = lambda opt: opt.strip()  # type: ignore[assignment]
        # Note: standard single-peer .conf fits ConfigParser cleanly
        parser.read_string(conf_text)

        iface_sec = next((s for s in parser.sections() if s.lower() == "interface"), None)
        peer_sec = next((s for s in parser.sections() if s.lower() == "peer"), None)
        if not iface_sec or not peer_sec:
            raise JaroProfileError("WireGuard configuration must contain [Interface] and [Peer] sections")

        iface_map = {k.lower(): v.strip() for k, v in parser.items(iface_sec)}
        peer_map = {k.lower(): v.strip() for k, v in parser.items(peer_sec)}

        address_first = iface_map["address"].split(",")[0].strip()
        mtu_val = int(iface_map.get("mtu", "1420"))
        pub_key = peer_map["publickey"]
        has_psk = "presharedkey" in peer_map

        ep_raw = peer_map.get("endpoint", "")
        if not ep_raw or ":" not in ep_raw:
            raise JaroProfileError("WireGuard [Peer] Endpoint (host:port) is required for JARO profile import")
        if ep_raw.startswith("["):
            ep_host, ep_port_s = ep_raw[1:].rsplit("]:", 1)
        else:
            ep_host, ep_port_s = ep_raw.rsplit(":", 1)
        ep_port = int(ep_port_s)

        allowed_ips = [c.strip() for c in peer_map["allowedips"].split(",") if c.strip()]
        keepalive = int(peer_map["persistentkeepalive"]) if "persistentkeepalive" in peer_map else None

        # Write full secret .conf ONLY to owner-protected 0o600 vault file, never into `.jaroprofile` JSON!
        vault_path = Path(vault_dir)
        vault_path.mkdir(parents=True, exist_ok=True)
        secret_conf_file = vault_path / f"{pid}.wg.conf"
        secret_conf_file.write_text(conf_text, encoding="utf-8")
        prot = protect_sensitive_file(secret_conf_file, 0o600)
        if not prot["protected"]:
            secret_conf_file.unlink(missing_ok=True)
            raise SecretSecurityError(f"Failed to enforce 0o600 on WireGuard secret vault: {prot['error']}")

        keychain_ref = f"keychain://{DEFAULT_IOS_APP_GROUP}/wireguard/{pid}/private_key"
        psk_ref = f"keychain://{DEFAULT_IOS_APP_GROUP}/wireguard/{pid}/preshared_key" if has_psk else None

        prof = JaroTunnelProfile(
            profile_id=pid,
            display_name=display_name,
            protocol="wireguard",
            host=ep_host,
            port=ep_port,
            authorized=authorized,
            include_default_route=bool(val["modifies_global_routes"] and allow_global_routes),
            included_routes=allowed_ips,
            mtu=mtu_val,
            tunnel_address_cidr=address_first,
            peer_public_key_b64=pub_key,
            persistent_keepalive_s=keepalive,
            keychain_secret_ref=keychain_ref,
            keychain_psk_ref=psk_ref,
            local_secret_file=str(secret_conf_file),
        )
        return self.add_profile(prof, persist=persist)

    def evaluate_remote_status(self, protocol: Optional[str] = None) -> Dict[str, Any]:
        """Returns explicit REMOTE_SERVER_REQUIRED (never SUCCESS) when no authorized remote profile exists."""
        remote_auth = self.list_profiles(protocol=protocol, authorized_only=True, remote_only=True)
        if not remote_auth:
            return {
                "status": ServerStatus.REMOTE_SERVER_REQUIRED.value,
                "ready": False,
                "remote_authorized_count": 0,
                "reason": (
                    "REMOTE_SERVER_REQUIRED: No authorized remote server profile is configured. "
                    "Import an authorized .jaroprofile when your server is available."
                ),
            }
        return {
            "status": ServerStatus.UNVERIFIED.value,
            "ready": False,
            "remote_authorized_count": len(remote_auth),
            "profile_ids": [p.profile_id for p in remote_auth],
            "reason": "Authorized remote profile(s) registered; live tunnel handshake/HTTPS verification required",
        }
