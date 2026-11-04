"""JARO WPF - iOS Swift + NetworkExtension Tunnel Contract Exporter (Phase 5).

Prepares portable, secret-free configuration contracts for adapting JARO WPF's WireGuard and
SSH/SOCKS5 tunnels to iOS via Swift and Apple's `NetworkExtension` framework (`NEPacketTunnelProvider`).

Strict Honesty & Security Invariants:
- NEVER claims that iOS tunnels work on a physical iPhone (`device_verified` is strictly `False`
  and `verification_status` is `"UNVERIFIED_ON_PHYSICAL_IPHONE"` until tested on real hardware).
- NEVER embeds raw private keys, passwords, or pre-shared keys in `providerConfiguration`; only
  Keychain item identifiers (`keychain_wg_private_key_ref`, `keychain_ssh_identity_ref`) are allowed.
- Enforces isolated split-tunnel routes (`include_default_route=False`) by default, rejecting
  `0.0.0.0/0` and `::/0` unless `allow_global_routes=True` is explicitly authorized.
- Returns `REMOTE_SERVER_REQUIRED` when exporting from `ServerManager` without an authorized remote server.
"""
import ipaddress
from typing import Any, Dict, List, Optional

from core.connection.server_manager import ServerManager, ServerRecord, ServerStatus
from core.security.secret_guard import SecretSecurityError, audit_json_no_plaintext_secrets

IOS_PACKET_TUNNEL_EXTENSION_MEMORY_LIMIT_MB = 15
IOS_VERIFICATION_STATUS = "UNVERIFIED_ON_PHYSICAL_IPHONE"


def _validate_split_routes(cidrs: List[str], allow_global_routes: bool) -> List[Dict[str, Any]]:
    parsed_routes: List[Dict[str, Any]] = []
    for raw_cidr in cidrs:
        net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
        if net.prefixlen == 0 and not allow_global_routes:
            raise ValueError(
                f"Global default route ({net}) rejected in iOS tunnel contract without explicit allow_global_routes=True"
            )
        if isinstance(net, ipaddress.IPv4Network):
            parsed_routes.append({
                "family": "IPv4",
                "destination": str(net.network_address),
                "subnet_mask": str(net.netmask),
                "cidr": str(net),
            })
        else:
            parsed_routes.append({
                "family": "IPv6",
                "destination": str(net.network_address),
                "network_prefix_length": net.prefixlen,
                "cidr": str(net),
            })
    return parsed_routes


def build_ios_wireguard_provider_contract(
    *,
    server: ServerRecord,
    tunnel_address_cidr: str,
    peer_public_key_b64: str,
    keychain_private_key_ref: str,
    included_routes: List[str],
    mtu: int = 1420,
    allow_global_routes: bool = False,
    app_group_id: str = "group.com.jaro.wpf",
    provider_bundle_id: str = "com.jaro.wpf.PacketTunnelExtension",
) -> Dict[str, Any]:
    """Builds a secret-free NEPacketTunnelProvider dictionary for a WireGuard tunnel on iOS."""
    if not server.authorized:
        raise PermissionError(f"Server {server.server_id} is not marked as authorized")
    if server.protocol != "wireguard":
        raise ValueError(f"Expected wireguard ServerRecord, got {server.protocol}")
    if not keychain_private_key_ref or not keychain_private_key_ref.startswith("keychain://"):
        raise ValueError("keychain_private_key_ref must be a 'keychain://' reference, never a raw key")
    if not (1280 <= int(mtu) <= 1500):
        raise ValueError(f"Invalid iOS tunnel MTU ({mtu}); expected 1280..1500")

    iface_iface = ipaddress.ip_interface(tunnel_address_cidr.strip())
    routes = _validate_split_routes(included_routes, allow_global_routes=allow_global_routes)

    contract: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "target_platform": "iOS 16.0+ (Swift / NetworkExtension)",
        "provider_class": "NEPacketTunnelProvider",
        "provider_bundle_identifier": provider_bundle_id,
        "app_group_identifier": app_group_id,
        "memory_ceiling_mb": IOS_PACKET_TUNNEL_EXTENSION_MEMORY_LIMIT_MB,
        "device_verified": False,
        "verification_status": IOS_VERIFICATION_STATUS,
        "verification_notice": (
            "Architectural contract ONLY. Not yet tested on physical iPhone hardware; requires macOS Xcode "
            "build + Apple com.apple.developer.networking.networkextension entitlement."
        ),
        "tunnel_mode": "wireguard_l3",
        "server_id": server.server_id,
        "server_address": server.address,
        "include_default_route": bool(allow_global_routes),
        "network_settings": {
            "tunnel_remote_address": server.host,
            "mtu": int(mtu),
            "tunnel_address": str(iface_iface.ip),
            "tunnel_prefix_length": iface_iface.network.prefixlen,
            "included_routes": routes,
        },
        "crypto_references": {
            "keychain_wg_private_key_ref": keychain_private_key_ref,
            "peer_public_key_b64": peer_public_key_b64.strip(),
            "keychain_accessibility": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        },
    }

    sec = audit_json_no_plaintext_secrets(contract, path_prefix="ios_wg_contract")
    if not sec["safe"]:
        raise SecretSecurityError(f"Plaintext secret rejected in iOS WireGuard contract: {sec['error']}")
    return contract


def build_ios_ssh_socks5_provider_contract(
    *,
    server: ServerRecord,
    username: str,
    pinned_hostkey_fingerprint_sha256: str,
    keychain_identity_ref: str,
    local_socks_port: int = 1080,
    allow_global_routes: bool = False,
    app_group_id: str = "group.com.jaro.wpf",
    provider_bundle_id: str = "com.jaro.wpf.PacketTunnelExtension",
) -> Dict[str, Any]:
    """Builds a secret-free NEPacketTunnelProvider + NEProxySettings contract for SSH/SOCKS5 on iOS.

    Note on iOS Sandbox: iOS forbids spawning `/usr/bin/ssh` via `posix_spawn`/`Process`.
    An iOS NetworkExtension must use an in-process Swift/C SSHv2 library (e.g. SwiftNIO SSH) inside
    `NEPacketTunnelProvider` with memory strictly <= 15 MB.
    """
    if not server.authorized:
        raise PermissionError(f"Server {server.server_id} is not marked as authorized")
    if server.protocol != "ssh_socks5":
        raise ValueError(f"Expected ssh_socks5 ServerRecord, got {server.protocol}")
    if not keychain_identity_ref or not keychain_identity_ref.startswith("keychain://"):
        raise ValueError("keychain_identity_ref must be a 'keychain://' reference, never a raw private key")
    if not pinned_hostkey_fingerprint_sha256.startswith("SHA256:"):
        raise ValueError("pinned_hostkey_fingerprint_sha256 must be a pinned 'SHA256:...' host key digest")
    if not (1024 <= int(local_socks_port) <= 65535):
        raise ValueError(f"Invalid loopback proxy port: {local_socks_port}")

    contract: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "target_platform": "iOS 16.0+ (Swift / NetworkExtension)",
        "provider_class": "NEPacketTunnelProvider",
        "provider_bundle_identifier": provider_bundle_id,
        "app_group_identifier": app_group_id,
        "memory_ceiling_mb": IOS_PACKET_TUNNEL_EXTENSION_MEMORY_LIMIT_MB,
        "device_verified": False,
        "verification_status": IOS_VERIFICATION_STATUS,
        "verification_notice": (
            "Architectural contract ONLY. iOS forbids spawning external ssh binaries; requires in-process "
            "SwiftNIO SSH inside NEPacketTunnelProvider and physical iPhone verification."
        ),
        "tunnel_mode": "ssh_direct_tcpip_proxy",
        "server_id": server.server_id,
        "server_address": server.address,
        "username": username.strip(),
        "include_default_route": bool(allow_global_routes),
        "proxy_settings": {
            "loopback_bind_host": "127.0.0.1",
            "local_proxy_port": int(local_socks_port),
            "exclude_simple_hostnames": True,
        },
        "crypto_references": {
            "keychain_ssh_identity_ref": keychain_identity_ref,
            "pinned_hostkey_fingerprint_sha256": pinned_hostkey_fingerprint_sha256.strip(),
            "keychain_accessibility": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        },
    }

    sec = audit_json_no_plaintext_secrets(contract, path_prefix="ios_ssh_contract")
    if not sec["safe"]:
        raise SecretSecurityError(f"Plaintext secret rejected in iOS SSH contract: {sec['error']}")
    return contract


def export_ios_readiness_summary(server_manager: Optional[ServerManager] = None) -> Dict[str, Any]:
    """Summarizes iOS NetworkExtension readiness and enforces REMOTE_SERVER_REQUIRED when empty."""
    mgr = server_manager or ServerManager()
    ssh_ready = mgr.evaluate_remote_tunnel_readiness("ssh_socks5")
    wg_ready = mgr.evaluate_remote_tunnel_readiness("wireguard")
    return {
        "target_platform": "iOS (Swift / NetworkExtension)",
        "device_verified": False,
        "verification_status": IOS_VERIFICATION_STATUS,
        "extension_memory_limit_mb": IOS_PACKET_TUNNEL_EXTENSION_MEMORY_LIMIT_MB,
        "remote_ssh_status": ssh_ready["status"],
        "remote_wireguard_status": wg_ready["status"],
        "ready_for_remote_export": bool(
            ssh_ready["status"] != ServerStatus.REMOTE_SERVER_REQUIRED.value
            or wg_ready["status"] != ServerStatus.REMOTE_SERVER_REQUIRED.value
        ),
        "requirements_pending": [
            "Physical iPhone 12 device verification (never claim functional before hardware test)",
            "macOS + Xcode compilation environment",
            "Apple Developer entitlement: com.apple.developer.networking.networkextension (packet-tunnel-provider)",
            "Authorized remote SSH or WireGuard endpoint (currently REMOTE_SERVER_REQUIRED)",
        ],
    }
