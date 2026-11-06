#!/usr/bin/env python3
"""Generador de configuraciones WireGuard para el VPS de JARO WPF (fase 4).

Este modulo NO genera claves. Las claves se producen con `wg genkey` en la
maquina que ejecuta el aprovisionamiento y se pasan por argumento o stdin.
Ningun archivo del repositorio debe contener claves privadas.

Uso (imprime a stdout; nunca escribe archivos):
    vps_wireguard_config.py server-conf --private-key <b64> \
        --address-ipv4 10.66.66.1/24 --address-ipv6 fd00:6:6::1/64 \
        --listen-port 51820 [--peer-public-key <b64> --peer-ipv4 10.66.66.2/32 \
        --peer-ipv6 fd00:6:6::2/128] [--wan-interface eth0]
    vps_wireguard_config.py client-conf --private-key <b64> \
        --address-ipv4 10.66.66.2/32 --address-ipv6 fd00:6:6::2/128 \
        --server-public-key <b64> --endpoint <host:port> \
        [--dns 10.66.66.1 --dns fd00:6:6::1] [--keepalive 25] \
        [--full-tunnel] [--allowed-ips 10.66.66.0/24 ...]
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")

DEFAULT_KEEPALIVE_S = 25
FULL_TUNNEL_ALLOWED_IPS = ("0.0.0.0/0", "::/0")


class ConfigError(ValueError):
    """Error de validacion de una configuracion WireGuard."""


def _require_key(value: str | None, label: str) -> str:
    if not value:
        raise ConfigError(f"{label} es obligatorio")
    if not WG_KEY_RE.match(value):
        raise ConfigError(f"{label} no es una clave publica/privada WireGuard valida (base64 de 44 caracteres)")
    return value


def _validate_address(value: str, label: str) -> str:
    try:
        interface = ipaddress.ip_interface(value)
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ConfigError(f"{label} invalida: {value}") from exc
    return f"{interface.ip}/{network.prefixlen}"


def _validate_addresses(values: list[str], label: str) -> list[str]:
    if not values:
        raise ConfigError(f"{label} es obligatorio")
    nets = [_validate_address(v, label) for v in values]
    v4 = [n for n in nets if ":" not in n]
    v6 = [n for n in nets if ":" in n]
    if v4 and v6:
        pass
    elif v4 or v6:
        # Se permite una sola familia, pero se registra: el cliente JARO exige
        # dual-stack unicamente para full tunnel.
        pass
    for i, net in enumerate(nets):
        try:
            parsed = ipaddress.ip_network(net, strict=True)
            for other in nets[i + 1 :]:
                other_parsed = ipaddress.ip_network(other, strict=True)
                if parsed.version == other_parsed.version and (
                    parsed.subnet_of(other_parsed) or other_parsed.subnet_of(parsed)
                ):
                    raise ConfigError(f"Direcciones solapadas en {label}: {net} y {other}")
        except ValueError:
            continue
    return nets


def _validate_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ConfigError(f"Puerto invalido: {value}") from exc
    if not (1 <= port <= 65535):
        raise ConfigError(f"Puerto fuera de rango: {port}")
    return port


def _validate_dns(values: list[str]) -> list[str]:
    out = []
    for v in values:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ConfigError(f"Servidor DNS invalido: {v}") from exc
        out.append(v)
    return out


def validate_peer_key_pair(server_public: str, peer_public: str) -> None:
    if server_public == peer_public:
        raise ConfigError("La clave publica del peer no puede ser la del servidor")


def _first_second_hosts(net: ipaddress._BaseNetwork) -> tuple:  # type: ignore[type-arg]
    """Primer y segundo host de una red SIN enumerarla (IPv6 /64 tiene 2^64)."""
    total = net.num_addresses
    if total >= 4:
        first = net.network_address + 1
    elif total == 2:  # /127: ambos usables
        first = net.network_address
    else:  # /128 o /32: la propia direccion
        first = net.network_address
    second = first + 1 if total > 2 else None
    return first, second


def build_server_config(
    private_key: str,
    address_ipv4: str,
    address_ipv6: str | None,
    listen_port: int,
    wan_interface: str,
    peer_public_key: str | None = None,
    peer_ipv4: str | None = None,
    peer_ipv6: str | None = None,
) -> str:
    private_key = _require_key(private_key, "PrivateKey del servidor")
    addr = [_validate_address(address_ipv4, "Address IPv4 del servidor")]
    if address_ipv6:
        addr.append(_validate_address(address_ipv6, "Address IPv6 del servidor"))
    _validate_port(str(listen_port))
    if not re.match(r"^[a-zA-Z0-9._-]+$", wan_interface):
        raise ConfigError(f"Interfaz WAN invalida: {wan_interface}")

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {', '.join(addr)}",
        f"ListenPort = {listen_port}",
        "MTU = 1420",
        f"PostUp = iptables -t nat -A POSTROUTING -o {wan_interface} -j MASQUERADE",
        f"PostDown = iptables -t nat -D POSTROUTING -o {wan_interface} -j MASQUERADE",
        "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT",
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT",
    ]
    if any(":" in a for a in addr):
        # NAT66 solo si el VPS tiene ruta IPv6 publica; no implica salida IPv6.
        lines.extend(
            [
                f"PostUp = ip6tables -t nat -A POSTROUTING -o {wan_interface} -j MASQUERADE",
                f"PostDown = ip6tables -t nat -D POSTROUTING -o {wan_interface} -j MASQUERADE",
            ]
        )
    if peer_public_key:
        peer_public_key = _require_key(peer_public_key, "PublicKey del peer")
        _require_key(private_key, "PrivateKey del servidor")
        # No hay forma de comparar contra la publica del servidor aqui sin la
        # clave privada; validate_peer_key_pair se aplica en el cliente.
        peer_lines = ["", "[Peer]", f"PublicKey = {peer_public_key}"]
        allowed = []
        if peer_ipv4:
            allowed.append(_validate_address(peer_ipv4, "AllowedIPs IPv4 del peer"))
        if peer_ipv6:
            allowed.append(_validate_address(peer_ipv6, "AllowedIPs IPv6 del peer"))
        if not allowed:
            raise ConfigError("El peer necesita al menos una AllowedIPs")
        peer_lines.append(f"AllowedIPs = {', '.join(allowed)}")
        lines.extend(peer_lines)
    return "\n".join(lines) + "\n"


def build_client_config(
    private_key: str,
    address_ipv4: str,
    server_public_key: str,
    endpoint: str,
    address_ipv6: str | None = None,
    dns_servers: list[str] | None = None,
    keepalive: int = DEFAULT_KEEPALIVE_S,
    full_tunnel: bool = False,
    allowed_ips: list[str] | None = None,
) -> str:
    private_key = _require_key(private_key, "PrivateKey del cliente")
    server_public_key = _require_key(server_public_key, "PublicKey del servidor")
    if private_key == server_public_key:
        raise ConfigError("La clave privada del cliente no puede ser la PublicKey del servidor")

    addr = [_validate_address(address_ipv4, "Address IPv4 del cliente")]
    if address_ipv6:
        addr.append(_validate_address(address_ipv6, "Address IPv6 del cliente"))

    host, sep, port = endpoint.rpartition(":")
    if not sep or not host:
        raise ConfigError(f"Endpoint invalido (se espera host:puerto): {endpoint}")
    _validate_port(port)
    if re.match(r"^\[?[0-9a-fA-F:.]+\]?$", host) is None:
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*$", host):
            raise ConfigError(f"Host del endpoint invalido: {host}")

    dns = _validate_dns(list(dns_servers or []))
    if full_tunnel:
        if not dns:
            raise ConfigError(
                "Full tunnel exige DNS explicito: sin DNS valido el trafico se resuelve fuera del tunel"
            )
        allowed = list(FULL_TUNNEL_ALLOWED_IPS)
    else:
        if not allowed_ips:
            raise ConfigError("Sin full tunnel debe especificarse --allowed-ips")
        allowed = [_validate_address(a, "AllowedIPs") for a in allowed_ips]

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {', '.join(addr)}",
    ]
    if dns:
        lines.append(f"DNS = {', '.join(dns)}")
    lines.append("MTU = 1420")
    lines.extend(["", "[Peer]", f"PublicKey = {server_public_key}", f"AllowedIPs = {', '.join(allowed)}"])
    lines.append(f"Endpoint = {endpoint}")
    if keepalive > 0:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_srv = sub.add_parser("server-conf", help="Generar wg0.conf del servidor")
    p_srv.add_argument("--private-key")
    p_srv.add_argument("--private-key-file", help="Archivo 0600 con la clave; evita exponerla en argv/ps")
    p_srv.add_argument("--address-ipv4", required=True)
    p_srv.add_argument("--address-ipv6")
    p_srv.add_argument("--listen-port", type=int, required=True)
    p_srv.add_argument("--wan-interface", default="eth0")
    p_srv.add_argument("--peer-public-key")
    p_srv.add_argument("--peer-ipv4")
    p_srv.add_argument("--peer-ipv6")

    p_cli = sub.add_parser("client-conf", help="Generar .conf del cliente (solo stdout)")
    p_cli.add_argument("--private-key")
    p_cli.add_argument("--private-key-file", help="Archivo 0600 con la clave; evita exponerla en argv/ps")
    p_cli.add_argument("--address-ipv4", required=True)
    p_cli.add_argument("--address-ipv6")
    p_cli.add_argument("--server-public-key", required=True)
    p_cli.add_argument("--endpoint", required=True)
    p_cli.add_argument("--dns", action="append", default=[])
    p_cli.add_argument("--keepalive", type=int, default=DEFAULT_KEEPALIVE_S)
    p_cli.add_argument("--full-tunnel", action="store_true")
    p_cli.add_argument("--allowed-ips", action="append", default=[])

    p_addr = sub.add_parser(
        "tunnel-addresses",
        help="Derivar IPs servidor/cliente de una subred de tunel (salida KEY=value)",
    )
    p_addr.add_argument("--tunnel-ipv4", required=True)
    p_addr.add_argument("--tunnel-ipv6")

    args = parser.parse_args(argv)
    if args.command == "tunnel-addresses":
        try:
            net4 = ipaddress.ip_network(_validate_address(args.tunnel_ipv4, "tunnel-ipv4"), strict=False)
            first4, second4 = _first_second_hosts(net4)
            out = [f"SERVER_IPV4={first4}/{net4.prefixlen}"]
            out.append(f"CLIENT_IPV4={second4}/32" if second4 else "CLIENT_IPV4=")
            if args.tunnel_ipv6:
                net6 = ipaddress.ip_network(_validate_address(args.tunnel_ipv6, "tunnel-ipv6"), strict=False)
                first6, second6 = _first_second_hosts(net6)
                out.append(f"SERVER_IPV6={first6}/{net6.prefixlen}")
                out.append(f"CLIENT_IPV6={second6}/128" if second6 else "CLIENT_IPV6=")
            else:
                out.extend(["SERVER_IPV6=", "CLIENT_IPV6="])
        except ConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print("\n".join(out))
        return 0
    if args.command not in ("server-conf", "client-conf"):
        print("ERROR: subcomando desconocido", file=sys.stderr)
        return 2
    if bool(args.private_key) == bool(args.private_key_file):
        print("ERROR: usar exactamente uno de --private-key '-' (stdin) o --private-key-file", file=sys.stderr)
        return 2
    try:
        if args.private_key == "-":
            args.private_key = sys.stdin.readline().strip()
        elif args.private_key_file:
            mode = os.stat(args.private_key_file).st_mode & 0o777
            if mode != 0o600:
                raise ConfigError(f"{args.private_key_file} debe tener permisos 0600 (tiene {oct(mode)})")
            with open(args.private_key_file, encoding="ascii") as fh:
                args.private_key = fh.readline().strip()
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        if args.command == "server-conf":
            print(
                build_server_config(
                    args.private_key,
                    args.address_ipv4,
                    args.address_ipv6,
                    args.listen_port,
                    args.wan_interface,
                    args.peer_public_key,
                    args.peer_ipv4,
                    args.peer_ipv6,
                ),
                end="",
            )
        else:
            print(
                build_client_config(
                    args.private_key,
                    args.address_ipv4,
                    args.server_public_key,
                    args.endpoint,
                    args.address_ipv6,
                    args.dns,
                    args.keepalive,
                    args.full_tunnel,
                    args.allowed_ips,
                ),
                end="",
            )
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
