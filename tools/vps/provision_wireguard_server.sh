#!/usr/bin/env bash
# Aprovisionamiento WireGuard para el VPS de JARO WPF (fase 4, revision correctiva).
# Ubuntu 22.04/24.04 o Debian 12. Requiere root. Idempotente: puede re-ejecutarse.
#
# Seguridad:
# - NO contiene claves: se generan con `wg genkey` en el VPS y se pasan al
#   generador mediante ARCHIVOS con permisos 0600 (nunca en argv/ps).
# - El .conf del cliente queda en /root/jaro-wireguard/ (0700/0600). Nunca
#   copiarlo al repositorio, CI ni documentacion.
# - --manage-firewall solo toca UFW si se pasa; SSH (TCP/22) NO se abre
#   globalmente: solo con --ssh-source <cidr>, o lo gestiona el proveedor
#   (en Oracle, la Security List de la VCN).
# - --dns no se anuncia al cliente salvo que exista un resolver operativo:
#   usa --install-unbound (lo instala y configura) o --assume-dns-resolver.
# - IPv6 NAT se genera solo si pasas --tunnel-ipv6; NO implica salida IPv6
#   publica funcional (eso se verifica aparte; ver verify_vps_evidence.sh).
# - --prefix DIR: modo de prueba aislada (sin systemctl real, rutas bajo DIR).
#
# Uso tipico (VPS real):
#   sudo bash provision_wireguard_server.sh \
#     --endpoint-host vps.ejemplo.dominio \
#     --tunnel-ipv4 10.66.66.0/24 --tunnel-ipv6 fd00:6:6::/64 \
#     --client-name iphone12 --install-unbound --manage-firewall

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WG_IF="wg0"
LISTEN_PORT="51820"
TUNNEL_IPV4=""
TUNNEL_IPV6=""
ENDPOINT_HOST=""
CLIENT_NAME="cliente1"
MANAGE_FIREWALL="0"
SSH_SOURCE=""
INSTALL_UNBOUND="0"
ASSUME_DNS_RESOLVER="0"
FULL_TUNNEL="0"
DNS_VALUES=()
PREFIX=""

usage() { sed -n '2,24p' "$0"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint-host) ENDPOINT_HOST="$2"; shift 2 ;;
    --tunnel-ipv4) TUNNEL_IPV4="$2"; shift 2 ;;
    --tunnel-ipv6) TUNNEL_IPV6="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --client-name) CLIENT_NAME="$2"; shift 2 ;;
    --dns) DNS_VALUES+=(--dns "$2"); shift 2 ;;
    --manage-firewall) MANAGE_FIREWALL="1"; shift ;;
    --ssh-source) SSH_SOURCE="$2"; shift 2 ;;
    --install-unbound) INSTALL_UNBOUND="1"; shift ;;
    --assume-dns-resolver) ASSUME_DNS_RESOLVER="1"; shift ;;
    --full-tunnel) FULL_TUNNEL="1"; shift ;;
    --wg-if) WG_IF="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Argumento desconocido: $1" >&2; usage ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Ejecutar como root (sudo)." >&2; exit 2; }
[[ -n "$ENDPOINT_HOST" && -n "$TUNNEL_IPV4" ]] || usage
[[ -z "$PREFIX" || "$PREFIX" == /* ]] || { echo "--prefix debe ser ruta absoluta" >&2; exit 2; }

# Directorios efectivos (modo normal vs modo de prueba aislada).
if [[ -n "$PREFIX" ]]; then
  CONF_DIR="$PREFIX/etc/wireguard"
  CLIENT_DIR="$PREFIX/root/jaro-wireguard"
  DRY_RUN="1"
else
  CONF_DIR="/etc/wireguard"
  CLIENT_DIR="/root/jaro-wireguard"
  DRY_RUN="0"
fi
mkdir -p "$CONF_DIR"
umask 077
mkdir -p "$CLIENT_DIR"
chmod 700 "$CLIENT_DIR"

if ! command -v wg >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq wireguard qrencode
fi

# Resolucion del DNS anunciado: solo con resolver operativo o asuncion explicita.
if [[ ${#DNS_VALUES[@]} -gt 0 && "$INSTALL_UNBOUND" != "1" && "$ASSUME_DNS_RESOLVER" != "1" ]]; then
  echo "ERROR: --dns exige un resolver operativo en el VPS." >&2
  echo "Usa --install-unbound (instala/configura Unbound) o --assume-dns-resolver si ya existe." >&2
  exit 2
fi
if [[ "$FULL_TUNNEL" == "1" && ${#DNS_VALUES[@]} -eq 0 && "$INSTALL_UNBOUND" != "1" ]]; then
  echo "ERROR: --full-tunnel exige DNS: pasa --install-unbound o --dns con resolver." >&2
  exit 2
fi
if [[ "$INSTALL_UNBOUND" == "1" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq unbound
fi

# IPs del tunel: servidor = primer host; cliente = segundo host (subcomando
# validado del generador; sin heredocs ad hoc).
ADDR_ARGS=(tunnel-addresses --tunnel-ipv4 "$TUNNEL_IPV4")
[[ -n "$TUNNEL_IPV6" ]] && ADDR_ARGS+=(--tunnel-ipv6 "$TUNNEL_IPV6")
eval "$(python3 "$SCRIPT_DIR/vps_wireguard_config.py" "${ADDR_ARGS[@]}")"
[[ -n "$CLIENT_IPV4" ]] || { echo "No se pudo derivar IP de cliente desde $TUNNEL_IPV4" >&2; exit 2; }

# Reenvio IP (necesario para NAT). En modo de prueba aislada se omite el sysctl real.
if [[ "$DRY_RUN" != "1" ]]; then
  cat > /etc/sysctl.d/70-jaro-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
  sysctl --system >/dev/null
fi

# Interfaz WAN para el NAT. En modo de prueba se permite --wan-if implicita eth0.
WAN_IF="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
[[ -n "$WAN_IF" ]] || WAN_IF="eth0"
if [[ "$DRY_RUN" != "1" ]]; then
  [[ -n "$(ip -4 route show default 2>/dev/null)" ]] || { echo "No hay ruta default; no se detecta interfaz WAN." >&2; exit 2; }
fi

SERVER_KEY="$CONF_DIR/${WG_IF}.key"
PEER_PUB="$CONF_DIR/${CLIENT_NAME}.clientpub"

# Claves: archivos 0600 en CONF_DIR; idempotencia (no se regeneran).
if [[ ! -s "$SERVER_KEY" ]]; then
  umask 077
  wg genkey > "$SERVER_KEY"
  chmod 0600 "$SERVER_KEY"
fi
if [[ ! -s "$PEER_PUB" ]]; then
  umask 077
  CLIENT_PRIV="$CONF_DIR/${CLIENT_NAME}.clientkey"
  wg genkey > "$CLIENT_PRIV"
  chmod 0600 "$CLIENT_PRIV"
  wg pubkey < "$CLIENT_PRIV" > "$PEER_PUB"
  chmod 0600 "$PEER_PUB"
fi
PEER_PUBKEY="$(cat "$PEER_PUB")"
SERVER_PUB="$(wg pubkey < "$SERVER_KEY")"

# Unbound (opcional): escucha SOLO en las IPs del tunel; sin exposicion publica.
if [[ "$INSTALL_UNBOUND" == "1" && "$DRY_RUN" != "1" ]]; then
  UNBOUND_CONF=/etc/unbound/unbound.conf.d/jaro-tunnel.conf
  {
    echo "server:"
    echo "  interface: ${SERVER_IPV4%%/*}"
    [[ -n "$SERVER_IPV6" ]] && echo "  interface: ${SERVER_IPV6%%/*}"
    echo "  access-control: ${TUNNEL_IPV4} allow"
    [[ -n "$TUNNEL_IPV6" ]] && echo "  access-control: ${TUNNEL_IPV6} allow"
    echo "  access-control: 0.0.0.0/0 refuse"
    echo "  access-control: ::/0 refuse"
    echo "  hide-identity: yes"
    echo "  hide-version: yes"
    echo "  qname-minimisation: yes"
  } > "$UNBOUND_CONF"
  chmod 0644 "$UNBOUND_CONF"
  unbound-checkconf || { echo "Configuracion de Unbound invalida" >&2; exit 2; }
  systemctl restart unbound || true
fi

# Configuracion del servidor via generador; claves por ARCHIVO (no argv).
SERVER_CONF="$(mktemp)"
chmod 0600 "$SERVER_CONF"
SERVER_ARGS=(server-conf --private-key-file "$SERVER_KEY" --address-ipv4 "$SERVER_IPV4" --listen-port "$LISTEN_PORT" --wan-interface "$WAN_IF" --peer-public-key "$PEER_PUBKEY" --peer-ipv4 "$CLIENT_IPV4")
[[ -n "$SERVER_IPV6" ]] && SERVER_ARGS+=(--address-ipv6 "$SERVER_IPV6" --peer-ipv6 "$CLIENT_IPV6")
python3 "$SCRIPT_DIR/vps_wireguard_config.py" "${SERVER_ARGS[@]}" > "$SERVER_CONF"

# Perfil del cliente: split tunnel por defecto (subred del tunel) o full tunnel
# bajo consentimiento explicito (--full-tunnel).
CLIENT_ARGS=(client-conf --private-key-file "$CONF_DIR/${CLIENT_NAME}.clientkey" --address-ipv4 "$CLIENT_IPV4" --server-public-key "$SERVER_PUB" --endpoint "${ENDPOINT_HOST}:${LISTEN_PORT}")
[[ -n "$CLIENT_IPV6" ]] && CLIENT_ARGS+=(--address-ipv6 "$CLIENT_IPV6")
if [[ "$FULL_TUNNEL" == "1" ]]; then
  CLIENT_ARGS+=(--full-tunnel)
else
  CLIENT_ARGS+=(--allowed-ips "$TUNNEL_IPV4")
  [[ -n "$TUNNEL_IPV6" ]] && CLIENT_ARGS+=(--allowed-ips "$TUNNEL_IPV6")
fi
CLIENT_ARGS+=("${DNS_VALUES[@]}")

CLIENT_CONF_OUT="$CLIENT_DIR/${CLIENT_NAME}.conf"
python3 "$SCRIPT_DIR/vps_wireguard_config.py" "${CLIENT_ARGS[@]}" > "$CLIENT_CONF_OUT"
chmod 0600 "$CLIENT_CONF_OUT"

if [[ "$DRY_RUN" != "1" ]]; then
  install -m 0600 "$SERVER_CONF" "$CONF_DIR/${WG_IF}.conf"
  if [[ "$MANAGE_FIREWALL" == "1" ]] && command -v ufw >/dev/null 2>&1; then
    ufw allow "${LISTEN_PORT}"/udp >/dev/null
    echo "UFW: regla ${LISTEN_PORT}/udp aplicada (autorizacion registrada en este comando)."
    if [[ -n "$SSH_SOURCE" ]]; then
      ufw allow from "$SSH_SOURCE" to any port 22 proto tcp >/dev/null
      echo "UFW: SSH/22 restringido a ${SSH_SOURCE}."
    else
      echo "AVISO: SSH/22 no se toco; gestionado por el proveedor (Security List de la VCN)."
    fi
  fi
  systemctl enable --now "wg-quick@${WG_IF}" >/dev/null
  WG_STATE="$(systemctl is-active "wg-quick@${WG_IF}")"
else
  mkdir -p "$PREFIX/etc"
  install -m 0600 "$SERVER_CONF" "$CONF_DIR/${WG_IF}.conf"
  if [[ "$MANAGE_FIREWALL" == "1" ]]; then
    echo "[dry-run] ufw allow ${LISTEN_PORT}/udp"
    if [[ -n "$SSH_SOURCE" ]]; then
      echo "[dry-run] ufw allow from ${SSH_SOURCE} to any port 22 proto tcp"
    else
      echo "[dry-run] SSH/22 no modificado (gestionado por el proveedor)"
    fi
  fi
  WG_STATE="dry-run"
fi
rm -f "$SERVER_CONF"

echo "== Aprovisionamiento completado =="
echo "Servidor: $SERVER_PUB (interfaz $WG_IF, puerto $LISTEN_PORT/udp)"
echo "Peer autorizado: $CLIENT_NAME ($PEER_PUBKEY)"
echo "Perfil cliente: $CLIENT_CONF_OUT (0600, NO subir al repo)"
if [[ "$FULL_TUNNEL" == "1" ]]; then
  echo "Modo cliente: FULL TUNNEL (consentimiento explicito registrado en este comando)."
else
  echo "Modo cliente: split tunnel (${TUNNEL_IPV4}${TUNNEL_IPV6:+, $TUNNEL_IPV6})."
fi
if [[ -n "$TUNNEL_IPV6" ]]; then
  echo "AVISO: se genero NAT IPv6, pero la salida IPv6 publica del VPS debe verificarse aparte."
fi
echo "Estado: $WG_STATE"
