#!/usr/bin/env bash
# Aprovisionamiento WireGuard para el VPS de JARO WPF (fase 4).
# Ubuntu 22.04/24.04 o Debian 12. Requiere root. Idempotente: puede re-ejecutarse.
#
# NO contiene claves: las genera en el VPS con `wg genkey`. El .conf del cliente
# se imprime SOLO por stdout y se guarda con permisos 0600 en /root/jaro-wireguard/
# del VPS; nunca debe copiarse a este repositorio, CI ni documentacion.
#
# Uso (ejemplo):
#   sudo bash provision_wireguard_server.sh \
#     --endpoint-host vps.ejemplo.dominio \
#     --tunnel-ipv4 10.66.66.0/24 --tunnel-ipv6 fd00:6:6::/64 \
#     --client-name iphone12 --dns 10.66.66.1 --dns fd00:6:6::1 \
#     --manage-firewall
#
# --manage-firewall SOLO con autorizacion explicita del usuario: abre UDP/51820
# y conserva SSH (22) en UFW. Nota: en Oracle Cloud ademas hay que crear la
# regla equivalente en la Security List / NSG de la VCN desde la consola web.

set -euo pipefail

WG_IF="wg0"
LISTEN_PORT="51820"
TUNNEL_IPV4=""
TUNNEL_IPV6=""
ENDPOINT_HOST=""
CLIENT_NAME="cliente1"
MANAGE_FIREWALL="0"
DNS_ARGS=()
SERVER_IPV4=""
SERVER_IPV6=""
CLIENT_IPV4=""
CLIENT_IPV6=""

usage() { sed -n '2,20p' "$0"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint-host) ENDPOINT_HOST="$2"; shift 2 ;;
    --tunnel-ipv4) TUNNEL_IPV4="$2"; shift 2 ;;
    --tunnel-ipv6) TUNNEL_IPV6="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --client-name) CLIENT_NAME="$2"; shift 2 ;;
    --dns) DNS_ARGS+=(--dns "$2"); shift 2 ;;
    --manage-firewall) MANAGE_FIREWALL="1"; shift ;;
    --wg-if) WG_IF="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Argumento desconocido: $1" >&2; usage ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Ejecutar como root (sudo)." >&2; exit 2; }
[[ -n "$ENDPOINT_HOST" && -n "$TUNNEL_IPV4" ]] || usage

if ! command -v wg >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq wireguard qrencode
fi

# Direccion del servidor: primera IP utilizable de la subred.
SERVER_IPV4="$(python3 - "$TUNNEL_IPV4" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = list(net.hosts())
print(f"{hosts[0]}/{net.prefixlen}" if hosts else f"{net.network_address}/{net.prefixlen}")
PY
)"
CLIENT_IPV4="$(python3 - "$TUNNEL_IPV4" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = list(net.hosts())
print(f"{hosts[1]}/32" if len(hosts) > 1 else "")
PY
)"
if [[ -n "$TUNNEL_IPV6" ]]; then
  SERVER_IPV6="$(python3 - "$TUNNEL_IPV6" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = list(net.hosts())
print(f"{hosts[0]}/{net.prefixlen}" if hosts else f"{net.network_address}/{net.prefixlen}")
PY
)"
  CLIENT_IPV6="$(python3 - "$TUNNEL_IPV6" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = list(net.hosts())
print(f"{hosts[1]}/128" if len(hosts) > 1 else "")
PY
)"
fi
[[ -n "$CLIENT_IPV4" ]] || { echo "No se pudo derivar IP de cliente desde $TUNNEL_IPV4" >&2; exit 2; }

# Reenvio IP (necesario para NAT).
cat > /etc/sysctl.d/70-jaro-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl --system >/dev/null

# NAT por interfaz WAN detectada (PostUp/PostDown los escribe wg-quick).
WAN_IF="$(ip -4 route show default | awk '{print $5; exit}')"
[[ -n "$WAN_IF" ]] || { echo "No hay ruta default; no se detecta interfaz WAN." >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_CONF="$(mktemp)"
SERVER_KEY="/etc/wireguard/${WG_IF}.key"
PEER_PUB="/etc/wireguard/${CLIENT_NAME}.clientpub"

# Reutiliza claves si ya existen (idempotencia).
if [[ ! -s "$SERVER_KEY" ]]; then
  umask 077
  wg genkey > "$SERVER_KEY"
fi
SERVER_PRIV="$(cat "$SERVER_KEY")"
SERVER_PUB="$(printf '%s' "$SERVER_PRIV" | wg pubkey)"
if [[ ! -s "$PEER_PUB" ]]; then
  umask 077
  CLIENT_PRIV="$(wg genkey)"
  printf '%s' "$CLIENT_PRIV" | wg pubkey > "$PEER_PUB"
  printf '%s' "$CLIENT_PRIV" > "/etc/wireguard/${CLIENT_NAME}.clientkey"
  unset CLIENT_PRIV
fi
PEER_PUBKEY="$(cat "$PEER_PUB")"

python3 "$SCRIPT_DIR/vps_wireguard_config.py" server-conf \
  --private-key "$SERVER_PRIV" \
  --address-ipv4 "$SERVER_IPV4" \
  $( [[ -n "$SERVER_IPV6" ]] && printf -- '--address-ipv6 %s' "$SERVER_IPV6" ) \
  --listen-port "$LISTEN_PORT" \
  --wan-interface "$WAN_IF" \
  --peer-public-key "$PEER_PUBKEY" \
  --peer-ipv4 "$CLIENT_IPV4" \
  $( [[ -n "$CLIENT_IPV6" ]] && printf -- '--peer-ipv6 %s' "$CLIENT_IPV6" ) \
  > "$SERVER_CONF"

install -m 0600 "$SERVER_CONF" "/etc/wireguard/${WG_IF}.conf"
rm -f "$SERVER_CONF"

if [[ "$MANAGE_FIREWALL" == "1" ]] && command -v ufw >/dev/null 2>&1; then
  ufw allow 22/tcp >/dev/null
  ufw allow "${LISTEN_PORT}"/udp >/dev/null
  echo "UFW: reglas 22/tcp y ${LISTEN_PORT}/udp aplicadas (autorizacion registrada en este comando)."
fi

systemctl enable --now "wg-quick@${WG_IF}" >/dev/null

# Perfil del cliente: SOLO archivo protegido en el VPS (nunca en el repo).
python3 "$SCRIPT_DIR/vps_wireguard_config.py" client-conf \
  --private-key "$(cat "/etc/wireguard/${CLIENT_NAME}.clientkey")" \
  --address-ipv4 "$CLIENT_IPV4" \
  $( [[ -n "$CLIENT_IPV6" ]] && printf -- '--address-ipv6 %s' "$CLIENT_IPV6" ) \
  --server-public-key "$SERVER_PUB" \
  --endpoint "${ENDPOINT_HOST}:${LISTEN_PORT}" \
  "${DNS_ARGS[@]}" \
  > "/root/jaro-wireguard/${CLIENT_NAME}.conf"
python3 "$SCRIPT_DIR/vps_wireguard_config.py" client-conf \
  --private-key "$(cat "/etc/wireguard/${CLIENT_NAME}.clientkey")" \
  --address-ipv4 "$CLIENT_IPV4" \
  $( [[ -n "$CLIENT_IPV6" ]] && printf -- '--address-ipv6 %s' "$CLIENT_IPV6" ) \
  --server-public-key "$SERVER_PUB" \
  --endpoint "${ENDPOINT_HOST}:${LISTEN_PORT}" \
  "${DNS_ARGS[@]}" \
  > "/root/jaro-wireguard/${CLIENT_NAME}.conf"
chmod 0600 "/root/jaro-wireguard/${CLIENT_NAME}.conf"

echo "== Aprovisionamiento completado =="
echo "Servidor: $SERVER_PUB  (interfaz $WG_IF, puerto $LISTEN_PORT/udp)"
echo "Peer autorizado: $CLIENT_NAME ($PEER_PUBKEY)"
echo "Perfil cliente: /root/jaro-wireguard/${CLIENT_NAME}.conf (0600, NO subir al repo)"
echo "Recuerda: en Oracle Cloud crea la regla UDP/${LISTEN_PORT} en la Security List de la VCN."
echo "Estado: $(systemctl is-active "wg-quick@${WG_IF}")"
