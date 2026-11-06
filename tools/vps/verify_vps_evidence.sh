#!/usr/bin/env bash
# Recoleccion de evidencia real en el VPS (fase 4). Requiere root.
# NO simula nada: cada chequeo depende de un peer real conectado.
#
# Uso:
#   sudo bash verify_vps_evidence.sh --wg-if wg0 \
#     --peer-public-key <b64> \
#     --client-tunnel-ip 10.66.66.2 \
#     --https-url https://midominio.com/health \
#     --dns-server 10.66.66.1 --dns-name midominio.com
#
# --https-url y --dns-name deben apuntar a servicios del USUARIO. No se usan
# servicios publicos por defecto (fase 3: sin URLs de sonda por defecto).

set -euo pipefail

WG_IF="wg0"
PEER_PUB=""
CLIENT_IP=""
HTTPS_URL=""
DNS_SERVER=""
DNS_NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wg-if) WG_IF="$2"; shift 2 ;;
    --peer-public-key) PEER_PUB="$2"; shift 2 ;;
    --client-tunnel-ip) CLIENT_IP="$2"; shift 2 ;;
    --https-url) HTTPS_URL="$2"; shift 2 ;;
    --dns-server) DNS_SERVER="$2"; shift 2 ;;
    --dns-name) DNS_NAME="$2"; shift 2 ;;
    *) echo "Arg desconocido: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Ejecutar como root (sudo)." >&2; exit 2; }
command -v wg >/dev/null 2>&1 || { echo "wireguard-tools no instalado" >&2; exit 2; }

fail=0
check() { # check <nombre> <cmd...>
  local name="$1"; shift
  if "$@"; then echo "OK    $name"; else echo "FALLO $name"; fail=1; fi
}

echo "== Evidencia en $(hostname) $(date -u +%FT%TZ) =="

if systemctl is-active --quiet "wg-quick@${WG_IF}"; then echo "OK    wg-quick@${WG_IF} activo"; else echo "FALLO wg-quick@${WG_IF} no activo"; fail=1; fi

# Handshake y contadores del peer concreto (no de cualquier peer).
if [[ -n "$PEER_PUB" ]]; then
  HS_LINE="$(wg show "$WG_IF" latest-handshakes | grep -F "$PEER_PUB" || true)"
  if [[ -n "$HS_LINE" ]]; then
    HS_TS="$(awk '{print $2}' <<<"$HS_LINE")"
    AGE=$(( $(date +%s) - HS_TS ))
    if (( AGE >= 0 && AGE <= 180 )); then echo "OK    handshake reciente (${AGE}s)"; else echo "FALLO handshake viejo o ausente (${AGE}s)"; fail=1; fi
  else
    echo "FALLO peer $PEER_PUB sin entrada de handshake"; fail=1
  fi
  TR_LINE="$(wg show "$WG_IF" transfer | grep -F "$PEER_PUB" || true)"
  if [[ -n "$TR_LINE" ]]; then
    RX="$(awk '{print $2}' <<<"$TR_LINE")"; TX="$(awk '{print $3}' <<<"$TR_LINE")"
    echo "INFO  transfer peer: RX=${RX}B TX=${TX}B (verificar incremento con 2 ejecuciones)"
  else
    echo "FALLO peer sin contadores de transferencia"; fail=1
  fi
else
  echo "AVISO sin --peer-public-key: no se filtra por peer (evidencia mas debil)"; fail=1
fi

[[ -n "$CLIENT_IP" ]] && check "ping IPv4 por el tunel" ping -c 3 -W 3 -I "$WG_IF" "$CLIENT_IP"

if [[ -n "$DNS_SERVER" && -n "$DNS_NAME" ]]; then
  if dig +time=5 +tries=1 "@${DNS_SERVER}" "$DNS_NAME" +short | grep -qE '.'; then
    echo "OK    resolucion DNS via tunel (${DNS_SERVER})"
  else
    echo "FALLO resolucion DNS via tunel (${DNS_SERVER})"; fail=1
  fi
fi

if [[ -n "$HTTPS_URL" ]]; then
  # Egress real a traves del tunel: la IP de origen visible debe ser la del VPS.
  check "HTTPS egress via tunel" curl -4 -sS --max-time 15 --interface "$WG_IF" -o /dev/null -w '%{http_code}\n' "$HTTPS_URL" | grep -q '^2'
fi

if sysctl -n net.ipv4.ip_forward | grep -q '^1$'; then echo "OK    ip_forward activo"; else echo "FALLO ip_forward"; fail=1; fi

exit $fail
