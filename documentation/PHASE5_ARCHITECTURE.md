# JARO WPF — Arquitectura de la Fase 5: Authorized Tunnel Infrastructure

## 1. Resumen Arquitectónico

La **Fase 5** completa la infraestructura criptográfica, de seguridad, registro de servidores y validación real en loopback para túneles **SSH/SOCKS5 (`direct-tcpip`)** y **WireGuard (`Noise_IKpsk2` + `ChaCha20-Poly1305`)**, preservando el 100 % de compatibilidad con los módulos de las Fases 1 a 4 (`58/58` pruebas automatizadas aprobadas) y manteniendo un consumo de memoria ligero (`VmHWM ~ 43.9 MB` en equipo con `~3.3 GB RAM`).

---

## 2. Nuevos Módulos y Módulos Auditados

| Módulo | Ruta | Responsabilidad Principal |
| :--- | :--- | :--- |
| `secret_guard` | [`core/security/secret_guard.py`](../core/security/secret_guard.py) | Redacción automática de secretos (`redact_secrets`), auditoría y protección `0o600` (`protect_sensitive_file`, `audit_sensitive_file`), bloqueo de claves/contraseñas en texto plano en JSON (`audit_json_no_plaintext_secrets`), validación de cabeceras de `IdentityFile`, fijado criptográfico de `known_hosts` (texto plano y `|1|salt|hash` HMAC-SHA1) y compuerta `PrivilegePolicyGate` (cero `sudo` automático). |
| `ServerManager` | [`core/connection/server_manager.py`](../core/connection/server_manager.py) | Registro tipado (`ServerRecord`) con los 9 campos obligatorios (`server_id`, `address`, `protocol`, `status`, `latency_ms`, `last_checked_utc`, `authorized`, `requirements`, `verified_capabilities`) y estado explícito `REMOTE_SERVER_REQUIRED` cuando no existen servidores remotos configurados. |
| `SshSocksTunnel` | [`core/protocols/ssh_engine.py`](../core/protocols/ssh_engine.py) | Prevención de colisiones de puerto local antes de lanzar `ssh -D`, clasificación determinista de errores SSH (`classify_ssh_error`), `GlobalKnownHostsFile=/dev/null`, `UpdateHostKeys=no`, cierre limpio de grupo de procesos (`os.killpg`) y separación estricta entre `local_socks5_functional`, `local_ssh_tunnel_functional` y `remote_ssh_tunnel_functional`. |
| `WireGuardTunnelEngine` | [`core/protocols/vpn_tunnel_engine.py`](../core/protocols/vpn_tunnel_engine.py) | Detección de binarios y módulo del kernel (`wireguard.ko.zst`), eliminación de `sudo -n` automático, bloqueo de rutas globales (`0.0.0.0/0`, `::/0`, `/1`) y overrides DNS no autorizados, auditoría de aislamiento de tabla de rutas (`inspect_routing_table`, `verify_route_isolation`), delta bidireccional `RX`/`TX` en vivo y recuperación `recover()`. |
| `LocalTunnelLabs` | [`core/network_tests/local_tunnel_labs.py`](../core/network_tests/local_tunnel_labs.py) | `LocalOpenSshLoopbackLab` (`/usr/sbin/sshd` real sin privilegios en `127.0.0.1` con `StrictModes yes`) y `LocalWireGuardLoopbackLab` (`wg_jaro0` `10.199.77.1/30` $\leftrightarrow$ `wg_jaro1` `10.199.77.2/30` en `jaro_wg_ns` sin tocar la ruta predeterminada y con limpieza garantizada). |
| `ios_tunnel_contract` | [`core/connection/ios_tunnel_contract.py`](../core/connection/ios_tunnel_contract.py) y [`ios/`](../ios/README_IOS_ARCHITECTURE.md) | Contratos sin secretos (`keychain://`) y esqueleto Swift `NEPacketTunnelProvider` (`device_verified = False`, `UNVERIFIED_ON_PHYSICAL_IPHONE`, techo de `15 MB` RAM y rutas aisladas por defecto). |
| Investigación Tigo | [`documentation/TIGO_COLOMBIA_OFFICIAL_RESEARCH.md`](./TIGO_COLOMBIA_OFFICIAL_RESEARCH.md) | Documentación técnica y regulatoria (CRC Colombia / 3GPP PGW-UPF) de canales oficiales de autogestión sin saldo (`Mi Tigo App`, portal cautivo de compras, `*300#`, `*10#`, `*611`) sin métodos de evasión. |

---

## 3. Cómo Registrar Posteriormente un Servidor Remoto Propio o Autorizado

Cuando dispongas de un servidor propio o autorizado, puedes registrarlo sin almacenar secretos en JSON mediante [`ServerManager`](../core/connection/server_manager.py):

```python
from core.connection.server_manager import ServerManager

mgr = ServerManager()

# Ejemplo 1: Registrar servidor SSH propio autorizado (clave privada 0o600 en disco)
mgr.register_ssh_server(
    server_id="mi-vps-ssh-01",
    host="203.0.113.25",
    port=22,
    username="mi_usuario",
    identity_file="/home/johanxinho/.ssh/id_ed25519_jaro",
    known_hosts_file="/home/johanxinho/.ssh/jaro_known_hosts",
    local_socks_port=1080,
    authorized=True,
    persist=True,
)

# Ejemplo 2: Registrar perfil WireGuard propio autorizado (archivo .conf 0o600 con AllowedIPs aisladas)
mgr.register_wireguard_server(
    server_id="mi-vps-wg-01",
    endpoint_host="203.0.113.25",
    endpoint_port=51820,
    interface_name="wg0",
    config_path="/home/johanxinho/.config/jaro/wg0.conf",
    authorized=True,
    persist=True,
)
```

Mientras `configs/servers.json` mantenga `authorized_ssh_tunnels: []` y `authorized_wireguard_tunnels: []`, el sistema informa siempre **`REMOTE_SERVER_REQUIRED`** (jamás `SUCCESS`).
