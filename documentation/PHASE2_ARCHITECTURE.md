# JARO WPF — Documentación Técnica Fase 2 (Motores de Transporte y Túneles)

## 1. Arquitectura de Tres Planos Separados

En la Fase 2, [`core/connection/transport_manager.py`](file:///home/johanxinho/JARO-WPF/core/connection/transport_manager.py) integra [`MultiMethodManager`](file:///home/johanxinho/JARO-WPF/core/connection/multi_method_manager.py) con los nuevos motores de transporte manteniendo tres planos estrictamente separados:

| Plano | Protocolos Integrados | Qué Verifica Realmente | ¿Equivale a Túnel IP / Internet General? |
| :--- | :--- | :--- | :---: |
| **1. `dns_resolution`** | `udp_dns` (53), `tcp_dns` (53), `dot` (853), `doq` (853) | Respuesta DNS RFC 1035 / 7858 / 9250 válida (`RCODE=0`, `ANCOUNT>0`) + X.509 en DoT/DoQ. | **No** (`provides_general_internet = False`) |
| **2. `application_transport`** | `https` (TCP 443), `http3` (QUIC UDP 443), `ssh_socks5` (SOCKS5 RFC 1928) | Handshake TLS 1.2/1.3 o QUIC v1/v2 autenticado + estado HTTP/1.1 o HTTP/3 + firma de payload + relay SOCKS5 real. | **Capa de Aplicación** (HTTP/SOCKS5; requiere salida no-DNS verificada) |
| **3. `ip_tunnel`** | `wireguard` (`vpn_tunnel_engine.py`) | Existencia de interfaz + handshake criptográfico `Noise_IKpsk2` reciente (`<= 180s` y `rx_bytes > 0`) y/o tráfico real verificado. | **Capa 3 IP** (únicamente con servidor propio/autorizado) |

---

## 2. Nuevos Motores Desarrollados

1. **QUIC / HTTP/3 Engine ([`core/protocols/quic_engine.py`](file:///home/johanxinho/JARO-WPF/core/protocols/quic_engine.py))**:
   - Separado explícitamente de `doq_engine.py` (rechaza `ALPN = ["doq"]`).
   - Valida certificados X.509 (`CERT_REQUIRED`), hostname/SNI y alertas criptográficas TLS 1.3 (`0x0100..0x01FF`).
   - Ejecuta peticiones HTTP/3 reales (`H3Connection`, `ALPN = ["h3"]`) midiendo por separado `handshake_time_ms`, `response_time_ms` y `total_latency_ms`.

2. **SSH & Dynamic SOCKS5 Engine ([`core/protocols/ssh_engine.py`](file:///home/johanxinho/JARO-WPF/core/protocols/ssh_engine.py))**:
   - Reutiliza el cliente nativo OpenSSH (`ssh` en Linux Mint y `ssh.exe` en Windows 10/11) sin añadir librerías pesadas en RAM.
   - Sin credenciales predeterminadas ni servidores inventados; exige `authorized=True`, clave privada con permisos `0600`/`0400` y `StrictHostKeyChecking=yes` con `known_hosts`.
   - Verifica el protocolo **RFC 1928 SOCKS5** y tráfico HTTPS extremo a extremo a través del proxy local (`probe_https_over_socks5`), descartando puertos abiertos que no hablen SOCKS5 real.

3. **WireGuard Tunnel Engine ([`core/protocols/vpn_tunnel_engine.py`](file:///home/johanxinho/JARO-WPF/core/protocols/vpn_tunnel_engine.py))**:
   - No genera claves ni perfiles de terceros.
   - Bloquea modificaciones de rutas globales (`0.0.0.0/0`, `::/0`, `/1`) salvo que se autorice explícitamente `allow_global_routes=True`, y prohíbe directivas de ejecución de comandos (`PreUp`/`PostUp`).
   - Detecta herramientas del sistema (`wg`, `wg-quick`, `ip`, `nmcli`) y degrada limpiamente cuando `wireguard-tools` no está instalado.

---

## 3. Limitaciones Técnicas Reales

1. **Los protocolos (QUIC, DoQ, SSH, WireGuard) no otorgan internet gratuito por sí mismos:** Si una red móvil o Wi-Fi bloquea el enrutamiento IP en su pasarela de facturación (PGW/UPF o portal cautivo), ningún protocolo de transporte autorizado puede cursar tráfico hacia servidores externos no permitidos por el operador.
2. **Herramientas de espacio de usuario WireGuard en el host actual:** En Linux Mint 22.3 actual están disponibles `/usr/bin/ssh`, `/usr/sbin/ip` y `/usr/bin/nmcli`, pero `wg` y `wg-quick` (`wireguard-tools`) no están instalados actualmente (`cli_ready: False`), lo cual `WireGuardTunnelEngine` detecta y reporta sin fallos.
3. **Portabilidad a iOS (iPhone 12):** En iOS no se pueden invocar subprocesos `ssh` o `wg-quick`; la lógica de control y perfiles validados en estos módulos deberá conectarse en fases futuras con `NEPacketTunnelProvider` (`WireGuardKit` / `Network.framework` QUIC nativo de Apple).
