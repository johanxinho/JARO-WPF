# JARO WPF
### Developed by JARO COMPLEMETS

Version: 1.0.0
Development OS: Linux Mint 22.3
Architecture: x86_64
Target device: iPhone 12
Target carrier: Tigo Colombia
Budget: 0 COP

## Main objective
Develop an original iOS connectivity application
with support for authorized free-access networks.

## Core modules
- UDP Engine
- DNS Engine
- DoQ Research
- Server Selector
- Connection Analyzer
- Tunnel Engine
- iOS VPN Client

## Development principles
- Free and open-source technologies
- Original source code
- Secure connections
- No unauthorized billing circumvention

## Estado de validación
- Los perfiles remotos deben configurarse con servidores propios/autorizados; el repositorio no incluye servidores ni credenciales de ejemplo.
- La suite Python se ejecuta con `python3 -m pip install -r requirements-dev.txt` y `python3 -m unittest discover -s tests -v`.
- Las limitaciones de iOS, firma de Packet Tunnel, artefactos sin firmar y estado de verificación se documentan en [ESTADO_Y_COMPILACION_ES.md](documentation/ESTADO_Y_COMPILACION_ES.md).
- La segunda fase audita el ciclo de `NEPacketTunnelProvider`, WireGuardKit, SSH/SOCKS5, DNS, rutas, App Groups y la vía legítima de firma en [FASE2_IOS_PACKET_TUNNEL_AUDITORIA_ES.md](documentation/FASE2_IOS_PACKET_TUNNEL_AUDITORIA_ES.md).
- La tercera fase cubre round-trip DNS, consentimiento de full tunnel, diagnósticos por peer y el laboratorio Linux en [FASE3_DNS_WIREGUARD_LAB_IOS_ES.md](documentation/FASE3_DNS_WIREGUARD_LAB_IOS_ES.md); handshake, firma e instalación física siguen sin probarse hasta usar un servidor propio, un team autorizado y un iPhone.
