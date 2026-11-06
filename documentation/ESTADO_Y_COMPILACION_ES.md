# Estado de endurecimiento y compilación — JARO WPF

Fecha: 5 de noviembre de 2026  
Rama de trabajo: `fix/jaro-functional-hardening`

La auditoría específica de lifecycle iOS, `packetFlow`, WireGuardKit, SSH, DNS, App Groups y firma está en [FASE2_IOS_PACKET_TUNNEL_AUDITORIA_ES.md](FASE2_IOS_PACKET_TUNNEL_AUDITORIA_ES.md).

## Alcance

Esta rama corrige fallos de seguridad y de verificación observados durante la auditoría del repositorio. No declara conectividad remota disponible ni inventa endpoints: `configs/servers.json` debe seguir vacío hasta que el usuario registre servidores y credenciales propios. Las pruebas locales descritas abajo usan exclusivamente loopback, claves temporales y servidores efímeros.

## Cambios principales

- **Coste de red:** Python ya no considera segura una ruta solo porque exista una interfaz «gratis» si otra interfaz activa es medida. En iOS, `userMarkedMetered = false` ya no anula `NWPath.isExpensive`/`isConstrained`; al quedar bloqueada la política el Packet Tunnel limpia capacidades verificadas, detiene SOCKS/SSH/WireGuard e intenta retirar las rutas de Network Extension. Si vuelve una ruta permitida, la recuperación distingue un adapter WireGuard activo de uno detenido y no etiqueta HTTPS/handshake como verificados sin medirlos.
- **DNS y diagnóstico:** el parser comprueba encabezado, transaction ID, pregunta, registros/respuestas completos, longitudes y compresión DNS; las probes UDP/TCP/DoT/DoQ cotejan el nombre consultado. Una respuesta HTTP sin TLS no equivale a HTTPS ni a Internet verificado.
- **SOCKS5 / HTTP CONNECT:** los sockets de datos dejan de heredar el timeout corto de negociación; CONNECT reenvía bytes que lleguen junto con la cabecera, valida la autoridad y los puertos y devuelve una dirección de enlace SOCKS5 tomada del socket upstream. Los streams activos se cierran al detener el puente. Se añadió una prueba local de stream ocioso y teardown.
- **Claves y confianza SSH:** no se cambian permisos a través de symlinks. `known_hosts` también se rechaza si terceros pueden modificar el archivo o su directorio padre. Windows deja de responder «protegido» con una ACL supuesta: requiere inspección real y falla cerrado ante cuentas no permitidas o herramientas de auditoría ausentes.
- **WireGuard/Linux:** la activación requiere autorización de mutación de interfaz y, por separado, de rutas; las capturas incompletas de IPv4/IPv6 no prueban aislamiento. El laboratorio usa nombres de interfaz/namespace únicos y solo limpia recursos creados por su ejecución.
- **iOS:** el alta SSH ya no rellena una IP, usuario o fingerprint de ejemplo. SSH no se declara autenticado por tener únicamente un socket TCP abierto. La ruta IP de SSH está bloqueada mientras el Packet Tunnel no procese `packetFlow`; se conserva el proxy configurado sin instalar rutas que se descartarían.
- **CI:** se añadió un job Ubuntu reproducible para `compileall` y toda la suite `unittest`. El workflow iOS valida el `Info.plist` de la extensión en vez de repararlo silenciosamente, fija WireGuardKit `1.0.16-27`, valida `libwg-go.a` y corrige en el checkout temporal dos incompatibilidades observadas con Xcode 16.4 (PackageDescription 5.3 y el header BSD). No se commitea ni se altera el repositorio upstream. Los IPA generados siguen siendo **sin firma**.

## Pruebas realizadas en este entorno

Con Python 3.12 y las dependencias declaradas en `requirements-dev.txt`:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m compileall -q core tests
python3 -m unittest discover -s tests -v
```

Resultado al cerrar la primera auditoría: **73 pruebas aprobadas**; en la segunda fase se añadieron contratos iOS y el total actual es **74 pruebas Python aprobadas**. Incluyen QUIC/DoQ, DNS, coste/failover, seguridad, perfiles, Windows por contratos, SSH/OpenSSH loopback real, SOCKS5, HTTP CONNECT y HTTPS local. `git diff --check` también pasó. Los escenarios que usan fallos inyectados son explícitamente simulados; no cuentan como prueba de conectividad remota.

En GitHub Actions, el commit `af03caf` pasó los tests Python y ambos jobs iOS en macOS/Xcode 16.4: `swift test`, generación de `libwg-go.a`, build Full, validación del PacketTunnel embebido, build Standalone y carga de ambos IPA. [Ver ejecución y artefactos del workflow](https://github.com/johanxinho/JARO-WPF/actions/runs/42135602853). Esta validación es de compilación/empaquetado, no de firma ni ejecución en un iPhone.

La segunda fase, commit `1f327bd`, volvió a pasar `swift test` y compiló/subió Full (WireGuardKit + PacketTunnel embebido) y Standalone sin extensión; la suite Python también pasó. [Ver build iOS](https://github.com/johanxinho/JARO-WPF/actions/runs/42139469499) y [Python CI](https://github.com/johanxinho/JARO-WPF/actions/runs/42139469581). Los IPA no están firmados y no se instalaron ni probaron en iPhone.

## Límites no verificables aquí

- El entorno de trabajo es Linux y no tiene `swift` ni `xcodebuild`; por ello **no se compiló ni firmó un binario iOS aquí**, no se ejecutaron las XCTest/Swift Package tests y no se probó en un iPhone físico.
- iOS requiere macOS/Xcode y una app/extensión firmadas. Para Packet Tunnel hacen falta App ID(s) correctos, grupo de aplicación compartido, entitlement de Network Extension `packet-tunnel-provider` y perfiles de aprovisionamiento compatibles con ambos targets. Una cuenta Apple Personal/Free no habilita necesariamente Network Extension para distribución/instalación; la disponibilidad depende del entitlement y del equipo Apple Developer.
- El workflow produce `.ipa` **unsigned** y no puede instalarse directamente en un iPhone. Para instalar, hay que firmar/exportar con certificado y provisioning profiles autorizados (localmente en Xcode o incorporados como secretos protegidos del CI). La variante Standalone omite PacketTunnel y no ofrece VPN de sistema.
- WireGuardKit es condicional. GitHub Actions sí compiló y enlazó `libwg-go.a` arm64 y empaquetó la app con su extensión. En este entorno Linux no se dispone de Xcode; tampoco se observó un handshake WireGuard real porque no se configuró ningún peer.
- No se configuró ni se probó un servidor SSH o WireGuard remoto del usuario. Sin host, puerto, huella pública, clave privada y autorización válidos no se puede afirmar que una VPN esté operativa. El estado correcto del catálogo vacío es `REMOTE_SERVER_REQUIRED`.
- Windows se conserva y la protección ACL ahora falla cerrado, pero la auditoría nativa `icacls` necesita validarse en una máquina Windows real.

## Compilación / instalación

### Python y Linux

Instalar dependencias de pruebas y ejecutar suite:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m compileall -q core tests
python3 -m unittest discover -s tests -v
```

WireGuard en Linux solo puede activarse contra perfiles autorizados, con `wireguard-tools`/interfaz disponibles y el consentimiento explícito que requiere la política local. El motor no eleva privilegios automáticamente.

### iOS mediante GitHub Actions

1. En la rama publicada, abrir **Actions → Build JARO WPF iOS artifacts (unsigned)** y ejecutar ambos jobs.
2. Descargar `JaroWPF-Full-unsigned-ipa` para la variante con PacketTunnel y `JaroWPF-Standalone-unsigned-ipa` para la variante sin extensión VPN.
3. Los artefactos de Actions duran 14 días. Son insumos sin firma, no instaladores listos para sideload. Los archivos descargados y verificados de esta ejecución tienen estos SHA-256:
   - Full: `189791000cc61d117f318d8d0c614c13761d965dc658e80c75b62170ca0e475f`
   - Standalone: `74b3626fc7421bbe3ffbd7fd339b3762c552c0a546a9321a126a61f42cb6999c`
4. Para instalar en un dispositivo, configurar Team/Bundle IDs, capability Network Extension, App Group y provisioning profiles de app/extensión en Xcode, firmar y exportar con una identidad Apple válida; después instalar desde Xcode o distribuir mediante un canal autorizado.
5. Solo afirmar funcionamiento VPN tras instalar en un iPhone compatible, añadir un perfil con servidor propio, observar handshake/tráfico real y verificar salida HTTPS por el túnel.

`requirements-dev.txt` y el workflow Python fijan las dependencias de CI. El paquete Swift y `ios/project.yml` son la fuente de proyecto iOS; el workflow macOS valida sus artefactos cuando se ejecuta en GitHub.
