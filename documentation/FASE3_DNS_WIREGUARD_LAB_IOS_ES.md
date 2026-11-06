# Fase 3 — DNS, WireGuard real y preparación para iPhone

**Rama:** `fix/jaro-functional-hardening`  
**Base de trabajo solicitada:** `7cd7d61`  
**Estado de verificación:** la compilación física, firma Apple e instalación en un iPhone 12 aún requieren cuenta/perfiles autorizados y un Mac/Xcode. Esta rama no contiene claves, perfiles de firma ni servidores del usuario.

## Matriz funcional

| Función | Implementación actual | Qué falta | Qué puede probarse sin Mac | Qué requiere firma o iPhone físico |
|---|---|---|---|---|
| Ciclo de `NEPacketTunnelProvider` | La extensión carga un perfil, inicia el transporte, aplica `NEPacketTunnelNetworkSettings`, monitorea ruta/coste, procesa mensajes IPC y al detener intenta parar motores y retirar settings. | No se ha comprobado la secuencia en iOS real, ni el comportamiento ante suspensión, jetsam, cambio Wi-Fi/celular o terminación forzada. | Auditoría estática, XCTest del paquete en macOS CI, validación de rutas/perfiles Python. | Firma de Full y pruebas en iPhone para lifecycle, permisos VPN, cambios de red y cierre real. |
| `packetFlow` | JARO **no** lee ni reinyecta paquetes manualmente. Para WireGuard, el `WireGuardAdapter` oficial se construye con el `NEPacketTunnelProvider`; su puente `libwg-go`/utun implementa el plano de paquetes. No hay un procesador `packetFlow.readPackets`/`writePackets` propio. | Falta observar en dispositivo paquetes reales y contadores del servidor durante tráfico de usuario. SSH no usa este plano IP. | Verificar dependencias, código, parser UAPI y empaquetado de la extensión en Actions. | Un perfil y servidor propios, firma Full, iPhone conectado y captura/contadores correlacionados. |
| WireGuardKit | El build Full enlaza WireGuardKit y `libwg-go`; el motor configura claves, endpoint, AllowedIPs, direcciones, MTU y DNS en `TunnelConfiguration`, y arranca/paraliza `WireGuardAdapter` con el lifecycle del provider. El estado se separa entre adapter iniciado, handshake y HTTPS. | El éxito de compilación no demuestra enlace UDP, handshake ni tráfico real. Falta probar el peer del usuario. | XCTest de parser UAPI por peer, validación de perfil, CI macOS y laboratorio de servidor propio. | Certificados/entitlements Full y un iPhone conectado a un endpoint WireGuard controlado por el usuario. |
| SSH/SOCKS5 | SSH proporciona una sesión autenticada y proxy TCP SOCKS5/HTTP CONNECT. El provider rechaza instalar rutas IP en modo SSH; no se anuncia como VPN IP. | No hay encapsulación o forwarding de paquetes IP por SSH y no se pretende implementar aquí. | Pruebas Python con OpenSSH/loopback y auditoría del guard de rutas. | La variante Standalone puede requerir firma de desarrollo para instalar el proxy; no necesita Packet Tunnel, pero sigue requiriendo iOS/Xcode para instalación normal. |
| DNS WireGuard | `DNS=` se valida como una lista de IPs IPv4/IPv6, se conserva en importación, Keychain/perfil portable y se asigna a `InterfaceConfiguration.dns` de WireGuardKit. La sustitución del DNS de iOS requiere consentimiento explícito. | La prueba usa el resolver del sistema y solo aporta evidencia de respuesta y deltas del peer; no es una captura DNS completa ni demuestra ausencia absoluta de fugas/caché. | Round-trip Python, XCTest de IPv4/IPv6/múltiples DNS y auditoría del mapeo al SDK. | Resolver real accesible por rutas del túnel, permisos Full y prueba desde iPhone. |
| `AllowedIPs` y full tunnel | Se aceptan rutas split válidas. Full tunnel requiere consentimiento explícito, el par canónico `0.0.0.0/0` + `::/0`, direcciones IPv4 e IPv6 y DNS válido autorizado. El consentimiento persistido habilita `NETunnelProviderProtocol.includeAllNetworks`. | iOS conserva excepciones de tráfico de sistema, control de red, portal cautivo, algunos servicios celulares y dispositivos complementarios. El servidor debe enrutar IPv4/IPv6 y servir DNS; el código no puede garantizar todos esos servicios fuera del túnel. | Casos de rutas incompletas, `/1`, DNS/MTU inválidos y consentimiento ausente. | Probar rutas reales, fallback, cambios de red y tráfico excluido en dispositivo. `includeAllNetworks` está disponible desde iOS 14; el deployment mínimo aquí es iOS 16. |
| MTU / IPv4 / IPv6 | Se validan MTU en rango admitido por el perfil (1280–1500), CIDRs y familias. Ambas familias se traducen a WireGuardKit; Full exige address y ruta por defecto de ambas. | El MTU óptimo depende de la red y encapsulación; no se ha medido en Wi-Fi/celular del usuario. | XCTest/Python con CIDRs IPv4/IPv6, MTU límite y configuración incompleta. | Pruebas con redes reales, PMTU, fragmentación y roaming. |
| Reconexión y teardown | `NWPathMonitor`, policy de coste, recuperación, handshake fresco y stop del adapter están conectados en el código. El provider suspende/paraliza y limpia capabilities/settings según política. | Los callbacks/races y la restauración tras suspensión o caída de proceso no están validados físicamente. | Auditoría de estado, pruebas de lógica de rutas/backoff y build. | Roaming Wi-Fi↔celular, modo avión, bloqueo/desbloqueo, suspensión, reconexión y verificación de tráfico en iPhone. |
| IPC App ↔ extensión | Configuración por `NETunnelProviderProtocol.providerConfiguration`, comandos de `sendProviderMessage`, perfiles/secretos separados y App Group común. | La firma debe autorizar el mismo App Group para host y extensión; no se ha comprobado el intercambio Keychain firmado en dispositivo. | Tests de esquema/serialización, entitlements plist y build de ambas variantes. | Provisioning válido para cada bundle y ensayo de guardado/carga del secreto por ambos procesos. |
| Diagnóstico de handshake/RX/TX | `getRuntimeConfiguration` de WireGuardKit se parsea por `public_key` del peer configurado. Un handshake fresco y deltas RX/TX se requieren para los estados verificados; contadores históricos por sí solos no bastan. | El origen solo puede considerarse realmente probado frente al servidor del usuario. Un tráfico concurrente puede coincidir temporalmente con un cambio de contador. | XCTest con UAPI sintético y peer correcto/incorrecto; no crea un handshake. | Correlacionar hora, RX/TX y `wg show` del servidor durante tráfico generado desde iPhone. |
| Diagnóstico DNS/HTTPS | DNS consulta `getaddrinfo` del sistema tras aplicar los ajustes y coteja DNS/ruta del perfil; para verificación de WireGuard exige handshake y deltas bidireccionales. HTTPS requiere URL aportada por el usuario, TLS válido, IP literal cubierta por AllowedIPs y deltas de peer. | Una respuesta DNS no prueba que ningún paquete haya escapado por otra ruta. HTTPS necesita un servidor propio con certificado válido para la IP literal usada; una URL hostname se rechaza deliberadamente para evitar una ruta no comprobada. | Tests del parser/validación y diagnósticos locales Python donde aplique; no simula DNS iOS ni HTTPS del túnel. | Servicio DNS/HTTPS controlado por el usuario, certificado confiable que coincida con IP y tráfico real desde iPhone. |
| Firma Full | Entitlements del host y extensión declaran `packet-tunnel-provider` y el App Group `group.com.jarocomplements.jarowpf`; IDs son `com.jarocomplements.jarowpf` y `com.jarocomplements.jarowpf.PacketTunnel`. | Falta equipo Apple con entitlement aprobado, App IDs/capabilities, certificados y perfiles de desarrollo que cubran ambos targets y UDID del iPhone. Los IPA de CI siguen sin firma. | Revisar plist/yaml, compilar y empacar Full en GitHub Actions. | Mac/Xcode o entorno macOS equivalente autorizado, cuenta/team con Network Extensions, dos perfiles válidos y un iPhone registrado. |

## Cambios implementados en esta fase

- El importador Python y Swift conservan `DNS=` en formato `.conf` y `.jaroprofile`; aceptan servidores DNS IPv4/IPv6 múltiples y rechazan literales inválidos.
- WireGuardKit recibe explícitamente `dns`, todas las direcciones y MTU del perfil. Perfiles viejos sin listas adicionales siguen usando su `tunnel_address_cidr`.
- El usuario debe habilitar por separado la sustitución DNS y el full tunnel al importar. Full tunnel requiere `0.0.0.0/0` y `::/0`, direcciones IPv4 e IPv6, DNS autorizado, consentimiento guardado y la política `includeAllNetworks` de iOS. Se rechazan rutas globales parciales tipo `/1`.
- El importador rechaza secciones/pares ambiguos y datos inválidos antes de escribir secretos. Las claves privadas y PSK no se serializan al perfil portable.
- Se agregaron pruebas Python y XCTest para round-trip, IPv4/IPv6, varios DNS, falta de consentimiento, perfil incompleto, MTU y direcciones/rutas inválidas, UAPI filtrada por peer y validación de nombres DNS.
- SSH continúa siendo un proxy TCP. Se añadió una regresión estática para impedir que obtenga rutas IP o se describa como Packet Tunnel.
- Se quitó el destino HTTPS público por defecto; el usuario suministra el URL. Las pruebas iOS no contactan servidores externos ni simulan una conexión.

## Laboratorio WireGuard propio en Linux

Los rangos siguientes (`10.77.0.0/24` y `fd77::/64`) son **direcciones privadas de ejemplo para que el usuario las asigne a su laboratorio**, no servidores JARO ni endpoints públicos. Sustitúyalos si se superponen con sus redes. Este documento no incluye claves ni credenciales.

### 1. Preparar herramientas y claves fuera del repositorio

En un Linux controlado por usted (Debian/Ubuntu, por ejemplo), instale `wireguard-tools` según la distribución. Genere claves en un directorio privado que no sea un checkout Git ni una carpeta sincronizada:

```bash
umask 077
mkdir -m 700 "$HOME/jaro-wg-private"
cd "$HOME/jaro-wg-private"
wg genkey > server.key
wg pubkey < server.key > server.pub
wg genkey > iphone.key
wg pubkey < iphone.key > iphone.pub
chmod 600 server.key iphone.key
```

No pegue las claves privadas en Issues, logs, GitHub Actions ni este repositorio. La clave privada del iPhone se importa en la app y queda separada en Keychain. Transfiera el archivo de cliente únicamente por un canal privado que controle; elimine copias temporales y copias de seguridad no deseadas después de importar. Las claves públicas sí se intercambian con el peer correspondiente.

### 2. Crear la configuración del servidor

Prepare `/etc/wireguard/wg0.conf` como root, con permisos `0600`. Sustituya cada texto `<...>` con el valor generado/configurado por usted; el bloque no es ejecutable hasta hacerlo. No suba el archivo a Git.

```ini
[Interface]
Address = 10.77.0.1/24, fd77::1/64
ListenPort = <UDP_PORT_ELEGIDO>
PrivateKey = <CONTENIDO_LOCAL_DE_server.key>

[Peer]
PublicKey = <CONTENIDO_LOCAL_DE_iphone.pub>
AllowedIPs = 10.77.0.2/32, fd77::2/128
```

El firewall del servidor y, si corresponde, el firewall/NAT de su proveedor deben permitir el puerto UDP elegido. Si el servidor está detrás de NAT, configure el reenvío UDP en su propio router. No abra puertos ni cambie reglas de firewall de un sistema que no administra. `AllowedIPs` del servidor asigna al iPhone solo las dos direcciones del peer.

Active `wg0` con `wg-quick` según la política de su host; después compruebe `sudo wg show wg0`. Si no hay `latest handshake`, el túnel todavía no está conectado, aunque el archivo esté bien formado. Un handshake exige que el UDP pueda llegar al endpoint y que la clave pública remota coincida.

### 3. Configuración privada de cliente para importar en JARO

Genere localmente el perfil de cliente, sin copiarlo al repositorio. Sustituya `<...>` por la clave privada y pública de su propio laboratorio, y por la IP o nombre de su endpoint autorizado:

```ini
[Interface]
PrivateKey = <CONTENIDO_LOCAL_DE_iphone.key>
Address = 10.77.0.2/24, fd77::2/64
MTU = 1420

[Peer]
PublicKey = <CONTENIDO_LOCAL_DE_server.pub>
Endpoint = <ENDPOINT_PROPIO>:<UDP_PORT_ELEGIDO>
AllowedIPs = 10.77.0.0/24, fd77::/64
PersistentKeepalive = 25
```

Este ejemplo es split tunnel y no cambia DNS. Para probar primero el handshake, impórtelo con ambas opciones de consentimiento apagadas. Si el servidor y firewall están accesibles, inicie JARO y observe el estado del peer/contadores; en Linux contraste `sudo wg show wg0 latest-handshakes transfer`.

No añada `DNS=` hasta haber configurado un resolver real que escuche en una dirección dentro de las rutas del túnel (por ejemplo, su propio servicio DNS ligado a `10.77.0.1` o `fd77::1`). WireGuard no instala ni crea un servidor DNS. Luego puede añadir `DNS = <IP_REAL_DE_SU_RESOLVER>` y aceptar la opción de DNS en la app. Una consulta exitosa indica respuesta y evidencia de cambio de contadores del peer; no certifica ausencia total de fugas ni distingue de forma criptográfica un paquete DNS de todo tráfico concurrente.

### 4. Full tunnel

No convierta el ejemplo a full tunnel solo cambiando `AllowedIPs`. Para Full, el perfil exige ambas rutas por defecto y el consentimiento visible del usuario. El servidor también debe tener forwarding IPv4 e IPv6 correctamente configurado, salida/NAT IPv4 si se requiere, un plan de direccionamiento IPv6 que realmente enrute, firewall coherente y DNS alcanzable. Una interfaz IPv6 ULA (`fd...`) por sí sola no da salida IPv6 a Internet.

Al autorizar full tunnel, la app configura `includeAllNetworks`. Apple documenta que enruta la mayor parte del tráfico por el túnel y descarta tráfico cuando el proveedor deja de estar conectado, con excepciones obligatorias de control de red, captive portal, determinados servicios celulares y dispositivos complementarios. Esto es una defensa del sistema más fuerte que limitarse a instalar rutas `0/0`, pero no permite afirmar que absolutamente todo el tráfico del dispositivo esté dentro de WireGuard. No habilite full tunnel hasta probar servidor, IPv4/IPv6, DNS y recuperación en su iPhone.

## Diagnósticos e interpretación honesta

1. **Adapter iniciado** significa que WireGuardKit aceptó iniciar el adapter; no prueba peer remoto.
2. **Handshake** se obtiene del UAPI del peer configurado y se considera fresco solo dentro de la ventana temporal del código. No se construye un handshake de prueba.
3. **RX/TX** se leen de contadores UAPI por clave pública del peer. Los diagnósticos de DNS/HTTPS requieren nuevos deltas bidireccionales, no solo contadores históricos.
4. **DNS** usa el resolver de iOS después de instalar `DNS=`. Una respuesta puede venir de caché o coincidir temporalmente con otro tráfico; los deltas son evidencia auxiliar, no captura/atribución causal perfecta.
5. **HTTPS** requiere que el usuario indique un `https://` con IP literal cubierta por `AllowedIPs`. La cadena TLS debe ser confiable para esa IP. El diagnóstico no usa un endpoint JARO o público predeterminado. Sin servicio y certificado apropiados del usuario, el estado no se puede verificar.
6. **VPN física real** solo queda demostrada al cotejar desde un iPhone instalado y firmado el handshake/contadores con el `wg show` del servidor controlado por el usuario y las pruebas DNS/HTTPS esperadas. CI no realiza esa prueba.

## Firma e instalación de Full en iPhone 12

La variante Full requiere, como mínimo:

- App ID explícito `com.jarocomplements.jarowpf` para la app host y `com.jarocomplements.jarowpf.PacketTunnel` para la extensión, con perfiles de desarrollo propios para cada bundle.
- Capability Network Extensions aprobada para el equipo, con entitlement `com.apple.developer.networking.networkextension` y valor `packet-tunnel-provider` tanto en host como extensión.
- App Group `group.com.jarocomplements.jarowpf` autorizado para ambos targets; el Keychain compartido depende de esa pertenencia firmada.
- Certificado Apple Development y provisioning profiles válidos para ambos targets, con el UDID del iPhone 12 incluido; Xcode y el iPhone deben estar emparejados. Para instalar desde Xcode, el teléfono debe confiar en el Mac y habilitar Developer Mode cuando iOS lo solicite.

La matriz oficial de Apple consultada para las fases anteriores distingue App Groups (disponible en membresía gratuita) de Network Extensions (no disponible en Personal Team gratuita). **Con Linux Mint, iPhone 12 y 0 COP no hay una ruta individual gratuita conocida para firmar Full con `packet-tunnel-provider`.** Las opciones legítimas de coste personal cero son que una organización ya autorizada incorpore al desarrollador y gestione el signing, o que una organización elegible por Apple obtenga una exención; eso requiere permiso del titular y no se presume. En ambos casos aún se requiere acceso a macOS/Xcode para registrar y probar el teléfono. Una Personal Team puede servir para Standalone/proxy, no transforma esa app en VPN IP; sus provisioning profiles de desarrollo son temporales.

Los IPA de GitHub Actions son deliberadamente unsigned: sirven para comprobar estructura/build y no se instalan normalmente en un iPhone. No se recomienda usar certificados/perfiles compartidos de terceros ni métodos que prometan fabricar un entitlement que el equipo Apple no tiene.

## Comprobación disponible y siguiente paso físico

En Linux se pueden ejecutar:

```bash
python3 -m compileall -q core tests
python3 -m unittest discover -s tests -v
git diff --check
```

La suite XCTest, el enlace real de `libwg-go`, y las dos compilaciones iOS Full/Standalone se delegan al workflow macOS de GitHub Actions. No hay Xcode ni dispositivo iPhone en este entorno Linux. Después de Actions, el siguiente paso físico no es instalar el IPA unsigned: hace falta un equipo/macOS con signing autorizado. Allí se selecciona el scheme `JaroApp`, se registra el dispositivo, se configura Team y provisioning para app y extensión, se archive/exporta firmado y se instala desde Xcode. Después se importa el perfil privado, se inicia el túnel y se comparan `latest handshake`, RX/TX y servicios propios. Sin esos permisos/recursos, la prueba física de Full queda bloqueada.

## Referencias

[1]: https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks "Apple: includeAllNetworks"
[2]: https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic "Apple: Routing your VPN network traffic"
[3]: https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes "Apple: enforceRoutes"
[4]: https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension "Apple: Network Extensions Entitlement"
[5]: https://developer.apple.com/help/account/reference/supported-capabilities-ios/ "Apple: Supported capabilities for iOS"
[6]: https://developer.apple.com/documentation/xcode/configuring-app-groups "Apple: Configuring App Groups"
[7]: https://developer.apple.com/help/account/provisioning-profiles/create-a-development-provisioning-profile/ "Apple: Create a development provisioning profile"
[8]: https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles "Apple: TN3125 Inside Code Signing and Provisioning Profiles"
[9]: https://git.zx2c4.com/wireguard-apple/commit/?id=2fec12a6e1f6e3460b6ee483aa00ad29cddadab1 "WireGuard Apple source pinned to release 1.0.16-27"
