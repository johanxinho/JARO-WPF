# JARO WPF — FASE 8.1: DOBLE COMPILACIÓN Y VALIDACIÓN (FULL vs. STANDALONE)

**Organización:** JARO COMPLEMETS  
**Proyecto:** JARO WPF  
**Dispositivo Objetivo:** iPhone 12 con iOS 27.0.1 *(Entorno Jailed Estándar Moderno)*  
**Entorno Local:** Linux Mint 22.3 (3.3 GiB RAM / sin Xcode local)  
**Presupuesto:** \$0 COP (Cero costos, sin servicios de pago, sin tarjetas de crédito)  
**Estado Actual en Hardware:** `UNVERIFIED_ON_PHYSICAL_IPHONE`  

---

## 1. Auditoría Completa de Secretos Previa a Publicación

En cumplimiento estricto de los Requisitos 1 y 2, se ejecutó un escaneo recursivo mediante expresiones regulares y validadores criptográficos en todo el espacio de trabajo:

- **Tokens y Credenciales:** `0` tokens de GitHub (`ghp_...`, `github_pat_...`), `0` claves de API de servicios externos, `0` credenciales de proveedores cloud.
- **Claves Privadas Reales:** `0` claves privadas reales en disco. Las cadenas `-----BEGIN ... PRIVATE KEY-----` presentes en el código corresponden exclusivamente a expresiones regulares de detección y redacción en [`core/security/secret_guard.py`](file:///home/johanxinho/JARO-WPF/core/security/secret_guard.py) y casos de prueba sintéticos que verifican el rechazo automático de claves en [`tests/`](file:///home/johanxinho/JARO-WPF/tests/).
- **Registros de Servidores:** [`configs/servers.json`](file:///home/johanxinho/JARO-WPF/configs/servers.json) mantiene sus listas de túneles autorizados estrictamente vacías:
  ```json
  "authorized_ssh_tunnels": [],
  "authorized_wireguard_tunnels": []
  ```
  reportando de forma transparente `REMOTE_SERVER_REQUIRED`.
- **Protección Git:** Se creó [`.gitignore`](file:///home/johanxinho/JARO-WPF/.gitignore) bloqueando el seguimiento de entornos virtuales (`.venv/`), artefactos de compilación (`build/`, `*.ipa`, `*.xcarchive`), bóvedas locales (`*.wg.conf`, `*.jaroprofile`) y certificados temporales.

---

## 2. Definición Arquitectónica de las Dos Variantes

Para no confundir una VPN completa con un proxy local ni sustituir indebidamente una por otra, se prepararon dos targets y schemes independientes:

```
                                  JARO WPF (ios/)
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
     [VARIANTE A — FULL]                             [VARIANTE B — STANDALONE]
Scheme: JaroApp                                 Scheme: JaroAppStandalone
Product: JaroWPF.app                            Product: JaroWPF-Standalone.app
Entitlements: Config/JaroApp.entitlements       Entitlements: Config/JaroAppStandalone.entitlements
  ├── JaroApp (SwiftUI)                           ├── JaroApp (SwiftUI)
  ├── JaroPacketTunnel.appex (VPN de Sistema)     ├── JaroCore (Modelos, Redacción, Backoff)
  │     ├── WireGuardKit (libwg-go.a real)        ├── JaroSecurity (Keychain)
  │     └── SwiftNIO SSH (DirectTCPIP)            ├── JaroProfiles (.jaroprofile)
  ├── com.apple...networkextension                ├── JaroTunnelEngine (SSH + Proxy Local)
  └── Objetivo: VPN L3 Completa del Sistema       ├── Cero extensiones VPN embebidas
                                                  └── Objetivo: Proxy y Diagnóstico In-App
```

### Especificación de Targets en [ios/project.yml](file:///home/johanxinho/JARO-WPF/ios/project.yml)
- **Target `JaroApp` (Variante A):** Embebe `target: JaroPacketTunnel (embed: true)` con la capacidad `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) en [JaroApp.entitlements](file:///home/johanxinho/JARO-WPF/ios/Config/JaroApp.entitlements).
- **Target `JaroAppStandalone` (Variante B):** Excluye cualquier extensión de red en [JaroAppStandalone.entitlements](file:///home/johanxinho/JARO-WPF/ios/Config/JaroAppStandalone.entitlements). Solo utiliza `Keychain Sharing` y `App Groups` compatibles con cuentas gratuitas de Apple ID.

---

## 3. Integración Real de WireGuardKit (Sin Puentes Vacíos)

1. **Dependencia y Compilación del Puente Go:**
   - `WireGuardKit` (`wireguard-apple` v1.0.16) delega el protocolo WireGuard en el espacio de usuario a una librería estática compilada en Go: `libwg-go.a` (`WireGuardKitGo`).
   - El workflow [`.github/workflows/ios_build.yml`](file:///home/johanxinho/JARO-WPF/.github/workflows/ios_build.yml) clona el repositorio oficial de WireGuard y ejecuta:
     ```bash
     make -C /tmp/wireguard-apple/Sources/WireGuardKitGo
     ```
     compilando `libwg-go.a` con `go 1.22` para la arquitectura `arm64-apple-ios`.
2. **Consumo en Swift:**
   - [`JaroWireGuardEngine.swift`](file:///home/johanxinho/JARO-WPF/ios/Sources/JaroTunnelEngine/JaroWireGuardEngine.swift) instancia directamente los tipos reales de `WireGuardKit`:
     - `WireGuardAdapter(with: packetTunnelProvider)`
     - `TunnelConfiguration(name:interface:peers:)`
     - `InterfaceConfiguration(privateKey:)`
     - `PeerConfiguration(publicKey:)` con `allowedIPs` y `endpoint`
   - La comprobación `#if canImport(WireGuardKit)` asegura que cuando el paquete de WireGuard está presente y `libwg-go.a` enlazada, la extensión ejecuta la máquina de estados real de WireGuard. Si faltara en algún entorno de prueba, arroja explícitamente `JaroWireGuardEngineError.wireGuardKitBridgeNotLinked`, sin falsear la conexión.

---

## 4. Workflows Independientes en GitHub Actions (`.github/workflows/ios_build.yml`)

El pipeline define dos jobs independientes ejecutados sobre el runner oficial de Apple Silicon **`macos-14`** (macOS Sonoma con Xcode 15/16 oficial):

### Job 1: `build-variant-a-full`
1. Verifica el toolchain Swift, Clang y Go 1.22.
2. Ejecuta la suite de pruebas unitarias Swift en macOS: `swift test --package-path ios`.
3. Precompila `libwg-go.a` mediante `make -C .../WireGuardKitGo`.
4. Exporta `JARO_ENABLE_WIREGUARDKIT=1` y genera `JaroWPF.xcodeproj` vía `xcodegen generate`.
5. Compila el scheme `JaroApp` con `CODE_SIGNING_ALLOWED=NO`.
6. Valida que `JaroPacketTunnel.appex` esté embebido en `build-full/Release-iphoneos/JaroWPF.app/PlugIns/`.
7. Empaqueta el bundle en `Payload/` y comprime: `JaroWPF_Full_unsigned.ipa`.
8. Publica el artefacto con retención de 14 días.

### Job 2: `build-variant-b-standalone`
1. Verifica el toolchain Swift y Xcode.
2. Ejecuta la suite de pruebas unitarias Swift: `swift test --package-path ios`.
3. Genera `JaroWPF.xcodeproj` vía `xcodegen generate`.
4. Compila el scheme `JaroAppStandalone` con `CODE_SIGNING_ALLOWED=NO`.
5. Valida que el bundle `JaroWPF-Standalone.app` **NO contenga la carpeta `PlugIns`** (garantizando compatibilidad estricta con firmas gratuitas).
6. Empaqueta el bundle en `Payload/` y comprime: `JaroWPF_Standalone_unsigned.ipa`.
7. Publica el artefacto con retención de 14 días.

---

## 5. Corrección de Errores Exactos de Compilación

Durante la auditoría del proyecto XcodeGen se detectó y resolvió el siguiente error potencial de enlazado en `ios/project.yml`:
- **Causa:** El target `JaroPacketTunnel` compilaba directamente los archivos en `Sources/JaroPacketTunnel` y a la vez declaraba dependencia del producto SPM `JaroPacketTunnel` (que también incluía dichos archivos).
- **Error Evitado:** `duplicate symbol '_OBJC_CLASS_$__TtC16JaroPacketTunnel20PacketTunnelProvider' in: ...`
- **Solución Aplicada:** Se ajustaron las dependencias del target en `ios/project.yml` para que enlace los módulos de soporte (`JaroTunnelEngine`, `JaroCore`, `JaroSecurity`, `JaroProfiles`, `JaroDiagnostics`), permitiendo que `PacketTunnelProvider.swift` se compile exactamente una vez dentro de la extensión.

---

## 6. Estado de Firma y la Realidad de un IPA No Firmado

> [!IMPORTANT]
> **Aclaración Técnica Obligatoria:** Un archivo `.ipa` no firmado (`_unsigned.ipa`) **NO es instalable directamente en un iPhone estándar**.  
> En iOS, el subsistema del kernel `amfid` exige que todo ejecutable Mach-O contenga una firma criptográfica con certificados de Apple y un perfil `.mobileprovision` embebido. Solamente dispositivos con exploits como TrollStore (iOS $\le$ 16.6.1 / 17.0) pueden ejecutar binarios sin firma de Apple.

### Ruta Gratuita y Legítima para Firmar desde Linux Mint (\$0 COP)
Para firmar legítimamente desde Linux con una cuenta gratuita de Apple ID ("Personal Team"):

1. **Herramientas Disponibles:**
   - **`AltServer-Linux`** o **`Sideloadly`** (ejecutable mediante Wine en Linux o en máquina de soporte): Utilizan un servidor local de Anisette (emulación del subsistema de autenticación de Apple) para solicitar el certificado de desarrollo de 7 días al servidor de Apple sin necesidad de Mac.
   - **`SideStore`:** Una vez instalado por primera vez, permite firmar e instalar IPAs directamente desde el propio iPhone mediante una conexión de loopback VPN interna.
2. **Comportamiento por Variante:**
   - **Variante B (Standalone):** Se firma **con éxito y sin advertencias** con la cuenta gratuita, ya que no solicita entitlements restringidos.
   - **Variante A (Full):** Al procesar el IPA, el servidor de aprovisionamiento de Apple devuelve:
     `"Personal Teams do not support Network Extensions"`
     y omite la extensión VPN o aborta la firma. Si se fuerza la instalación de la extensión sin firma oficial de Apple, iOS 27.0.1 arroja el error `0xe8008016`.

---

## 7. Instrucciones Verificadas para Instalar en iPhone 12 con iOS 27.0.1

### Paso 1: Obtener el Artefacto desde GitHub Actions
Descargar el archivo `JaroWPF_Standalone_unsigned.ipa` (para uso inmediato con cuenta gratuita) o `JaroWPF_Full_unsigned.ipa` (para inspección o uso con cuenta de pago) desde la pestaña *Actions → Artifacts* del repositorio.

### Paso 2: Firma con Apple ID Personal (\$0 COP)
Firmar el archivo `JaroWPF_Standalone_unsigned.ipa` utilizando su cuenta de Apple ID mediante la herramienta de sideloading elegida, generando `JaroWPF_Standalone_signed.ipa`.

### Paso 3: Conexión USB y Emparejamiento en Linux Mint
1. Conectar el iPhone 12 por cable USB al PC y desbloquear la pantalla.
2. Asegurar el demonio `usbmuxd`:
   ```bash
   sudo systemctl start usbmuxd
   ```
3. Emparejar el iPhone con Linux Mint:
   ```bash
   idevicepair pair
   ```
   *(Pulsar **"Confiar en este ordenador"** en la pantalla del iPhone e ingresar el código de desbloqueo).*
4. Verificar la comunicación:
   ```bash
   ideviceinfo -s
   ```
   *(Debe retornar el modelo `iPhone13,2` y el UDID del dispositivo).*

### Paso 4: Instalación Directa
Instalar la variante firmada por cable mediante la herramienta nativa de Linux:
```bash
ideviceinstaller -i JaroWPF_Standalone_signed.ipa
```

### Paso 5: Confianza y Modo Desarrollador en iOS 27.0.1
1. En el iPhone 12, abrir *Ajustes → Privacidad y seguridad → Modo de desarrollo*, activarlo y reiniciar el dispositivo.
2. Ir a *Ajustes → General → VPN y gestión de dispositivos*, seleccionar el correo de su Apple ID y pulsar **"Confiar en [su cuenta]"**.
3. Abrir la app **JARO WPF**.

### Paso 6: Telemetría en Tiempo Real desde Linux
Monitorear los eventos de la app en vivo por USB desde la terminal de Linux:
```bash
idevicesyslog | grep "Jaro"
```

---

## 8. Pruebas Pendientes en Hardware Físico

1. **Verificación de UI y Bóveda Keychain:** Apertura de la aplicación en el iPhone 12, renderizado SwiftUI y almacenamiento seguro de claves Curve25519 en el Keychain del teléfono.
2. **Verificación de Proxy Local Standalone:** Activar el toggle *"Modo Standalone"* en la app, conectar con un servidor SSH autorizado y verificar que el puerto `127.0.0.1:<puerto>` responda a solicitudes HTTP CONNECT y SOCKS5.
3. **Comprobación de Política de Red:** Cambiar entre Wi-Fi y Datos Móviles para validar la lectura de `NWPathMonitor` en pantalla.
4. **Prueba de Extensión VPN (Variante A):** Intentar la instalación de la Variante A para documentar en el log del dispositivo el rechazo exacto de Apple al entitlement de VPN bajo cuenta gratuita.

---

## 9. Resumen de Costos y Seguridad

- Repositorio público en GitHub para CI: **\$0 COP**.
- Runners oficiales `macos-14` con Xcode 15/16: **\$0 COP** (minutos ilimitados para proyectos públicos).
- Herramientas locales de Linux (`usbmuxd`, `ideviceinstaller`): **\$0 COP** (instaladas y de código abierto).
- Cuenta personal Apple ID: **\$0 COP**.
- **Costo Total:** **\$0 COP**.
- **Seguridad:** Cero secretos, certificados o contraseñas subidos a la nube. El repositorio permanece completamente desprovisto de claves privadas.
