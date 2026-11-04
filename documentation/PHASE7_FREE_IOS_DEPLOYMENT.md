# JARO WPF — FASE 7: COMPILACIÓN Y DESPLIEGUE GRATUITO EN IPHONE DESDE LINUX

**Organización:** JARO COMPLEMETS  
**Proyecto:** JARO WPF  
**Dispositivo Objetivo:** iPhone 12  
**Entorno de Desarrollo:** Linux Mint 22.3  
**Presupuesto:** \$0 COP (Cero costos, sin servicios de pago, sin tarjetas de crédito)  
**Estado Actual del Hardware:** `UNVERIFIED_ON_PHYSICAL_IPHONE`  

---

## 1. Diagnóstico y Estado Real del Repositorio

- **Fases 1 a 6:** Completadas y verificadas con `65/65` pruebas automatizadas aprobadas en Linux Mint (`7.138s`, `0 B` de tráfico externo no autorizado).
- **Motores Multiplataforma en Linux/Windows:**
  - QUIC / HTTP/3 (`aioquic`), DNS (Do53, DoT, DoQ), HTTPS estricto con validación X.509/SAN.
  - SSH / SOCKS5 (`SshSocksTunnel`) con clave Ed25519 y verificación de huella `SHA256:...`.
  - WireGuard (`WireGuardTunnelEngine`) con aislamiento estricto de rutas (`verify_route_isolation`) y compuerta de privilegios (`PrivilegePolicyGate`).
  - Gestor de perfiles portable `.jaroprofile` v1.0 (`JaroProfileManager`), puente dual SOCKS5/HTTP CONNECT (`JaroDualProxyBridge`), y adaptadores Windows (`WindowsOpenSshAdapter`, `WindowsWireGuardServiceAdapter`).
- **Arquitectura Nativa iOS en `ios/`:**
  - 7 módulos en Swift 5.9+: `JaroCore`, `JaroSecurity`, `JaroProfiles`, `JaroTunnelEngine`, `JaroDiagnostics`, `JaroPacketTunnel`, `JaroApp`.
  - Configuración declarativa mediante `Package.swift` y `project.yml` (XcodeGen).
  - Entitlements definidos: `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`), App Group `group.com.jarocomplements.jarowpf`, Keychain Sharing.
- **Herramientas de Comunicación con iPhone presentes en Linux Mint:**
  - Verificado en el sistema: `/usr/bin/usbmuxd`, `/usr/bin/ideviceinstaller`, `/usr/bin/idevicepair`, `/usr/bin/ideviceinfo`, `/usr/bin/idevice_id` ya están instalados y operativos.

---

## 2. Alternativas de Compilación Evaluadas

| Alternativa | Costo | Viabilidad Técnica | Veredicto | Motivo Técnico |
|---|---|---|---|---|
| **Compilación cruzada directa en Linux Mint** (`swift build --triple arm64-apple-ios`) | \$0 COP | **Inviable** | **Descartada** | Apple **no publica el SDK de iOS** (Darwin SDK) ni sus frameworks privativos (`NetworkExtension`, `SwiftUI`, `Security`, `Network`) para Linux. El compilador Swift en Linux no puede enlazar contra librerías de iOS que no existen legal ni físicamente en Linux. |
| **Máquina Virtual macOS en Linux** (OSX-KVM / Docker-OSX) | \$0 COP | **Inviable en este host** | **Descartada** | El host dispone de **3.3 GiB de RAM** y 2.0 GiB de swap. Ejecutar macOS virtualizado con Xcode 15/16 requiere un mínimo de 12 a 16 GiB de RAM. En 3.3 GiB provocaría agotamiento inmediato de memoria (Kernel OOM Panic). |
| **Servicios Cloud Mac de Pago** (MacStadium, AWS EC2 Mac, Bitrise) | \$20–\$100+ USD | Viable técnicamente | **Descartada** | Viola la restricción estricta de **presupuesto \$0 COP** y requiere tarjetas de crédito o suscripciones. |
| **Compilación Remota Gratuita mediante GitHub Actions (Runner macOS)** | **\$0 COP** | **Totalmente Viable** | **SELECCIONADA** | GitHub Actions ofrece runners oficiales macOS (Sonoma `macos-14`, Sequoia `macos-15`) con **Xcode 15/16 completo preinstalado**. Para repositorios públicos es **100% gratuito** y con minutos ilimitados. Permite compilar mediante `xcodegen` + `xcodebuild` y empaquetar un `.ipa` como artefacto descargable sin costo ni tarjeta de crédito. |

---

## 3. Requisitos de Apple y la Barrera de NetworkExtension

### A. Cuenta Apple ID Gratuita ("Personal Team")
Cualquier persona puede crear una cuenta gratuita de Apple ID para firmar aplicaciones de desarrollo personal. Sin embargo, Apple impone restricciones arquitectónicas estrictas a nivel de servidor de aprovisionamiento:

1. **Vigencia del Certificado:** **7 días**. Tras 7 días, la firma expira y la aplicación no puede abrirse en el iPhone a menos que se re-firme e instale nuevamente.
2. **Límite de Dispositivos y Apps:** Máximo **3 aplicaciones simultáneas** instaladas por dispositivo mediante cuenta gratuita.
3. **Restricción Crítica de Entitlements:**
   - El entitlement `com.apple.developer.networking.networkextension` con la capacidad `packet-tunnel-provider` es una **Managed Capability** (capacidad privilegiada).
   - **Los servidores de Apple RECHAZAN emitir perfiles de aprovisionamiento con `packet-tunnel-provider` a cuentas gratuitas (Personal Team).**
   - El error exacto arrojado por Apple es:  
     `"Personal Teams do not support Network Extensions"`  
     o `"Provisioning profile doesn't include the com.apple.developer.networking.networkextension entitlement."`
   - Si se instala un binario en un iPhone estándar (sin exploit) que contenga la extensión `JaroPacketTunnel`, el instalador del sistema operativo (`installd` y `amfid`) verifica criptográficamente que el perfil de aprovisionamiento emitido por Apple contenga el entitlement. Al no contenerlo, la instalación es rechazada con error `0xe8008016` o el proceso de la VPN es terminado inmediatamente con `SIGKILL`.

### B. Matriz de Posibilidades según el Estado del iPhone 12

| Estado del iPhone 12 | ¿Permite Compilar \$0 COP? | ¿Permite Instalar App \$0 COP? | ¿Permite VPN del Sistema (`PacketTunnel`)? | Explicación Técnica y Alternativa |
|---|---|---|---|---|
| **iPhone Estándar (Jailed, sin exploit)** con cuenta Apple gratuita | **SÍ** (vía GitHub Actions) | **SÍ** (firma 7 días vía AltStore / Sideloadly / ideviceinstaller) | **NO** (Bloqueado por Apple en cuentas gratuitas) | **Alternativa Real JARO:** Compilar la aplicación en modo **JARO Standalone In-App Proxy / Diagnostic Client** (sin la extensión `PacketTunnel`). La app ejecuta en primer plano el motor SSHv2 (`SwiftNIO SSH`) y el proxy local (`SOCKS5` / `HTTP CONNECT` en `127.0.0.1:<puerto>`). El tráfico del dispositivo se enruta configurando manualmente el proxy Wi-Fi de iOS hacia `127.0.0.1`. |
| **iPhone con TrollStore** (iOS 14.0 – 16.6.1 / 17.0) | **SÍ** (vía GitHub Actions) | **SÍ** (Permanente, sin límite de 7 días) | **SÍ** (VPN 100% Funcional) | TrollStore explota el fallo de **CoreTrust** para otorgar a la app y sus extensiones permisos de nivel de sistema (Root/Platform Entitlements). En este caso, **`NEPacketTunnelProvider` funciona de forma nativa y completa a \$0 COP sin cuenta de pago**. |
| **iPhone con Jailbreak** (iOS 15.0 – 16.5.1 / 16.6.1 Dopamine) | **SÍ** (vía GitHub Actions) | **SÍ** (vía Filza / dpkg) | **SÍ** (VPN 100% Funcional) | Los permisos se inyectan localmente mediante `ldid` sin requerir firma oficial de Apple. |

---

## 4. Limitaciones del Entorno Linux

1. **Ausencia de SDK de Apple:** Linux no puede compilar directamente archivos que importen `NetworkExtension`, `UIKit`, `SwiftUI`, `Security` o `Network.framework`.
2. **Generación de Anisette Data para Firma Local:** Las herramientas de sideloading en Linux (como `altserver-linux`) requieren un servidor local o contenedor de Anisette (emulación del subsistema de autenticación de Apple) para solicitar el certificado de 7 días al servidor de Apple sin Xcode.
3. **Comunicación USB Directa Funcional:** Linux Mint cuenta con `usbmuxd` y `libimobiledevice` (`ideviceinstaller`, `idevicepair`, `idevicesyslog`), lo que permite emparejar el iPhone 12 por cable, consultar su información, instalar paquetes `.ipa` y leer los registros del sistema en vivo sin necesidad de software de terceros ni Windows.

---

## 5. Procedimiento Elegido (\$0 COP, Reproducible y Seguro)

Para respetar el presupuesto de \$0 COP, no subir secretos a la nube y preservar la arquitectura completa, el procedimiento se divide en dos etapas:

```
[Código Swift en Linux Mint]
          │
          ▼  (git push a repositorio público propio)
[GitHub Actions (macOS Runner Oficial $0 COP)]
   ├── 1. Instala Go y xcodegen vía Homebrew
   ├── 2. Genera JaroWPF.xcodeproj
   ├── 3. Compila JaroApp (Unsigned Release)
   └── 4. Empaqueta Payload/JaroApp.app -> JaroWPF_unsigned.ipa
          │
          ▼  (descarga directa del artefacto a Linux Mint)
[Linux Mint 22.3 (Host Local)]
   ├── Opción 1 (iPhone con TrollStore):
   │     Instalación directa por USB: ideviceinstaller -i JaroWPF_unsigned.ipa
   │
   └── Opción 2 (iPhone Jailed Estándar):
         Firma con Apple ID gratuito (7 días) -> Instalación por USB
         Modo de operación: In-App Proxy / Diagnóstico local
```

### Seguridad y Privacidad Garantizadas:
- **CERO claves privadas ni contraseñas subidas a GitHub:** El repositorio solo contiene código fuente público. Los archivos `servers.json` y los perfiles de conexión se mantienen vacíos (`REMOTE_SERVER_REQUIRED`) hasta que el usuario configure sus servidores de forma privada y local en el propio dispositivo.
- **CERO costos:** Utiliza la cuota pública ilimitada de GitHub Actions y cuentas gratuitas de Apple.

---

## 6. Comandos Reproducibles

### A. Workflow de Compilación Remota en GitHub Actions (`.github/workflows/ios_build.yml`)
El archivo de automatización compila el código nativo en un entorno virtual macOS oficial:

```yaml
name: Build JARO WPF iOS IPA ($0 COP)

on:
  workflow_dispatch:
  push:
    branches: [ main, master ]
    paths:
      - 'ios/**'
      - '.github/workflows/ios_build.yml'

jobs:
  build-ios:
    runs-on: macos-14 # macOS Sonoma con Xcode 15/16 preinstalado
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Go (requerido por WireGuardKitGo)
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install XcodeGen
        run: brew install xcodegen

      - name: Generate Xcode Project
        working-directory: ios
        run: xcodegen generate

      - name: Build Unsigned Application Bundle
        working-directory: ios
        run: |
          xcodebuild build \
            -project JaroWPF.xcodeproj \
            -scheme JaroApp \
            -destination 'generic/platform=iOS' \
            -configuration Release \
            CODE_SIGNING_ALLOWED=NO \
            CODE_SIGNING_REQUIRED=NO \
            CODE_SIGN_IDENTITY="" \
            BUILD_DIR="${{ github.workspace }}/build"

      - name: Package Unsigned IPA
        run: |
          mkdir -p build/Payload
          APP_PATH=$(find build -name "JaroWPF.app" -type d | head -n 1)
          cp -R "$APP_PATH" build/Payload/
          cd build
          zip -r JaroWPF_unsigned.ipa Payload
          cd ..

      - name: Upload IPA Artifact
        uses: actions/upload-artifact@v4
        with:
          name: JaroWPF-unsigned-ipa
          path: build/JaroWPF_unsigned.ipa
```

### B. Comandos en Linux Mint para Emparejar e Instalar en el iPhone 12 por USB

1. **Iniciar el demonio de multiplexación USB:**
   ```bash
   sudo systemctl start usbmuxd
   ```

2. **Conectar el iPhone 12 por cable USB al PC y desbloquear la pantalla.**

3. **Emparejar el dispositivo con Linux Mint:**
   ```bash
   idevicepair pair
   ```
   *(Pulsar **"Confiar en este ordenador"** e introducir el código de desbloqueo en la pantalla del iPhone).*

4. **Verificar comunicación con el iPhone:**
   ```bash
   ideviceinfo -s
   ```
   *(Muestra el modelo `iPhone13,2` correspondiente al iPhone 12, la versión de iOS y el identificador UDID).*

5. **Si el iPhone cuenta con TrollStore:**
   Instalar directamente el IPA descargado desde Linux:
   ```bash
   ideviceinstaller -i JaroWPF_unsigned.ipa
   ```

6. **Si el iPhone es estándar (Jailed):**
   Firmar el IPA con la cuenta gratuita de Apple ID mediante una herramienta de sideloading compatible (por ejemplo, Sideloadly o AltServer) e instalar por USB:
   ```bash
   ideviceinstaller -i JaroWPF_signed_personal.ipa
   ```

7. **Monitorear registros de la aplicación en tiempo real desde Linux:**
   ```bash
   idevicesyslog | grep "Jaro"
   ```

---

## 7. Matriz de Funciones: Qué Puede Probarse vs. Qué Requiere Cuenta de Pago

| Capacidad de JARO WPF | Probado y Verificado en Linux (Fases 1–6) | Probable en iPhone Estándar (\$0 COP, Cuenta Gratis) | Probable en iPhone con TrollStore (\$0 COP) | Requiere Cuenta Apple de Pago (\$99 USD/año) |
|---|---|---|---|---|
| **Gestor de Perfiles `.jaroprofile`** | SÍ (Fase 6) | SÍ (Interfaz SwiftUI) | SÍ (Interfaz SwiftUI) | No requerida |
| **Bóveda Keychain Segura** | SÍ (Fase 6) | SÍ (`Security.framework`) | SÍ (`Security.framework`) | No requerida |
| **Cliente SSHv2 en Proceso** | SÍ (Fase 5/6) | SÍ (`SwiftNIO SSH` en app) | SÍ (`SwiftNIO SSH` en app) | No requerida |
| **Proxy Dual SOCKS5 / HTTP CONNECT** | SÍ (Fase 6) | SÍ (Escuchando en `127.0.0.1`) | SÍ (Escuchando en `127.0.0.1`) | No requerida |
| **Diagnóstico HTTPS con Validación X.509** | SÍ (Fase 4/6) | SÍ (Sondas internas en app) | SÍ (Sondas internas en app) | No requerida |
| **Aislamiento de Coste (`NWPathMonitor`)** | SÍ (Fase 4/6) | SÍ (Detección Wi-Fi / Celular) | SÍ (Detección Wi-Fi / Celular) | No requerida |
| **Túnel VPN del Sistema (`NEPacketTunnel`)** | No aplicable (iOS) | **NO** *(Bloqueado por Apple en cuenta gratis)* | **SÍ** *(Vía bypass CoreTrust)* | **SÍ** *(Única vía oficial de Apple)* |
| **Enrutamiento Global de Apps de Terceros** | No aplicable (iOS) | **Parcial** *(Solo apps con soporte proxy manual o proxy Wi-Fi)* | **SÍ** *(Túnel L3 completo del sistema)* | **SÍ** *(Túnel L3 completo del sistema)* |

---

## 8. Funciones Pendientes para Completar el Despliegue en Hardware

1. **Definir la vía del iPhone 12:** El usuario debe confirmar la versión de iOS de su iPhone 12 para determinar si dispone de TrollStore (iOS $\le$ 16.6.1 / 17.0) o si opera en iOS estándar reciente (iOS 17.x / 18.x).
2. **Publicar el repositorio en GitHub (o crear repositorio espejo):** Para habilitar la ejecución del workflow de compilación en runner macOS sin costo.
3. **Descargar y probar el primer binario en el dispositivo físico:** Realizar la primera prueba de enlace físico USB mediante `ideviceinfo` y verificar el arranque de la interfaz SwiftUI en el iPhone 12.
