# JARO WPF — FASE 8.4: INFORME DE VALIDACIÓN BINARIA, EXTENSIÓN Y FIRMA
**Organización:** JARO COMPLEMETS  
**Proyecto:** JARO WPF  
**Fecha:** 2026-11-04  
**Entorno de desarrollo:** Linux Mint 22.3  
**Dispositivo objetivo:** iPhone 12 (iOS 27.0.1)  
**Presupuesto:** 0 COP (Sin pagos, sin suscripciones pagas, sin elusión de seguridad)  
**Repositorio GitHub:** [https://github.com/johanxinho/JARO-WPF](https://github.com/johanxinho/JARO-WPF)  
**Commit de validación:** [`66829f6`](https://github.com/johanxinho/JARO-WPF/commit/66829f6)  
**Workflow oficial:** [`.github/workflows/ios_build.yml`](https://github.com/johanxinho/JARO-WPF/blob/main/.github/workflows/ios_build.yml)  

---

## 1. RESULTADOS DE INTEGRACIÓN CONTINUA (GITHUB ACTIONS)

Ambas variantes fueron compiladas de forma limpia e independiente en runners `macos-14` (Apple Silicon M1/M2 con Xcode 15.4 / Swift 5.10):

| Métrica | Variante A: Full System VPN | Variante B: Standalone In-App Proxy |
| :--- | :--- | :--- |
| **Workflow Run** | [Run 41932514935](https://github.com/johanxinho/JARO-WPF/actions/runs/41932514935) | [Run 41932514935](https://github.com/johanxinho/JARO-WPF/actions/runs/41932514935) |
| **Job ID** | `126932706607` | `126932707091` |
| **Resultado final** | **SUCCESS (Completado)** | **SUCCESS (Completado)** |
| **Duración** | 3m 33s | 2m 57s |
| **Toolchain** | Xcode 15.4 (Build 15F31d) / Go 1.22.12 | Xcode 15.4 (Build 15F31d) |
| **Destino de compilación** | `generic/platform=iOS` (arm64) | `generic/platform=iOS` (arm64) |
| **Nombre de artefacto** | `JaroWPF-Full-unsigned-ipa` | `JaroWPF-Standalone-unsigned-ipa` |
| **Archivo generado** | `JaroWPF_Full_unsigned.ipa` | `JaroWPF_Standalone_unsigned.ipa` |
| **Tamaño del archivo** | **7,314,237 bytes (~7.3 MB)** | **2,554,552 bytes (~2.5 MB)** |
| **Hash SHA-256** | `cba88ebe31d20d327e63f25a772f231238c5d24a2b7a07c7ae4021350ce7dc2b` | `284e1635f4e8bd3ee9d5ac7e8631b28e6aec9e70c161d91335a02a7b65c1b962` |

---

## 2. INSPECCIÓN BINARIA DETALLADA — VARIANTE A (FULL VPN)

Se descargó el paquete `JaroWPF_Full_unsigned.ipa` de la ejecución `41932514935` y se descomprimió en un entorno de inspección aislado en Linux:

### A. Estructura interna del paquete
```text
Payload/
├── JaroWPF.app/
│   ├── JaroWPF (Binario Mach-O 64-bit arm64, app principal)
│   ├── Info.plist (CFBundleIdentifier: com.jarocomplements.jarowpf)
│   ├── PkgInfo
│   ├── swift-crypto_Crypto.bundle/
│   ├── swift-nio_NIOPosix.bundle/
│   └── PlugIns/
│       └── JaroPacketTunnel.appex/
│           ├── JaroPacketTunnel (Binario Mach-O 64-bit arm64, 12,579,816 bytes)
│           ├── Info.plist (Metadatos de extensión)
│           ├── swift-crypto_Crypto.bundle/
│           └── swift-nio_NIOPosix.bundle/
```

### B. Verificación de la extensión Network Extension
- **Existencia confirmada:** `JaroPacketTunnel.appex` existe físicamente dentro del subdirectorio `PlugIns/` de la aplicación principal.
- **Identificador de la extensión:** `com.jarocomplements.jarowpf.PacketTunnel` (coincide exactamente con el `PRODUCT_BUNDLE_IDENTIFIER` configurado en `project.yml`).
- **Punto de extensión:** `NSExtensionPointIdentifier` = `com.apple.networkextension.packet-tunnel`.
- **Clase principal:** `NSExtensionPrincipalClass` = `JaroPacketTunnel.PacketTunnelProvider`.
- **Arquitectura:** `Mach-O 64-bit arm64 executable` (compilado para iOS 16.0+, compatible nativamente con el chip A14 Bionic del iPhone 12).

### C. Enlace real de WireGuardKit y libwg-go.a
No existen stubs vacíos ni simulaciones. Se verificó mediante inspección de símbolos binarios y logs del enlazador `ld`:
1. **Archivo estático precompilado:** `libwg-go.a` (3.1 MB) generado por Go 1.22 a partir del repositorio oficial `wireguard-apple/Sources/WireGuardKitGo` para `iphoneos arm64`.
2. **Símbolos CGO de bajo nivel enlazados en el binario:**
   - `_wgTurnOn` / `main.wgTurnOn` (6 referencias binarias)
   - `_wgTurnOff` / `main.wgTurnOff` (5 referencias binarias)
   - `_wgSetConfig` / `main.wgSetConfig` (6 referencias binarias)
   - `_wgGetConfig` / `main.wgGetConfig` (6 referencias binarias)
   - `_wgVersion` (4 referencias binarias)
3. **Módulos Swift de alto nivel enlazados:**
   - `WireGuardKit.WireGuardAdapter` (15 referencias binarias activas)
   - `PacketTunnelProvider` (25 referencias binarias activas)
   - `PacketTunnelProvider.o` y `WireGuardAdapter.o` enlazados directamente en el archivo ejecutable.

### D. Implementación del ciclo de vida de NEPacketTunnelProvider
El archivo `Sources/JaroPacketTunnel/PacketTunnelProvider.swift` implementa el ciclo de vida completo de NetworkExtension:
- `startTunnel(options:completionHandler:)`:
  - Valida el margen de memoria contra el techo estricto de Jetsam de 15 MB (`queryAvailableExtensionMemoryBytes()`).
  - Extrae y decodifica el perfil seguro `.jaroprofile` v1.0 desde `providerConfiguration["jaro_profile_json"]`.
  - Exige explícitamente `authorized == true` en el perfil; si no existe servidor configurado, retorna error controlado `REMOTE_SERVER_REQUIRED`.
  - Invoca `JaroWireGuardEngine.start(profile:secretStore:packetTunnelProvider:)`, el cual instancia y activa `WireGuardAdapter`.
- `stopTunnel(with:completionHandler:)`:
  - Detiene el monitor de costes `JaroPathCostMonitor`.
  - Cierra de forma ordenada el servidor local SOCKS5 y la sesión SSH.
  - Ejecuta `WireGuardAdapter.stop()`, liberando los sockets UDP y el descriptor TUN.
- `handleAppMessage(_:completionHandler:)`:
  - Provee canal de telemetría bidireccional IPC con `JaroApp` para consultas de estado (`statusSnapshot`), logs en memoria y verificación HTTPS en vivo.

---

## 3. INSPECCIÓN BINARIA DETALLADA — VARIANTE B (STANDALONE)

### A. Estructura interna del paquete
```text
Payload/
└── JaroWPF-Standalone.app/
    ├── JaroWPF-Standalone (Binario Mach-O 64-bit arm64, 9,894,432 bytes)
    ├── Info.plist (CFBundleIdentifier: com.jarocomplements.jarowpf.standalone)
    ├── PkgInfo
    ├── swift-crypto_Crypto.bundle/
    └── swift-nio_NIOPosix.bundle/
```

### B. Ausencia total de extensiones y permisos restringidos
- **Zero PlugIns:** El paquete no contiene el directorio `PlugIns/`.
- **Zero NetworkExtension:** No solicita `com.apple.developer.networking.networkextension` en su `Info.plist` ni en sus entitlements.
- **Arquitectura:** `Mach-O 64-bit arm64 executable` nativo.

### C. Motores integrados in-process
- **SSHv2 nativo:** Implementado mediante `SwiftNIO SSH` (`NIOSSHHandler`, canal `DirectTCPIP`). Requiere servidor remoto autorizado y validación de huella digital SHA-256 del host key; de lo contrario retorna `REMOTE_SERVER_REQUIRED`.
- **Proxy dual SOCKS5 / HTTP CONNECT:** Implementado en `JaroLocalSOCKS5Server.swift`, escucha en `127.0.0.1:1080` y reenvía tráfico mediante canales `direct-tcpip` sobre la conexión SSH activa.

---

## 4. AUDITORÍA DE ENTITLEMENTS Y REALIDAD DE FIRMA

### Matriz de Entitlements
| Entitlement / Capacidad | Variante A (Full VPN) | Variante B (Standalone) | Exigencia de Apple en iOS |
| :--- | :--- | :--- | :--- |
| `com.apple.developer.networking.networkextension` | **Solicitado** (`packet-tunnel-provider`) | **NO solicitado** (Excluido) | **Privilegiado:** Apple bloquea este entitlement en cuentas gratuitas (Personal Team). Exige Apple Developer Program oficial (\$99/año o Fee Waiver). |
| `keychain-access-groups` | Solicitado (`group.com.jarocomplements.jarowpf`) | Solicitado (`group.com.jarocomplements.jarowpf`) | Compatible con firma gratuita. |
| `com.apple.security.application-groups` | Solicitado (`group.com.jarocomplements.jarowpf`) | Solicitado (`group.com.jarocomplements.jarowpf`) | Compatible con firma gratuita. |
| `embedded.mobileprovision` | **Ausente** (Compilación sin firma) | **Ausente** (Compilación sin firma) | Requerido por el kernel de iOS para instalación. |
| `_CodeSignature` | **Ausente** | **Ausente** | Requerido por `installd` en dispositivos no-jailbroken. |

> [!IMPORTANT]
> **Distinción técnica fundamental:**  
> Un entitlement declarado en el archivo de texto fuente `.entitlements` **NO** confiere autorización por sí mismo en iOS. La autorización efectiva la otorga exclusivamente Apple cuando genera e incrusta el archivo criptográfico `embedded.mobileprovision` firmado por su entidad certificadora.  
> Los paquetes generados en CI son deliberadamente **IPAs sin firmar (`_unsigned.ipa`)**, ya que GitHub Actions no posee (ni debe poseer) certificados privados de firma personal.

---

## 5. MATRIZ DE PRUEBAS TÉCNICAS Y SEPARACIÓN DE RESPONSABILIDADES

| Nivel de Verificación | Estado | Evidencia |
| :--- | :--- | :--- |
| **1. Pruebas Python (Linux)** | **65/65 APROBADAS** (7.66s) | `unittest discover -s tests -v`. Valida motores de protocolos, paridad de esquemas `.jaroprofile`, seguridad de claves y aislamiento de rutas. |
| **2. Pruebas Swift (macOS CI)** | **4/4 APROBADAS** (0.01s) | `swift test --package-path ios` (`JaroCoreTests`). Valida importación de perfiles, redacción de secretos, retroceso exponencial y validación criptográfica OpenSSH. |
| **3. Compilación Xcode (macOS CI)** | **COMPILADO EXITOSO** (3m 33s) | Xcode 15.4 genera los dos binarios Mach-O arm64 con optimización de Release. |
| **4. Enlace WireGuard (macOS CI)** | **ENLAZADO REALMENTE** | `libwg-go.a` + `WireGuardKit` vinculados estáticamente en `JaroPacketTunnel`. |
| **5. Estado de Firma** | **SIN FIRMAR (`_unsigned`)** | No se inyectaron certificados no autorizados ni perfiles ficticios. |
| **6. Instalación en iPhone 12** | **NO INSTALADO / PENDIENTE DE FIRMA** | `ideviceinfo` reporta que el iPhone no está conectado vía USB. La instalación de IPAs sin firmar es rechazada por el daemon `installd` de iOS. |
| **7. Conexión SSH Remota** | **`REMOTE_SERVER_REQUIRED`** | Registros autorizados vacíos en cumplimiento de la política de seguridad; sin servidores de prueba ficticios. |
| **8. Conexión WireGuard Remota** | **`REMOTE_SERVER_REQUIRED`** | Sin servidor WireGuard remoto registrado; validación en loopback local aprobada en pruebas unitarias. |
| **9. Tráfico real y salida a Internet** | **VERIFICADO EN LOOPBACK LOCAL / PENDIENTE REMOTO** | Transferencia bidireccional local validada; tráfico hacia Internet a través de túnel móvil requiere servidor autorizado y firma de app. |

---

## 6. DIFERENCIA OPERATIVA: VPN DE SISTEMA VS. PROXY LOCAL

```
+---------------------------------------------------------------------------------------+
|                                    JARO WPF DUAL CORE                                 |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|   [ VARIANTE A: FULL SYSTEM VPN ]                       [ VARIANTE B: STANDALONE ]    |
|   -------------------------------                       --------------------------    |
|   * Componente: JaroPacketTunnel.appex                  * Componente: JaroWPF-Standalone|
|   * Tipo: NEPacketTunnelProvider                        * Tipo: App de usuario única  |
|   * Capa de red: Capa 3 (IP / Packet Layer)            * Capa de red: Capa 5/7 (TCP)  |
|   * Interfaz: Virtual TUN (utun)                        * Interfaz: Loopback 127.0.0.1|
|   * Alcance: Todo el tráfico de iOS                     * Alcance: Apps configuradas  |
|   * Motores: WireGuard + SSH L3 Split-Tunnel           * Motores: In-process SSHv2   |
|   * Requisito Apple: Apple Developer (\$99/año)          * Requisito Apple: Apple ID $0|
|                                                                                       |
+---------------------------------------------------------------------------------------+
```

---

## 7. PROCEDIMIENTO EXACTO PARA PROBAR EN IPHONE 12 (PRESUPUESTO $0 COP)

Dado que no se dispone de cuenta de pago de Apple Developer (\$99 USD/año) ni de Mac física local, la vía técnica legítima y gratuita consiste en firmar y desplegar la **Variante B (Standalone)**:

### Paso 1: Conectar y emparejar el iPhone 12 en Linux Mint
1. Conectar el iPhone 12 mediante cable USB a la máquina con Linux Mint.
2. Desbloquear la pantalla del iPhone y presionar **"Confiar en este ordenador"**, ingresando el código de desbloqueo.
3. Verificar el emparejamiento ejecutando en la terminal:
   ```bash
   idevicepair pair
   ideviceinfo -s
   ```
   Debe mostrar el `UniqueDeviceID` (UDID) del dispositivo.

### Paso 2: Firma legítima con Apple ID gratuito ($0 COP)
Existen dos métodos directos sin pagar:

#### Opción 2A — En el iPhone (On-Device mediante SideStore / AltStore)
1. Instalar el asistente gratuito AltStore o SideStore en el iPhone utilizando una cuenta de Apple ID gratuita estándar.
2. Transferir el archivo `JaroWPF_Standalone_unsigned.ipa` al iPhone (vía iCloud Drive, AirDrop local o cable USB mediante `ifuse`).
3. Abrir SideStore/AltStore, seleccionar **"My Apps" -> "+"** y elegir `JaroWPF_Standalone_unsigned.ipa`.
4. La herramienta utilizará tu Apple ID gratuito para solicitar un certificado de desarrollo personal válido por 7 días y firmará el paquete instalándolo directamente.

#### Opción 2B — Desde Linux Mint con `zsign` o herramientas de firma local
1. Obtener el certificado de desarrollo gratuito (`.p12`) y el perfil de aprovisionamiento (`.mobileprovision`) generado por Xcode o el servicio de aprovisionamiento de Apple para tu Apple ID.
2. Firmar el IPA localmente:
   ```bash
   zsign -k dev.p12 -p password -m embedded.mobileprovision -o JaroWPF_Standalone_signed.ipa /tmp/run-41932514935/standalone/JaroWPF_Standalone_unsigned.ipa
   ```
3. Instalar en el iPhone mediante USB:
   ```bash
   ideviceinstaller -i JaroWPF_Standalone_signed.ipa
   ```

### Paso 3: Activación en iOS
1. Ir en el iPhone a **Ajustes -> General -> Gestión de VPN y dispositivos**.
2. Bajo **"App de desarrollador"**, presionar sobre tu correo de Apple ID y pulsar **"Confiar"**.
3. En iOS 16+, habilitar el **Modo de desarrollador** en **Ajustes -> Privacidad y seguridad -> Modo de desarrollador** (requiere reiniciar el dispositivo).
4. Abrir la app **JARO WPF** en la pantalla de inicio.

### Paso 4: Prueba operativa del proxy
1. Configurar un servidor SSH legítimo propio (IP, puerto, usuario, llave pública/privada).
2. Presionar **"Iniciar Proxy Local"**. La app levantará el listener en `127.0.0.1:1080`.
3. Configurar el proxy HTTP/SOCKS5 en la red Wi-Fi del iPhone apuntando a `127.0.0.1:1080` para enrutar el tráfico de Safari a través del túnel SSH autenticado.
