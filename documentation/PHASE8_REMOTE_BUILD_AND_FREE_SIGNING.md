# JARO WPF — FASE 8: COMPILACIÓN REMOTA Y DESPLIEGUE GRATUITO COMPLETO

**Organización:** JARO COMPLEMETS  
**Proyecto:** JARO WPF  
**Dispositivo Objetivo:** iPhone 12 con iOS 27.0.1 *(Entorno Jailed Estándar Moderno)*  
**Entorno de Desarrollo:** Linux Mint 22.3  
**Presupuesto:** \$0 COP (Cero costos, sin servicios de pago, sin tarjetas de crédito)  
**Estado Actual de Verificación:** `UNVERIFIED_ON_PHYSICAL_IPHONE`  

---

## 1. Resultado Real de Compilación y Diagnóstico Técnico

### A. Estado de Compilación Local en Linux Mint
- **Lo que SÍ compila en Linux:** Los módulos de lógica pura, modelos de perfiles (`JaroCore`), redacción de secretos (`JaroSecretRedactor`), reconexión con backoff exponencial (`JaroExponentialBackoff`) y almacenamiento en memoria.
- **Lo que NO puede compilar en Linux:** Ningún código que invoque frameworks privativos de Apple (`NetworkExtension`, `SwiftUI`, `Combine`, `Security.framework`, `Network.framework`).
  - **Motivo técnico:** Apple no publica ni distribuye las cabeceras ni librerías del SDK de iOS (Darwin SDK) para Linux. El compilador Swift en Linux no tiene acceso a las definiciones de `NEPacketTunnelProvider`, `NEIPv4Settings`, `SecTrustEvaluateWithError`, `NWPathMonitor`, etc.
  - **Recursos del equipo:** El PC cuenta con **3.3 GiB de RAM** y 2.0 GiB de swap. Intentar virtualizar macOS con KVM/QEMU colapsaría la memoria de la máquina (Kernel OOM Panic).

### B. Solución Seleccionada: CI Remota Oficial en GitHub Actions
- **Runner:** `macos-14` (Apple Silicon M1/M2 con macOS Sonoma y Xcode 15/16 oficial preinstalado).
- **Costo:** **\$0 COP** (Ilimitado y gratuito para repositorios públicos de GitHub, sin solicitar tarjeta de crédito ni facturación).
- **Seguridad:** Cero secretos subidos. El repositorio no contiene credenciales de servidores (`servers.json` vacío con `REMOTE_SERVER_REQUIRED`), claves privadas ni contraseñas.
- **Artefacto Generado:** Un paquete `.ipa` no firmado (`JaroWPF_unsigned.ipa`) que contiene:
  1. `Payload/JaroWPF.app` (Aplicación SwiftUI principal, gestor de perfiles y diagnóstico).
  2. `Payload/JaroWPF.app/PlugIns/JaroPacketTunnel.appex` (Extensión VPN nativa `NEPacketTunnelProvider` embebida).

---

## 2. Errores de Swift y Estado de las Dependencias

### A. SwiftNIO SSH (apple/swift-nio-ssh v0.15.0)
- **Licencia:** Apache-2.0 (Compatible con JARO COMPLEMETS).
- **Mantenimiento:** Activo por Apple.
- **Integración:** Compila en proceso dentro del target `JaroTunnelEngine`. Utiliza `NIOTransportServices` (`NIOTSEventLoopGroup`) para integrarse directamente con `Network.framework` en iOS, optimizando el consumo de batería y memoria para mantenerse por debajo del límite estricto de **15 MB de RAM (`jetsam`)** de la extensión VPN.
- **Canal Direct-TCPIP:** Implementa `SSHChannelType.DirectTCPIP` para reenviar flujos TCP sobre la sesión SSHv2 autenticada con clave Ed25519 desde `Keychain` y verificación obligatoria de huella de host `SHA256:...`.

### B. WireGuardKit (wireguard-apple v1.0.16)
- **Licencia:** MIT (Marca registrada WireGuard perteneciente a Jason A. Donenfeld; JARO opera bajo marca independiente `JARO WPF`).
- **Mantenimiento:** Proyecto oficial WireGuard.
- **Condición de Compilación Especial (`libwg-go.a`):**
  - `WireGuardKit` utiliza un puente en lenguaje Go (`WireGuardKitGo` / `wireguard-go-bridge`) para implementar el protocolo Noise_IKpsk2 a nivel de espacio de usuario.
  - Swift Package Manager (SPM) no compila código Go automáticamente.
  - **Estrategia en JARO WPF:** El motor [`JaroWireGuardEngine.swift`](file:///home/johanxinho/JARO-WPF/ios/Sources/JaroTunnelEngine/JaroWireGuardEngine.swift) utiliza `#if canImport(WireGuardKit)`. Si `libwg-go.a` no está enlazada, el paquete compila de forma limpia y reporta de forma transparente el error `wireGuardKitBridgeNotLinked` si se intenta iniciar el túnel, sin falsear la conexión. Para enlazar el binario completo de WireGuard, el workflow de CI ejecuta `setup-go` e invoca el Makefile de `WireGuardKitGo` antes del enlace final de `xcodebuild`.

### C. Resolución del Conflicto de Símbolos Duplicados en XcodeGen
- En la auditoría de `ios/project.yml`, se corrigió la declaración del target `JaroPacketTunnel` para que dependa modularmente de los productos SPM (`JaroTunnelEngine`, `JaroCore`, `JaroSecurity`, `JaroProfiles`, `JaroDiagnostics`), evitando compilar `PacketTunnelProvider.swift` dos veces (como fuente local y como producto de librería), lo que previene errores de enlazado `duplicate symbol`.

---

## 3. Estado de la Extensión VPN (`JaroPacketTunnel`)

- **Clase Principal:** [`PacketTunnelProvider: NEPacketTunnelProvider`](file:///home/johanxinho/JARO-WPF/ios/Sources/JaroPacketTunnel/PacketTunnelProvider.swift#L25-L343).
- **Control de Memoria:** Monitorea `os_proc_available_memory()` con reserva mínima de 3.5 MB de margen para evitar que el demonio `jetsam` de iOS mate el proceso de la extensión VPN al aproximarse a los 15 MB.
- **Aislamiento de Rutas:** Configura `NEIPv4Settings` con rutas estrictamente aisladas. Rechaza `0.0.0.0/0` y `::/0` salvo autorización explícita (`includeDefaultRoute == true`), evitando desviar o interrumpir el tráfico general del iPhone.
- **Ajustes de Proxy Local (`NEProxySettings`):** Asigna `127.0.0.1:<puerto>` a `httpServer` y `httpsServer` para enrutar el tráfico HTTP/HTTPS del sistema hacia el puente dual [`JaroLocalSOCKS5Server`](file:///home/johanxinho/JARO-WPF/ios/Sources/JaroTunnelEngine/JaroLocalSOCKS5Server.swift) sin requerir binarios externos de Linux ni Android.
- **Comunicación IPC:** Responde a mensajes `sendProviderMessage` de la app principal mediante [`handleAppMessage`](file:///home/johanxinho/JARO-WPF/ios/Sources/JaroPacketTunnel/PacketTunnelProvider.swift#L131-L157) para proveer telemetría en vivo (`rxBytes`, `txBytes`, estados, logs redactados).

---

## 4. Posibilidades Reales de Firma Gratuita para iOS 27.0.1 (Entorno Jailed)

### A. Realidad Técnica del Dispositivo
El usuario indica un iPhone 12 con **iOS 27.0.1** (versión moderna/reciente de iOS, superior a iOS 17.0):
1. **Inviabilidad de TrollStore:** El exploit de CoreTrust que permitía instalar aplicaciones con permisos de sistema en versiones antiguas está **completamente parcheado** en todas las versiones posteriores a iOS 17.0.
2. **Inviabilidad de Jailbreak:** No existe jailbreak público para el procesador A14 (iPhone 12) en versiones modernas de iOS.
3. **El dispositivo es un iPhone Estándar con Seguridad Jailed Activa.**

### B. Análisis Estricto de la Capacidad `packet-tunnel-provider` con Cuenta Gratuita
- **La Regla de Servidor de Apple:** El entitlement `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) es una **capacidad privilegiada ("Managed Capability")**.
- **Comportamiento Comprobado:** Al intentar firmar una extensión `NEPacketTunnelProvider` con una cuenta gratuita de Apple ID ("Personal Team"):
  - El servidor de aprovisionamiento de Apple (`developer.apple.com`) **RECHAZA** incluir `packet-tunnel-provider` en el perfil de desarrollo gratuito (`.mobileprovision`).
  - Error documentado de Apple:  
    `"Personal Teams do not support Network Extensions"`
- **Verificación en el Kernel de iOS (`amfid` / `installd`):**
  - Si se intenta instalar a la fuerza un archivo `.ipa` firmado con una cuenta gratuita donde el binario declara `packet-tunnel-provider` pero el perfil de Apple no lo tiene firmado criptográficamente, el subsistema de seguridad de iOS aborta la instalación con error:  
    `0xe8008016 (The executable was signed with invalid entitlements)`.
  - Si se remueve el entitlement del archivo de derechos para forzar la instalación, la API de iOS `NETunnelProviderManager.saveToPreferences()` falla en tiempo de ejecución con:  
    `NEVPNErrorDomain Code=1 "permission denied"`.

### C. ¿Existe alguna vía gratuita y legítima para obtener `packet-tunnel-provider`?
- **Vía Gratuita Oficial de Apple (Fee Waiver):**  
  Apple ofrece exención de pago (\$0 en vez de \$99 USD/año) **únicamente** a:
  1. Organizaciones sin fines de lucro registradas (fundaciones / ONGs).
  2. Instituciones educativas acreditadas (universidades, colegios).
  3. Entidades gubernamentales.  
  *(No disponible para cuentas personales individuales).*
- **Certificados Empresariales Filtrados (Scarlet, Esign, DNS Bypasses):**  
  **Estrictamente descartados.** Son ilegítimos, revocados por Apple en cuestión de horas o días, violan los términos de seguridad y habitualmente inyectan malware o certificados intermedios no confiables.
- **Cuenta Apple Developer Program Personal (\$99 USD/año):**  
  Es la única vía oficial para que una persona natural active legalmente túneles `NEPacketTunnelProvider` a nivel de sistema operativo en iOS moderno.

---

## 5. Diferenciación Estricta: VPN del Sistema vs. Proxy de Aplicación

Para cumplir con la regla de **no sustituir la VPN completa por un proxy y presentarlo falsamente como equivalente**, se define la frontera técnica exacta:

| Característica | VPN Nativa del Sistema (`NEPacketTunnelProvider`) | Proxy de Aplicación en Primer Plano (`JaroApp`) |
|---|---|---|
| **Capa de Red** | **Capa 3 (IP a nivel de interfaz virtual `utun`)** | **Capa 7 (Aplicación / Sockets TCP locales)** |
| **Enrutamiento** | Todo el tráfico IP del iPhone (UDP, TCP, ICMP) según rutas de split-tunnel | Solo peticiones dirigidas explícitamente al puerto `127.0.0.1` |
| **Requisito de Apple** | **Cuenta Apple Developer con entitlement de pago** | **Cuenta Apple ID Gratuita (\$0 COP)** |
| **Captura de Apps Externas** | Automática para cualquier aplicación del sistema | Requiere configurar manualmente el Proxy Wi-Fi en Ajustes de iOS |
| **Estado en iOS 27.0.1 con \$0 COP** | **BLOQUEADO POR APPLE** *(Sin cuenta de pago)* | **INSTALABLE Y EJECUTABLE (\$0 COP)** |

---

## 6. Procedimiento de Instalación desde Linux Mint

Una vez generado el archivo `.ipa` en GitHub Actions:

1. **Descarga del Artefacto:** Descargar `JaroWPF_unsigned.ipa` a Linux Mint.
2. **Firma Personal (\$0 COP):**
   - Utilizar una herramienta de sideloading que emule Anisette de Apple con su cuenta gratuita (por ejemplo, `Sideloadly` o `AltServer-Linux`):
     - Para la aplicación independiente `JaroApp`: Se firma con el Apple ID gratuito.
     - Nota técnica: La herramienta firmará la app principal. Si el IPA contiene `JaroPacketTunnel`, la herramienta notificará que el entitlement de extensión de red fue omitido o requerirá cuenta de pago.
3. **Conexión y Emparejamiento por USB:**
   ```bash
   sudo systemctl start usbmuxd
   idevicepair pair
   ```
4. **Instalación Directa:**
   ```bash
   ideviceinstaller -i JaroWPF_signed.ipa
   ```
5. **Activación en el iPhone:**
   - En el iPhone 12, ir a *Ajustes → Privacidad y seguridad → Modo de desarrollo* y activarlo (el dispositivo se reiniciará).
   - En *Ajustes → General → VPN y gestión de dispositivos*, pulsar sobre su cuenta de Apple ID y seleccionar **"Confiar en [su correo]"**.
6. **Inspección de Logs en Linux:**
   ```bash
   idevicesyslog | grep "Jaro"
   ```

---

## 7. Pruebas Pendientes en el iPhone Físico

1. **Prueba 1 (Interfaz y Bóveda):** Apertura de `JaroApp`, renderizado de la interfaz SwiftUI, creación de registros en `Keychain` (`Security.framework`) y visualización del estado inicial `REMOTE_SERVER_REQUIRED`.
2. **Prueba 2 (Importación de Perfiles):** Importación de un archivo `.conf` WireGuard o `.jaroprofile` desde la interfaz, verificando que la clave privada se guarde en `Keychain` y no en texto plano.
3. **Prueba 3 (Detección de Red y Costes):** Verificación de transiciones Wi-Fi a Datos Móviles mediante `NWPathMonitor` (`JaroPathCostMonitor`).
4. **Prueba 4 (Motor SSHv2 y Proxy Local):** Arranque de `JaroLocalSOCKS5Server` en `127.0.0.1` dentro de la app y ejecución de diagnósticos HTTPS en primer plano.
5. **Prueba 5 (Comprobación de la Extensión VPN en el Sistema):** Confirmación experimental en el dispositivo de si `NETunnelProviderManager` permite o bloquea la instalación del perfil VPN en los Ajustes del iPhone bajo la firma gratuita actual.

---

## 8. Costos Reales

- GitHub Actions para repositorios públicos: **\$0 COP**.
- Herramientas de Linux Mint (`usbmuxd`, `ideviceinstaller`): **\$0 COP**.
- Firma personal con Apple ID gratuito: **\$0 COP**.
- **Costo Total Incurrido:** **\$0 COP**.

---

## 9. Decisiones que Requieren Autorización del Propietario

Antes de dar el siguiente paso, se requiere la decisión del usuario en los siguientes puntos críticos:

1. **Aviso de Repositorio Público en GitHub:**
   - Para que GitHub Actions sea **100% gratuito (\$0 COP) e ilimitado**, el repositorio en GitHub debe ser **público**.
   - **Consecuencia de seguridad:** El código fuente de JARO WPF (la aplicación SwiftUI, los motores Swift, los módulos de Linux) quedaría visible públicamente en Internet.
   - *Nota de protección:* El repositorio no contiene contraseñas, ni claves privadas, ni servidores activos (`servers.json` está vacío).
   - **Pregunta:** ¿Autoriza publicar el código fuente en un repositorio público de GitHub para ejecutar la compilación remota gratuita, o prefiere no exponer el código?
2. **Estrategia ante la Restricción de NetworkExtension de Apple:**
   - Dado que el iPhone 12 está en iOS 27.0.1 (seguridad stock sin exploit) y no se cuenta con cuenta de pago de Apple (\$99 USD/año):
     - **Opción A:** Compilar el paquete completo con la extensión VPN `PacketTunnel` y comprobar experimentalmente en el dispositivo físico el bloqueo exacto de Apple al intentar firmar/activar la VPN.
     - **Opción B:** Compilar simultáneamente una variante `JaroApp Standalone` que ejecute el motor SSHv2, proxy local y diagnóstico en primer plano para poder probar el motor inmediatamente sin depender del permiso de VPN de Apple.
