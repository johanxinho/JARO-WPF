# JARO WPF — Arquitectura Nativa iOS (`Swift 5.9+` / `NetworkExtension`)

**Organización:** JARO COMPLEMETS  
**Proyecto:** JARO WPF — Fase 6 (`Native iOS Tunnel Engine`)  
**Estado en dispositivo físico:** `UNVERIFIED_ON_PHYSICAL_IPHONE` (arquitectura modular Swift completa, validada estáticamente y en protocolos cruzados desde Linux; pendiente de compilación en macOS + Xcode y prueba en iPhone físico).

## 1. Separación Modular (`ios/`)

| Módulo | Ruta | Responsabilidad |
|---|---|---|
| `JaroCore` | `Sources/JaroCore/` | Modelos `.jaroprofile` v1.0, estados (`REMOTE_SERVER_REQUIRED`), redactor de secretos, ring buffer acotado (`< 15 MB`), reconector con backoff exponencial y circuit breaker. |
| `JaroSecurity` | `Sources/JaroSecurity/` | Bóveda `Keychain` (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, grupo compartido `group.com.jarocomplements.jarowpf`), validadores Curve25519, huella OpenSSH `SHA256:...` y evaluador X.509 estricto (`SecTrustEvaluateWithError`). |
| `JaroProfiles` | `Sources/JaroProfiles/` | Importación/exportación de `.jaroprofile` v1.0 e importador seguro de `.conf` WireGuard que extrae claves privadas directamente al `Keychain` y bloquea rutas globales (`0.0.0.0/0`, `::/0`) por defecto. |
| `JaroTunnelEngine` | `Sources/JaroTunnelEngine/` | `JaroWireGuardEngine` (`WireGuardKit`), `JaroNativeSSHEngine` (`SwiftNIO SSH` `0.15.0` con `DirectTCPIP`) y `JaroLocalSOCKS5Server` (puente dual `SOCKS5` RFC 1928 + `HTTP CONNECT` RFC 9110 en `127.0.0.1`). |
| `JaroDiagnostics` | `Sources/JaroDiagnostics/` | `JaroPathCostMonitor` (`NWPathMonitor` sin asumir que Wi-Fi es gratuito) y `JaroHTTPSEgressDiagnostic` (sonda HTTPS X.509 acotada a `<= 8 KB` a través del túnel con detección de portal cautivo). |
| `JaroPacketTunnel` | `Sources/JaroPacketTunnel/` | Extensión del sistema `PacketTunnelProvider` (`NEPacketTunnelProvider`), aislamiento de rutas (`NEIPv4Settings`), proxy del sistema (`NEProxySettings`), vigilancia de memoria `os_proc_available_memory()` (`<= 15 MB`) e IPC JSON (`handleAppMessage`). |
| `JaroApp` | `Sources/JaroApp/` | Interfaz `SwiftUI`, controlador `NETunnelProviderManager`, importador de perfiles, visor de telemetría `RX`/`TX` y aviso informativo que separa el transporte cifrado sobre internet activo de los canales sin saldo de operadores móviles (Tigo Colombia). |

## 2. Dependencias Auditadas y Licencias

| Paquete | Versión | Licencia | Mantenimiento | Uso en JARO iOS |
|---|---|---|---|---|
| `apple/swift-nio` | `2.65.0+` | `Apache-2.0` | Activo (Apple) | EventLoop y `ByteBuffer` de baja huella de RAM. |
| `apple/swift-nio-transport-services` | `1.21.0+` | `Apache-2.0` | Activo (Apple) | Integración nativa con `Network.framework` en iOS. |
| `apple/swift-nio-ssh` | `0.15.0+` | `Apache-2.0` | Activo (Apple) | Cliente SSHv2 en proceso (`DirectTCPIP`) sin ejecutar binarios externos prohibidos por el sandbox de iOS. |
| `apple/swift-crypto` | `3.4.0+` | `Apache-2.0` | Activo (Apple) | Claves `Ed25519` / `P-256` y huellas `SHA256` de host keys. |
| `WireGuardKit` (`wireguard-apple`) | `1.0.16+` | `MIT` *(marca registrada WireGuard de J. A. Donenfeld; JARO usa marca propia)* | Oficial WireGuard | `WireGuardAdapter`, configuración `utun` y estadísticas UAPI (`rx_bytes`/`tx_bytes`). |

## 3. Compilación en macOS con Xcode

1. Instalar en macOS **Xcode 15.4+** (Swift 5.9+), **Go 1.21+** (`brew install go`) y opcionalmente **XcodeGen** (`brew install xcodegen`).
2. Generar el proyecto Xcode desde `ios/`:
   ```bash
   xcodegen generate
   ```
3. Para pruebas puras de paquetes Swift sin enlazar aún el puente Go de WireGuard:
   ```bash
   swift test
   ```
4. Para activar el motor completo `WireGuardKit` en el target `JaroPacketTunnel`:
   - Configurar el target de tipo *External Build System* (`WireGuardGoBridgeiOS`, `/usr/bin/make`, `SDKROOT = iphoneos`) que compila `libwg-go.a` desde `WireGuardKitGo`.
   - Definir `JARO_ENABLE_WIREGUARDKIT=1` en el entorno al resolver paquetes en Xcode.
   - Firmar ambos targets (`com.jarocomplements.jarowpf` y `com.jarocomplements.jarowpf.PacketTunnel`) con una cuenta **Apple Developer Program** que posea el entitlement `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) y el App Group `group.com.jarocomplements.jarowpf`.
