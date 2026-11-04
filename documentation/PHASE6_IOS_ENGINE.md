# JARO WPF — FASE 6: NATIVE IOS TUNNEL ENGINE & CROSS-PLATFORM INFRASTRUCTURE

**Organización:** JARO COMPLEMETS  
**Proyecto:** JARO WPF  
**Estado de Verificación en Hardware iPhone:** `UNVERIFIED_ON_PHYSICAL_IPHONE` *(nunca declarar funcional en iPhone físico hasta compilar en Xcode sobre macOS e instalar en hardware real con provisioning `packet-tunnel-provider`)*.

---

## 1. Resumen Arquitectónico

La Fase 6 extiende el núcleo validado en Linux (Fases 1–5) hacia una arquitectura nativa para **iOS 16.0+** escrita íntegramente en **Swift 5.9+**, preservando el núcleo Python en Linux y añadiendo adaptadores limpios para **Windows 10/11**:

1. **iOS Nativo (`ios/`)**:
   - Sin binarios de Linux ni ejecutables Android; todo corre en proceso respetando el sandbox de iOS y el techo de **`15 MB` de RAM (`jetsam`)** de `NEPacketTunnelProvider`.
   - **Puente Dual `SOCKS5` + `HTTP CONNECT` (`JaroLocalSOCKS5Server.swift` y `core/protocols/dual_proxy_bridge.py`)**: dado que `NEProxySettings` en iOS enruta tráfico HTTPS del sistema mediante `HTTP CONNECT` (`httpsServer`) mientras clientes internos hablan `SOCKS5` (RFC 1928), el listener local en `127.0.0.1:<port>` inspecciona el primer byte (`0x05` vs `'C'`) y multiplexa ambos flujos sobre canales `SSHChannelType.DirectTCPIP` de `SwiftNIO SSH`.
2. **Esquema Portable `.jaroprofile` v1.0 (`core/profiles/jaro_profile_manager.py` $\leftrightarrow$ `JaroProfileManager.swift`)**:
   - Cero claves privadas ni contraseñas en JSON; sólo referencias `keychain://group.com.jarocomplements.jarowpf/...`.
   - Aislamiento estricto de rutas (`include_default_route = false` por defecto; rechaza `0.0.0.0/0` y `::/0` sin autorización explícita).
   - Registros remotos vacíos por defecto: devuelve explícitamente `REMOTE_SERVER_REQUIRED` (jamás `SUCCESS`).
3. **Adaptadores Windows (`core/platform/windows_tunnel_adapter.py`)**:
   - `WindowsOpenSshAdapter` (`System32\OpenSSH\ssh.exe`, `CREATE_NEW_PROCESS_GROUP`, auditoría NTFS `icacls`).
   - `WindowsWireGuardServiceAdapter` (`wireguard.exe /installtunnelservice` protegido por `PrivilegePolicyGate`, cero elevación UAC automática, parser JSON de `Get-NetRoute` compatible con `verify_route_isolation()`).

---

## 2. Procedimiento Seguro para Agregar un Servidor Propio Autorizado

Cuando disponga de un servidor propio o autorizado (VPS Linux con OpenSSH o WireGuard):

1. **Nunca almacene claves privadas dentro de `configs/servers.json` ni en archivos `.jaroprofile`**.
2. **Para WireGuard**:
   - Genere el par de claves localmente (`wg genkey | tee client.key | wg pubkey > client.pub` o desde la app iOS).
   - Configure en el servidor autorizado un bloque `[Peer]` con su `PublicKey` y rutas específicas (evite `0.0.0.0/0` salvo que desee túnel completo explícito).
   - En Linux/Windows use `JaroProfileManager.import_wireguard_conf_text(..., authorized=True)` (guarda el `.wg.conf` en bóveda `0o600` y exporta un `.jaroprofile` limpio); en iOS use **Importar `.conf`** en `JaroMainView` (almacena `PrivateKey` directamente en `Keychain` con `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
3. **Para SSH/SOCKS5**:
   - Obtenga fuera de banda la huella real del servidor ejecutando en el propio servidor: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
   - Registre `pinned_hostkey_sha256 = "SHA256:..."` en el `.jaroprofile` y cargue la semilla `Ed25519` de cliente en `Keychain` (iOS) o archivo `0o600` (Linux/Windows).
   - Ejecute siempre el diagnóstico **Verificar Salida HTTPS Real por el Túnel** antes de considerar operativo el servidor.

---

## 3. Separación Estricta frente a Operadores Móviles (Tigo Colombia)

Tal como documenta [`TIGO_COLOMBIA_OFFICIAL_RESEARCH.md`](./TIGO_COLOMBIA_OFFICIAL_RESEARCH.md), los canales sin saldo de Tigo Colombia están limitados a portales oficiales de autogestión y recarga del operador. Tanto el núcleo multiplataforma como `JaroApp` en iOS separan estrictamente los motores de túnel cifrado (que requieren conectividad IP legítima autorizada) de la información de canales gratuitos oficiales del operador, sin implementar evasión de cobro, inyección de cabeceras ni suplantación de SNI/dominios.
