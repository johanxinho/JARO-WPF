# JARO WPF — FASE 9: DESPLIEGUE GRATUITO Y PRUEBAS EN IPHONE 12
**Organización:** JARO COMPLEMETS  
**Proyecto:** JARO WPF  
**Fecha:** 2026-11-04  
**Entorno de desarrollo:** Linux Mint 22.3 (Kernel Linux 6.8 x86_64)  
**Dispositivo objetivo:** iPhone 12 (iOS 27.0.1 / Chip Apple A14 Bionic)  
**Presupuesto:** 0 COP (Cero pagos, sin tarjetas de crédito, sin suscripciones pagas)  
**Repositorio GitHub:** [johanxinho/JARO-WPF](https://github.com/johanxinho/JARO-WPF)  
**Artefacto objetivo:** `JaroWPF_Standalone_unsigned.ipa` (2,554,552 bytes, SHA-256: `284e1635f4e8bd3ee9d5ac7e8631b28e6aec9e70c161d91335a02a7b65c1b962`)  
**Compilación verificada:** [GitHub Actions Run 41932514935](https://github.com/johanxinho/JARO-WPF/actions/runs/41932514935) (Commit [`66829f6`](https://github.com/johanxinho/JARO-WPF/commit/66829f6))  

---

## 1. INVESTIGACIÓN DE HERRAMIENTAS DE FIRMA Y DESPLIEGUE EN LINUX MINT

Se evaluaron las herramientas disponibles en el ecosistema para sideloading e instalación en iOS desde Linux sin pagar licencias de Apple Developer (\$99 USD/año):

| Herramienta | Soporte Nativo en Linux Mint | Mecanismo de Comunicación | Compatibilidad con Apple ID Gratuito | Viabilidad Técnica Real en Linux |
| :--- | :--- | :--- | :--- | :--- |
| **Sideloadly** | **NO** (0% soporte) | No aplica (sólo Windows y macOS) | Sí (en Windows/Mac) | **Inviable en Linux.** No existe binario para Linux. Su ejecución bajo Wine falla porque Wine no tiene acceso a las bibliotecas de bajo nivel USB (`usbmuxd`). Requeriría una máquina virtual Windows completa. |
| **AltServer-Linux** (NyaMisty / AltLinux) | **SÍ** (Comunitario de código abierto) | `usbmuxd` / `libimobiledevice` | Sí (Personal Team de 7 días) | **Viable pero complejo.** Requiere ejecutar un contenedor Docker con emulación de Anisette (`open-anisette-server`) para generar cabeceras ADI de Apple. Exige renovación cada 7 días manteniendo el iPhone conectado o en la misma red local que la PC. |
| **SideStore + iloader** (Recomendado oficial) | **SÍ** (Oficial SideStore via `iloader` AppImage) | `usbmuxd` / `libimobiledevice` | Sí (Personal Team de 7 días) | **Altamente viable y autónomo.** `iloader` (AppImage para Linux x86_64) realiza la instalación inicial del instalador SideStore vía USB. Posteriormente, la renovación de la app se hace **directamente en el iPhone** mediante un bucle local VPN (WireGuard/LocalDevVPN), sin necesidad de PC. |
| **`zsign` + `ideviceinstaller`** | **SÍ** (CLI nativo en Linux) | `usbmuxd` vía socket `/var/run/usbmuxd` | Requiere `.p12` y `.mobileprovision` ya existentes | **Viable para firma offline.** `zsign` no contacta los servidores de Apple ni genera certificados por sí mismo; solo firma el IPA si el usuario ya dispone de un certificado `.p12` y un perfil de aprovisionamiento emitido por Apple. |

---

## 2. REQUISITOS REALES DE INSTALACIÓN Y RENOVACIÓN

### A. Límites impuestos por Apple en cuentas gratuitas (Personal Team)
Apple restringe severamente las cuentas gratuitas de Apple ID bajo las siguientes condiciones innegociables:
1. **Caducidad del certificado:** Los certificados de desarrollo personal expiran exactamente a los **7 días** de ser emitidos.
2. **Límite de aplicaciones activas:** Máximo **3 aplicaciones sideloaded** activas simultáneamente por dispositivo.
3. **Límite de App IDs:** Máximo **10 App IDs** registrados por cuenta cada 7 días.
4. **Exclusión de NetworkExtension:** Las cuentas gratuitas **NO** tienen derecho a la capacidad `packet-tunnel-provider`. Esta es la razón técnica estricta por la cual se desarrolló y compiló la **Variante B (Standalone)**.

### B. Proceso de renovación periódica
- **Con AltServer-Linux:** El iPhone debe conectarse por cable USB o compartir red local con Linux Mint cada 7 días para refrescar la firma.
- **Con SideStore:** El iPhone renueva el certificado y el perfil de forma autónoma desde el propio dispositivo conectándose a los servidores de Apple mediante su proxy local Anisette y LocalDevVPN.

---

## 3. OBTENCIÓN LEGÍTIMA DE CERTIFICADOS DE DESARROLLO DESDE LINUX

### A. La barrera criptográfica de Apple: GrandSlam y Anisette
A diferencia de las cuentas de pago (que poseen claves API de App Store Connect en formato `.p8`), las cuentas gratuitas de Apple ID solo pueden obtener certificados mediante la API interna **Xcode Developer Services** (`https://developerservices2.apple.com/services/QH65B2/...`).

Para autenticar una solicitud de certificado gratuito, los servidores de Apple exigen obligatoriamente:
1. **Credenciales del Apple ID:** Correo y contraseña de la cuenta.
2. **Autenticación de dos factores (2FA):** Código de verificación de 6 dígitos enviado por Apple al dispositivo de confianza.
3. **Cabeceras Anisette (`libadi`):** Datos criptográficos de máquina (`X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-R`, `X-Apple-I-MD-LU`, `X-Apple-I-SRL-NO`) generados por binarios propietarios de Apple presentes en macOS o iTunes para Windows.

### B. Política de seguridad estricta y protección de credenciales
> [!IMPORTANT]
> **POLÍTICA DE PRIVACIDAD Y SEGURIDAD:**  
> - **Jamás compartas tu contraseña de Apple ID, código de 2FA o token de sesión con un asistente de inteligencia artificial ni en herramientas de terceros no auditadas.**  
> - El proceso de obtención de certificados debe ser ejecutado **exclusivamente por el usuario de forma directa y privada** en su propia máquina o dispositivo.  
> - No se utilizarán certificados empresariales pirateados ni exploits (como TrollStore, el cual no es compatible con iOS 27 ni con versiones recientes de iOS).

---

## 4. CONCORDANCIA TÉCNICA: BUNDLE ID, ENTITLEMENTS Y PERFIL

Antes de aplicar cualquier firma, se verificaron los metadatos de `JaroWPF_Standalone_unsigned.ipa`:

```text
Paquete: JaroWPF_Standalone_unsigned.ipa
├── Bundle ID en Info.plist: com.jarocomplements.jarowpf.standalone
├── Ejecutable: JaroWPF-Standalone (Mach-O 64-bit arm64)
├── Entitlements fuente (JaroAppStandalone.entitlements):
│   ├── keychain-access-groups: $(AppIdentifierPrefix)group.com.jarocomplements.jarowpf
│   └── com.apple.security.application-groups: group.com.jarocomplements.jarowpf
└── Permisos restringidos: ZERO (Sin com.apple.developer.networking.networkextension)
```

### Reglas de coincidencia al firmar con Apple ID Personal:
1. **Prefijo de App ID (Team ID):** Al firmar con una cuenta personal, Apple genera un identificador único de equipo de 10 caracteres (ej. `K9X2ABCD42`).
2. **Identificador de Bundle:** Si el perfil de aprovisionamiento gratuito generado por Apple asigna un identificador con comodín (`*`) o un identificador adaptado a tu cuenta (ej. `com.usuario.jarowpf.standalone`), la herramienta de firma (como SideStore o `zsign`) actualiza el `CFBundleIdentifier` del `Info.plist` para que coincida exactamente con el perfil.
3. **Grupos de aplicaciones (App Groups):** Las cuentas gratuitas no pueden aprovisionar App Groups personalizados en el portal de Apple. La herramienta de firma omite de forma segura el entitlement de App Group no aprovisionado, permitiendo que la app se instale y ejecute en su sandbox de usuario estándar sin provocar el error de instalación `0xe8008015`.

---

## 5. VALIDACIÓN DEL MOTOR SSH Y PROXY LOCAL (PRUEBAS LOCALES REALES)

Se comprobó el funcionamiento del motor SSH y el servidor dual SOCKS5 / HTTP CONNECT tanto en el núcleo Python multiplataforma como en la arquitectura Swift:

### A. Resultados del laboratorio loopback real en Linux Mint
Se ejecutó la prueba de integración contra un servidor OpenSSH (`sshd`) real unprivileged en loopback (`127.0.0.1`):
```bash
PYTHONPATH=. .venv/bin/python3 -m unittest tests.test_phase6_ios_and_crossplatform.TestPhase6DualProxyOverRealOpenSshLoopback -v
```
**Resultado:** `test_dual_socks5_and_http_connect_over_real_sshd_direct_tcpip_https` ... **OK (0.949s)**.

**Métricas verificadas en la prueba:**
1. **Autenticación SSH legítima:** Conexión mediante par de llaves Ed25519 con verificación estricta de host key (`SHA256:...`).
2. **Canal Direct-TCPIP:** Apertura de canal TCP hacia un servidor HTTPS local (`127.0.0.1`) sin requerir acceso shell ni privilegios root.
3. **Ruta A (SOCKS5 - RFC 1928):** Negociación de saludo SOCKS5 (sin autenticación `0x00`), comando Connect (`0x01`), y transferencia HTTPS TLS 1.3 verificada (`tls_verified = True`, `real_internet = True`).
4. **Ruta B (HTTP CONNECT - RFC 7231 / RFC 9110):** Negociación de encabezado `CONNECT localhost:PORT HTTP/1.1`, respuesta `200 Connection Established`, y tunelización TLS X.509 HTTPS verificada.

### B. Implementación nativa en iOS (`JaroTunnelEngine`)
- **SSHv2:** Implementado mediante `SwiftNIO SSH` (`NIOSSHHandler`). Si la lista de servidores remotos está vacía, la app reporta controladamente `REMOTE_SERVER_REQUIRED`.
- **Proxy SOCKS5 / CONNECT:** Implementado en `JaroLocalSOCKS5Server.swift`, enlaza en `127.0.0.1:1080` para servir peticiones de aplicaciones locales.

---

## 6. LIMITACIONES OPERATIVAS DEL PROXY STANDALONE EN IOS

> [!WARNING]
> **LIMITACIONES TÉCNICAS FUNDAMENTALES (NO ES UNA VPN GLOBAL):**  
> 1. **Sin interfaz de red TUN a nivel de kernel:** La variante Standalone opera en espacio de usuario (Capa 5/7). **No crea una interfaz virtual `utun`** en el kernel de iOS.
> 2. **Sin intercepción global de tráfico:** Las aplicaciones de terceros instaladas en el iPhone (redes sociales, juegos, apps bancarias, daemons del sistema) **NO** desviarán su tráfico automáticamente hacia `127.0.0.1:1080`.
> 3. **Configuración manual exclusiva para redes Wi-Fi:**
>    - En iOS, la interfaz gráfica del sistema permite configurar un proxy HTTP manual **únicamente dentro de los ajustes de una red Wi-Fi específica** (*Ajustes -> Wi-Fi -> [Nombre de red] -> Configurar proxy -> Manual*).
>    - **En redes móviles (Datos Celulares / 4G / 5G / Tigo Colombia), iOS NO proporciona una interfaz gráfica para configurar un proxy HTTP/SOCKS5 manual.** Para enrutar tráfico celular sin VPN L3 se requiere soporte interno en la aplicación cliente o un perfil APN/PAC corporativo.
> 4. **Suspensión en segundo plano por Jetsam:** Al no ser una extensión del sistema NetworkExtension, iOS suspenderá el proceso de la app aproximadamente 30 segundos después de pasar a segundo plano, a menos que el usuario mantenga la app en pantalla o interactúe con ella.

---

## 7. PROCEDIMIENTO DETALLADO DE DESPLIEGUE EN IPHONE 12 ($0 COP)

### Requisitos previos en Linux Mint:
Verificar que las utilidades USB estén instaladas y operativas:
```bash
which idevicepair ideviceinfo usbmuxd
```
Salida verificada en el sistema:
- `/usr/bin/idevicepair` (Versión 1.3.0)
- `/usr/bin/ideviceinfo` (Versión 1.3.0)
- `/usr/sbin/usbmuxd` (Versión 1.1.1)

---

### Procedimiento Oficial Recomendado: Despliegue mediante SideStore + iloader

Este método es el estándar actual para Linux documentado por el equipo de SideStore:

#### Paso 1: Conexión física y emparejamiento USB
1. Conectar el iPhone 12 mediante cable USB al ordenador con Linux Mint.
2. Desbloquear el iPhone y pulsar **"Confiar en este ordenador"**, introduciendo el código de desbloqueo.
3. En la terminal de Linux Mint, verificar el emparejamiento:
   ```bash
   idevicepair pair
   ```
   Debe responder: `SUCCESS: Paired with device <UDID>`.
4. Comprobar la detección del dispositivo:
   ```bash
   ideviceinfo -k DeviceName -k ProductType -k ProductVersion
   ```

#### Paso 2: Descarga de `iloader` (Herramienta oficial de sideloading para Linux)
1. Descargar el ejecutable AppImage oficial de `iloader` para Linux x86_64:
   ```bash
   curl -fsSLO https://github.com/nab138/iloader/releases/latest/download/iloader-linux-amd64.AppImage
   chmod +x iloader-linux-amd64.AppImage
   ```
2. Ejecutar la aplicación en Linux Mint:
   ```bash
   ./iloader-linux-amd64.AppImage
   ```

#### Paso 3: Instalación de SideStore en el iPhone
1. En la interfaz gráfica de `iloader`, iniciar sesión con tu cuenta personal de Apple ID y contraseña (proceso local en tu máquina; ingresa el código 2FA cuando Apple lo solicite en tu iPhone).
2. Seleccionar el iPhone 12 detectado en la lista.
3. Hacer clic en **"Install SideStore"**. La herramienta solicitará el certificado gratuito de 7 días a Apple, firmará el paquete e instalará SideStore en tu iPhone.

#### Paso 4: Autorización en iOS y Modo de Desarrollador
1. En el iPhone, abrir **Ajustes -> General -> Gestión de VPN y dispositivos**.
2. Bajo **"App de desarrollador"**, pulsar sobre tu dirección de correo de Apple ID y seleccionar **"Confiar"**.
3. En iOS 16+, activar el modo de desarrollo:
   - Ir a **Ajustes -> Privacidad y seguridad -> Modo de desarrollador**.
   - Activar el interruptor y reiniciar el iPhone. Al reiniciar, confirmar pulsando **"Activar"** e ingresar el código.

#### Paso 5: Instalación y firma de `JaroWPF_Standalone_unsigned.ipa`
1. Transferir el archivo `JaroWPF_Standalone_unsigned.ipa` descargado en Linux Mint hacia el iPhone (mediante almacenamiento local, nube personal o navegador).
2. Abrir la app **SideStore** en el iPhone (asegurarse de que el perfil local de SideStore esté activo).
3. Ir a la pestaña **"My Apps"**, presionar el botón **"+"** en la esquina superior y seleccionar `JaroWPF_Standalone_unsigned.ipa`.
4. SideStore firmará el binario localmente con tu certificado gratuito de 7 días y lo instalará en el sistema operativo.
5. El icono de **JARO WPF** aparecerá en la pantalla de inicio de tu iPhone 12 listo para abrir.

---

### Prueba Operativa en el iPhone 12:
1. Abrir la aplicación **JARO WPF** en el iPhone 12.
2. Ingresar la configuración de un servidor SSH propio autorizado (Host, Puerto, Usuario, Llave privada en formato compatible). Si no se ingresa un servidor, la app mantendrá su estado seguro `REMOTE_SERVER_REQUIRED`.
3. Activar el interruptor del **Proxy Local** para iniciar el listener en `127.0.0.1:1080`.
4. Conectar el iPhone a tu red Wi-Fi local, entrar a los ajustes de la red Wi-Fi, seleccionar **Configurar Proxy -> Manual**, colocar Servidor `127.0.0.1` y Puerto `1080`.
5. Abrir Safari en el iPhone y verificar la navegación a través del túnel SSH autenticado.
