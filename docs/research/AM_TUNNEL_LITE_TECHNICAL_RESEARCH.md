# Investigación técnica integral — AM TUNNEL LITE y JARO WPF

Fecha: 6 de noviembre de 2026 · Rama: `fix/jaro-functional-hardening` · Commit base: `b472c2b`
Naturaleza: **fase exclusivamente de investigación**. No se modificó código fuente, ni configuraciones, ni servidores, ni `main`.

## 1. Resumen ejecutivo

- **AM TUNNEL LITE VPN** (id. Android `app.vpn.amtunnellite`, también publicado como `am tunnel lite` en App Store) es una VPN gratuita de un solo botón desarrollada por **APNA SOFTWARE (SMC-PRIVATE) LIMITED** (Karachi, Pakistán), con más de 10 millones de descargas y actualización publicada el 1 de octubre de 2026 (ficha oficial de Google Play).
- Su modo "configuración automática" es coherente con una arquitectura de **servidores remotos del desarrollador + perfiles predefinidos descargados/embebidos**: el usuario no introduce servidores propios (ficha oficial: "Not need any configuration, just simply click one button").
- El changelog oficial menciona "added new protocol" y "Added v2Pdr"; fuentes comunitarias secundarias (no verificables de forma independiente) mencionan modos **UDP y FastDNS** y selección de protocolos. La lista completa (Direct, HTTP, SSL, SSL Proxy, UDPQ, Shadowsocks, WebSocket, CloudFront) **no está confirmada** para la versión instalada por el usuario: es un patrón conocido de la familia de apps "túnel/injector", no una evidencia sobre esta versión.
- El comportamiento observado por el usuario ("conecta sin saldo ni paquete de datos") **solo es posible si el operador entrega alguna conectividad IP** (al menos DNS y algunos destinos autorizados por el operador). Tigo Colombia ha ofrecido oficialmente **zero-rating por servicio** (WhatsApp/Instagram/Facebook), lo que demuestra que el operador clasifica tráfico por destino. Una VPN **no puede funcionar si el operador no proporciona ninguna conectividad IP**.
- JARO WPF debe **distinguir tres estados** (túnel conectado / Internet disponible / acceso autorizado a un servicio) y **no implementará** mecanismos para disfrazar tráfico ni eludir cobros o restricciones del operador.
- Auditoría del repositorio (commit `b472c2b`): iOS con WireGuardKit real (variante Full) y SSH/SOCKS5 como proxy TCP (Standalone), 100 pruebas Python, diagnósticos por evidencia; **Android no existe todavía en el repositorio**.

## 2. Fuentes consultadas

| # | Fuente | Qué aporta | Calidad |
|---|---|---|---|
| F1 | [Ficha oficial Google Play](https://play.google.com/store/apps/details?id=app.vpn.amtunnellite) (consultada 2026-11-06) | Desarrollador, changelog, política de datos declarada, sitio oficial, apps hermanas | Primaria |
| F2 | [Sitio del desarrollador](http://antunnellite.blogspot.com/) | Blog oficial; un único post genérico de 2022 | Primaria (pobre) |
| F3 | [Política de privacidad declarada](https://rozarvpn.xyz/user/privacy_pub) y correo de soporte en F1 | Dominio de infraestructura del desarrollador | Primaria (no auditada aquí) |
| F4 | [AM Tunnel Lite en App Store](https://apps.apple.com/us/app/am-tunnel-lite/id6741327105) | Existencia de variante iOS | Primaria |
| F5 | [Tigo: cambios al beneficio de redes sociales](https://ayuda.tigo.com.co/hc/centro-de-ayuda/articles/1729094184-cambios-en-el-beneficio-de-redes-sociales-planes-moviles-movil) | Zero-rating oficial por servicio (WhatsApp/Instagram/Facebook), vigencia y cambios desde 2023 | Primaria (operador) |
| F6 | [Documentación oficial Android VpnService](https://developer.android.com/reference/android/net/VpnService) y [guía VPN](https://developer.android.com/guide/topics/connectivity/vpn) | Modelo de VPN en Android (consentimiento, interfaz TUN, rutas) | Primaria (plataforma) |
| F7 | Referencias comunitarias secundarias (grupos/tutoriales que mencionan "UDP", "FastDNS", "protocol selection" en AM Tunnel) | Indicios de modos; no verificables independientemente | Secundaria (solo hipótesis) |

## 3. Información confirmada de AM Tunnel Lite

1. **Identidad y autoría** (F1): desarrollador APNA TUNNEL / APNA SOFTWARE (SMC-PRIVATE) LIMITED, Karachi, Pakistán; categoría Herramientas; calificación 3+; anuncios incluidos.
2. **Escala y actividad** (F1): 10M+ descargas; última actualización 2026-10-01.
3. **Propuesta de uso** (F1): "no requiere configuración; un botón". Es decir, el perfil del usuario no proviene de servidores propios: hay una **selección automática de servidores/perfiles** gestionada por el desarrollador.
4. **Ecosistema de apps hermanas** (F1): APNA VPN, APNA TUNNEL LITE, AM TUNNEL PRO, XMAX VPN LITE — misma familia de producto reutilizando infraestructura.
5. **Changelog** (F1): "Increased server Speed / added new protocol / improvement in connection / Added v2Pdr". El término "v2Pdr" sugiere (hipótesis, no confirmado) un componente tipo V2Ray/VMess moderno; **no hay evidencia pública suficiente** para afirmarlo.
6. **Variante iOS existe** (F4): el desarrollador publica también en iOS, lo que implica uso de NEVPNManager/PacketTunnel o un producto proxy en iOS.
7. **Declaración de privacidad** (F1): "no se comparte datos con terceros; no se recopilan datos; cifrado en tránsito" — es una **autodeclaración** no verificable.
8. **Zero-rating en Tigo Colombia** (F5): el operador ha tenido oficialmente beneficios de uso sin consumo de datos por servicio (redes sociales), posteriormente reconfigurado (2023: uso ilimitado de las redes sociales aunque se agoten las gigas del plan). Esto demuestra **control por destino en la red móvil**.

## 4. Información desconocida (no asumir como verdad)

- Qué protocolos **exactos** expone la versión instalada (Direct, HTTP, SSL, SSL Proxy, UDPQ, Shadowsocks, WebSocket): **no confirmado**; solo menciones comunitarias (F7).
- Qué servidores y endpoints usa la configuración automática, y cómo se actualizan (embebidos vs. descargados): **no confirmado**.
- El significado exacto del perfil "B - GLOBAL 11" observado por el usuario: **no confirmado**. Es coherente con identificadores de lista de servidores/perfiles remotos, pero es una hipótesis.
- Por qué conecta "sin saldo" en el caso particular del usuario: **no confirmado**. Hipótesis técnica documentada en §6.
- Qué datos recopila realmente el desarrollador (la autodeclaración de Play no es auditable desde fuentes públicas).

## 5. Análisis de protocolos (estado por término)

| Término | Estado | Comentario |
|---|---|---|
| Direct | No confirmado | Etiqueta típica de conexión directa a servidor del desarrollador |
| HTTP | Parcialmente confirmado | Familia de apps usa túneles HTTP CONNECT; sin evidencia específica de esta versión |
| SSL / SSL Proxy | Parcialmente confirmado | Túnel TLS hacia un endpoint del desarrollador; mencionado en tutoriales de la familia |
| UDPQ | No confirmado | Modo UDP descrito por la comunidad (F7); sin fuente primaria |
| Shadowsocks | No confirmado | Mencionado en ecosistemas similares; sin evidencia de esta versión |
| WebSocket | No confirmado | Patrón habitual para atravesar proxies/CDN; sin evidencia específica |
| CloudFront | No confirmado | Posible uso de CDN como front door; **no se investigarán endpoints ni payloads** |
| Configuración automática | Confirmado como producto | F1: un botón, sin configuración del usuario |
| Selección automática de servidores | Confirmado como producto | Coherente con perfiles remotos (p. ej. "B - GLOBAL 11"); mecánica interna desconocida |
| DNS | Parcialmente confirmado | F7 menciona "FastDNS" y ajustes de DNS privado del sistema |

Nota de alcance: conforme a las reglas del proyecto, **no se buscaron hosts, payloads ni endpoints privados** y no se desarrollará nada destinado a evadir el cobro de datos.

## 6. Análisis de conectividad móvil (Tigo Colombia)

Estados distintos que conviene no confundir:

1. **Conexión de radio móvil** (RRC/registro en la red): puede existir sin sesión de datos (voz/SMS). No implica IP.
2. **Sesión de datos (PDP context/AN session)**: el operador asigna una dirección IP (IPv4 y/o IPv6) aunque no haya saldo. Muchos operadores mantienen la sesión con **jaula de facturación** (walled garden): solo alcanza el portal del operador, su DNS y ciertos destinos.
3. **Acceso a servicios sin descontar datos** (zero-rating): el operador permite tráfico hacia destinos autorizados sin cobro (F5 confirma el modelo en Tigo). La clasificación es del operador (DPI/allowlist).
4. **VPN conectada**: un túnel IP hacia un servidor del proveedor **sobre** la conectividad subyacente. En Android, VpnService crea una interfaz TUN y enruta el tráfico a través de ella (F6); el tráfico del túnel mismo viaja por la red subyacente.
5. **IPv4 / IPv6**: pueden estar disponibles por separado (una sola familia o ambas). Un túnel dual-stack requiere conectividad dual-stack subyacente o encapsulación.
6. **DNS funcional**: resolver consultas (del operador o privado). Sin DNS, muchas apps fallan aunque haya ruta IP.
7. **Internet completo**: cualquier destino alcanzable; es el estado que la facturación controla.

**Respuesta a la pregunta clave**: una VPN **no puede funcionar cuando el operador no proporciona ninguna conectividad IP al dispositivo**. Si AM Tunnel Lite "conecta sin saldo", la explicación técnica necesaria es que el operador **sí entrega conectividad IP limitada** (al menos DNS y un conjunto de destinos), y que el servidor del túnel es alcanzable dentro de ese conjunto o del esquema de zero-rating vigente. Esto es una hipótesis coherente con F5 y con la arquitectura de estos productos; **verificarla requeriría mediciones en el dispositivo**, y de ninguna manera JARO WPF construirá mecanismos para explotar esa situación.

## 7. Auditoría del estado actual de JARO WPF (rama `fix/jaro-functional-hardening`, commit `b472c2b`)

Verificado sobre archivos y commits reales (no solo documentación):

| Área | Estado real |
|---|---|
| Arquitectura | Core Python multiplataforma + iOS (Swift Package, XcodeGen) con dos variantes compiladas en CI |
| Android | **No implementado** (no hay código Android en el repositorio) |
| iOS | Sí: app + Packet Tunnel Provider (variante Full); Standalone sin VPN de sistema |
| WireGuardKit | Integrado en Full: `libwg-go.a`, DNS/MTU/direcciones multi-AF, keepalive; parseo UAPI por peer |
| PacketTunnelProvider | Ciclo de vida implementado; diagnósticos con evidencia (handshake ≤180 s por PublicKey, deltas RX/TX, IP literal cubierta por AllowedIPs) |
| SSH | Proxy TCP (SSHv2 → SOCKS5/HTTP CONNECT) en ambas variantes; **no** se presenta como VPN IP |
| DNS | `DNS=` conservado de extremo a extremo; diagnóstico getaddrinfo con deltas; consentimiento para override |
| IPv4/IPv6 | Validación dual-stack para full tunnel (canonical `0.0.0.0/0 + ::/0`); rutas por perfil |
| Full/split tunnel | Full solo con consentimiento explícito + `includeAllNetworks`; split por AllowedIPs |
| Perfiles | Importador/serializador estricto (directivas conocidas, un peer, claves validadas); kit VPS para servidor propio |
| Diagnósticos | HTTPS con URL del usuario (sin sondas públicas por defecto), DNS, handshake, RX/TX |
| Pruebas | 100 Python OK + XCTest en CI (runs 42255352726 y 42255426937) |
| Funciones solo visuales | Ninguna identificada en el flujo principal tras las fases 1–4; persisten límites externos |
| Pendientes | Firma Apple (Network Extensions requiere equipo de pago), conexión real no verificada, Android inexistente |
| Seguridad | Sin secretos en repo (verificado por tests), claves por archivo 0600, consentimientos explícitos |

## 8. Tabla comparativa

Estados: **Confirmado** / **Parcialmente confirmado** / **No confirmado** / **No implementado** / **No aplicable**.

| Característica | AM Tunnel Lite | JARO WPF | Estado |
|---|---|---|---|
| Conexión automática | Confirmado como producto (F1) | Requiere perfil propio del usuario | No aplicable a JARO (diseño) |
| Selección de servidor | Confirmado como producto; mecánica desconocida | Lista de servidores autorizados por el usuario (`configs/servers.json` vacío por diseño) | Parcialmente confirmado |
| WireGuard | No confirmado | Integrado (Full) y compilado en CI | JARO: Confirmado (compilación); conexión real pendiente |
| SSH | No confirmado | Proxy TCP SSHv2+SOCKS5 verificado en pruebas | JARO: Confirmado |
| TLS | No confirmado | HTTPS/DoT/DoQ en diagnóstico y egress local verificados | JARO: Confirmado (local) |
| Shadowsocks | No confirmado | No implementado | No implementado |
| DNS | Parcialmente confirmado (F7) | Extremo a extremo + diagnóstico | JARO: Confirmado |
| IPv4 | No confirmado | Validado y probado | JARO: Confirmado |
| IPv6 | No confirmado | Validado dual-stack; salida IPv6 del VPS pendiente | JARO: Parcialmente confirmado |
| Reconexión automática | Confirmado como producto; mecánica desconocida | Política de path/coste y teardown implementados; reconexión en dispositivo no probada | JARO: Parcialmente confirmado |
| Diagnósticos | No confirmado | Por evidencia real (handshake, deltas, AllowedIPs) | JARO: Confirmado |
| Android | Confirmado (es app Android) | No implementado | No implementado |
| iOS | Confirmado (variante iOS existe, F4) | Full/Standalone compilados; instalación física pendiente de firma | JARO: Parcialmente confirmado |

## 9. Arquitectura recomendada para JARO WPF

Modular, sin funciones de evasión de cobros:

1. **Módulo de conectividad**: detectar y clasificar el estado real (radio con/sin sesión de datos, IPv4, IPv6, DNS, alcances por destino). Salida explícita: `NO_IP_CONNECTIVITY | RESTRICTED (walled garden) | FULL` — nunca etiquetar "VPN conectada" sin evidencia (ya implementado en iOS; reutilizable).
2. **Diagnóstico IPv4/IPv6/DNS**: pruebas independientes por familia y resolución (getaddrinfo y consultas directas), con resultados separados por estado.
3. **Selección de servidores autorizados**: solo servidores del usuario (VPS propio de fase 4) con verificación de credenciales; sin listas remotas de terceros.
4. **Motor WireGuard** (ya en iOS; futuro en Android): perfil validado → interfaz TUN → handshake → contadores.
5. **SSH como proxy TCP** cuando exista servidor autorizado (ya implementado).
6. **Transporte TLS** para diagnósticos y para egress HTTPS; no como camuflaje de tráfico.
7. **Reconexión automática** con backoff y revalidación de consentimientos y estado del operador.
8. **Perfiles de conexión** con almacenamiento seguro (Keychain/Keystore, nunca en repo/CI).
9. **Indicadores honestos**: tres estados distintos — (a) túnel conectado, (b) Internet disponible, (c) acceso autorizado a una red/servicio — cada uno con su evidencia.
10. **Android (fase futura)**: `VpnService` (F6) con consentimiento del usuario, interfaz TUN, rutas DNS/route exclusión del túnel mismo, y librería WireGuard (wireguard-android) o implementación equivalente.

## 10. Riesgos técnicos y de seguridad

- **Legal/ética**: replicar el comportamiento "gratis sin saldo" implicaría eludir la facturación del operador; queda expresamente **fuera de alcance**.
- **Privacidad de terceros**: apps "una sola botón" operan servidores ajenos con visibilidad total del tráfico y autodeclaraciones de privacidad no auditables; JARO usa exclusivamente servidores propios.
- **Confusión de estados**: mostrar "conectado" cuando solo hay un túnel sin Internet real engaña al usuario (ya mitigado en JARO por evidencia).
- **Android**: VpnService requiere consentimiento explícito y puede ser revocado por el sistema; VPN siempre-encendida y kill switch cambian el comportamiento de rutas (F6).
- **Operacional**: zero-rating cambia sin aviso (F5 documenta un cambio oficial); cualquier hipótesis basada en ello es frágil.
- **Suministro**: el changelog cambia protocolos entre versiones sin documentación técnica (F1).

## 11. Plan de implementación por fases (propuesta)

1. **Fase A (hecha)**: iOS Full/Standalone, WireGuardKit, diagnósticos por evidencia, kit VPS.
2. **Fase B (en curso)**: VPS Oracle real, evidencia handshake/RX/TX/DNS/HTTPS/IPv6, firma Apple.
3. **Fase C**: Android base: `VpnService` + wireguard-android con el mismo modelo de perfiles validados y diagnósticos por evidencia; reutilizar el núcleo Python para el importador/validador.
4. **Fase D**: reconexión automática y clasificación de conectividad (módulo del §9.1) con indicadores de tres estados en ambas plataformas.
5. **Fase E**: endurecimiento (kill switch/always-on documentado, telemetría local, auditoría de privacidad).

## 12. Pruebas necesarias para validar cada función

| Función | Prueba mínima de validación |
|---|---|
| Detección de conectividad | Con y sin sesión de datos: clasificación correcta de `NO_IP_CONNECTIVITY`/`RESTRICTED`/`FULL` |
| Diagnóstico IPv4/IPv6 | Éxito y fallo controlados por familia; resultados separados |
| DNS | Resolución con delta de contadores del peer; fallo sin resolver operativo |
| WireGuard | Handshake ≤180 s filtrado por PublicKey; RX/TX incrementándose en 2 mediciones |
| SSH proxy | Streams reales contra servidor autorizado; sin rutas IP instaladas |
| Reconexión | Avión ON/OFF y cambio Wi-Fi↔celular; handshake nuevo tras volver |
| Full tunnel | Consentimiento explícito + includeAllNetworks + DNS autorizado; exenciones del sistema documentadas |
| Android VpnService | Consentimiento, rutas, exclusión del tráfico del túnel, reconexión del servicio |
| Instalación física | Firma Apple válida; cotejo de diagnósticos del teléfono con `wg show` del VPS |

## INFORMACIÓN QUE NECESITAMOS DEL USUARIO

Sin credenciales ni datos sensibles:

1. **Versión exacta de AM Tunnel Lite** instalada (Ajustes → Aplicaciones → AM TUNNEL LITE VPN → versión) y captura de "Novedades" de Play Store.
2. Captura de la pantalla principal con el perfil "B - GLOBAL 11" visible (sin abrir opciones internas).
3. Lista de modos/protocolos que muestra el menú de la app (solo nombres: p. ej. Direct, SSL, UDP…) y la opción marcada.
4. Estado del teléfono al momento de la prueba "sin saldo": captura de la barra de estado (icono 4G/5G/LTE), y si aparece "4G"/"LTE" aunque no haya datos.
5. Resultado no intrusivo: con la app **detenida**, en el navegador del teléfono, intentar abrir `http://detectportal.android.com` (o cualquier página) y capturar el mensaje exacto (p. ej. "sin conexión" vs. portal de Tigo). Esto distingue "sin IP" de "jaula de facturación".
6. País/región y operador secundario si prueba con otra SIM (para comparar comportamiento).
7. Si es posible (sin datos sensibles): captura de Ajustes → Redes → Punto de acceso (APN) mostrando solo el **nombre** del APN y tipo; nunca usuario/contraseña del APN.

No se solicitan claves privadas, contraseñas, tokens, códigos de acceso, capturas con credenciales ni archivos de configuración que contengan secretos.
