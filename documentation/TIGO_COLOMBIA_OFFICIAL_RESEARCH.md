# Investigación Técnica Oficial: Canales Gratuitos y de Autogestión en Tigo Colombia

> **Alcance ético, legal y técnico (JARO WPF — Fase 5)**:
> Este documento recopila **únicamente** las modalidades oficiales, públicas y reguladas de acceso sin saldo (*zero-rating* de autogestión) documentadas por **Tigo Colombia (Colombia Móvil S.A. E.S.P.)** y el marco normativo de la **Comisión de Regulación de Comunicaciones (CRC)** de Colombia.
>
> **Prohibición estricta**: No se incluyen, inventan ni sugieren *payloads*, cabeceras HTTP alteradas, SNI *spoofing*, APNs no documentados, servidores de terceros ni técnicas de evasión de tasación/facturación del operador.

---

## 1. Canales Oficiales Sin Consumo de Saldo Documentados por Tigo Colombia

Cuando una línea prepago o cuenta control de Tigo Colombia se encuentra con **$0 COP de saldo** y sin paquetes de datos activos, la red móvil mantiene habilitados **exclusivamente** canales cerrados de autogestión, consulta y recarga:

1. **Aplicación Oficial *Mi Tigo* (Zero-Rating de Autogestión)**:
   - Tigo Colombia permite la navegación dentro de los endpoints propios de la aplicación **Mi Tigo** sin descontar megabytes del plan ni requerir saldo previo para funciones de autogestión:
     - Consulta de saldo, vigencia y consumos de línea.
     - Compra de *Paquetigos* y recargas en línea mediante pasarelas de pago autorizadas (PSE, Nequi, Daviplata, tarjetas débito/crédito).
     - Solicitud de adelanto de saldo o paquetes de emergencia (**Tigo Te Presta**, sujeto a elegibilidad crediticia de la línea en Tigo).
     - Gestión de facturas en planes pospago.
   - **Nota técnica**: El operador advierte explícitamente que descargas desde tiendas externas (*App Store* / *Google Play*) o redirecciones hacia dominios de terceros fuera del flujo de autogestión/pago no están cubiertas por la gratuidad.

2. **Portal Cautivo Web de Autogestión / Compras Tigo**:
   - Al intentar abrir una sesión de datos sin saldo ni paquete activo, el nodo de pasarela del operador (PGW/UPF) intercepta o redirige las solicitudes HTTP hacia el portal cautivo oficial de Tigo Colombia (`compras.tigo.com.co` / `transacciones.tigo.com.co` / `mitigo.com.co`).
   - Este portal permite adquirir paquetes o activar *Tigo Te Presta* sin saldo, pero **no** enruta tráfico hacia hosts arbitrarios de internet.

3. **Canales GSM / USSD (Sin requerir sesión IP ni datos móviles)**:
   - Operan sobre señalización GSM/LTE sin utilizar túneles IP:
     - **`*300#` / `*300`**: Menú interactivo USSD/marcación gratuita para consulta de saldo, compra de paquetes y *Tigo Te Presta*.
     - **`*10#`**: Consulta rápida de saldo en pantalla vía USSD.
     - **`*611`**: Línea de atención al usuario de Tigo desde líneas móviles Tigo.
     - **`*255#`**: Consulta del número propio de la línea Tigo.

4. **Promociones Comerciales Condicionadas a Recarga / Paquete Vigente**:
   - Aplicaciones incluidas sin descuento de datos generales (por ejemplo, mensajería de texto en WhatsApp o Facebook en ciertos *Paquetigos* promocionales) **requieren tener un paquete o recarga vigente** cuyas condiciones comerciales explícitamente las incluyan; **no** constituyen acceso gratuito permanente en estado de saldo cero, ni habilitan transporte UDP/TCP arbitrario hacia servidores externos.

---

## 2. Marco Regulatorio en Colombia (CRC)

- Bajo el régimen de protección de usuarios de comunicaciones de la **CRC (Resolución CRC 5050 de 2016 y actualizaciones)** y las disposiciones de neutralidad de red en Colombia (Ley 1450 de 2011, Art. 56; Resolución CRC 3502 de 2011):
  - Los operadores móviles habilitan el acceso gratuito a sus **canales de atención, consulta de saldo y recarga/autogestión** aun cuando el usuario no cuente con saldo disponible.
  - Los esquemas comerciales de *zero-rating* están estrictamente delimitados por las ofertas comerciales registradas por el operador y **no obligan ni habilitan** el tránsito libre de protocolos generales de transporte (HTTPS general, HTTP/3, SSH o VPN WireGuard) cuando la cuenta carece de saldo o plan activo.

---

## 3. Análisis de Arquitectura de Red Móvil (3GPP PGW / UPF) e Implicaciones para JARO WPF

En una red 4G EPC (`PGW` + `PCRF`) o 5G Core (`UPF` + `PCF`) como la de Tigo Colombia:

1. **Filtrado por Reglas PCC (*Policy and Charging Control*) en Capa 3/4 y Capa 7**:
   - Cuando el perfil del suscriptor en el `OCS` (*Online Charging System*) tiene cuota `0`, el `UPF`/`PGW` aplica una política restrictiva (*walled garden*):
     - Solo permite flujos IP cuyos **rangos de IP destino**, **pares IP:puerto** y validación TLS/HTTP coinciden con las listas blancas oficiales del operador (servidores de `Mi Tigo`, portal cautivo y pasarelas bancarias PSE durante la transacción).
     - Cualquier paquete `TCP SYN` (ej. SSH puerto `22`/`443`) o datagrama `UDP` (ej. WireGuard `51820`, QUIC `443`, DoQ `853`) dirigido a una IP externa ajena a esa lista blanca es **descartado en el UPF/PGW** o redirigido al portal cautivo.
2. **Integración Veraz con el Motor de Diagnóstico de JARO WPF**:
   - Si JARO WPF se ejecuta sobre una conexión Tigo Colombia sin saldo:
     - [`CostManager`](../core/connection/cost_manager.py) clasifica la interfaz celular (`wwan0` / `usb0` / `pdp_ip0`) como **`CostProfile.METERED`** y bloquea sondas automáticas salvo autorización explícita del usuario.
     - Si el usuario autoriza un diagnóstico puntual, [`DiagnosticEngine`](../core/network_tests/diagnostic_engine.py) detectará de forma precisa y honesta:
       - `CAPTIVE_PORTAL_INTERCEPTED` (si el operador redirige las peticiones web al portal de compras Tigo),
       - `DNS_ONLY_NO_WEB` (si el DNS del operador resuelve nombres pero el UPF bloquea las IPs externas), o
       - `CELLULAR_NO_INTERNET` (si los paquetes hacia internet general son descartados).
   - **Conclusión técnica**: SSH y WireGuard en JARO WPF son motores de túnel **para redes donde ya existe conectividad IP autorizada** (Wi-Fi autorizado, Ethernet autorizado, o plan de datos móvil legítimo y activo autorizado por el usuario) hacia un **servidor propio o autorizado**. No proporcionan ni buscan proporcionar internet gratuito sobre redes móviles sin saldo.
