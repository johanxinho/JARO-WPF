# JARO WPF — Documentación Técnica y Auditoría Fase 1 (v1.1.0)

## 1. Objetivo de la Fase 1
Establecer el núcleo de diagnóstico multicapa, selección inteligente separada por categorías (`internet_transport` vs `dns_service`), reconexión segura con *backoff* exponencial + *circuit breaker* e integración con DNS-over-QUIC (RFC 9250) y DNS-over-TLS (RFC 7858), garantizando un uso mínimo de memoria (< 32 MB RSS) en Linux Mint 22.3 (3.3 GB RAM).

---

## 2. Diferenciación Estricta de Estados de Conectividad
El módulo [`core/network_tests/connectivity_prober.py`](file:///home/johanxinho/JARO-WPF/core/network_tests/connectivity_prober.py) evita falsos positivos separando las capas de red en seis niveles verificables (`ConnectivityState`):

| Estado | Significado Técnico | ¿Existe Internet Real? |
| :--- | :--- | :---: |
| `NO_NETWORK` | Sin interfaces operativas ni respuesta de sockets locales/remotos. | No |
| `SOCKET_ONLY` | El kernel completa `SYN -> SYN-ACK` TCP, pero no hay protocolo válido (posible intercepción por firewall/middlebox). | No |
| `DNS_ONLY` | El puerto 53/853 resuelve DNS o **únicamente responde la IP de un proveedor DNS (`1.1.1.1`)**, mientras que los servidores web generales externos fallan. | No |
| `SERVER_HANDSHAKE` | Se completa un handshake TLS 1.2/1.3 con verificación criptográfica X.509 (`CERT_REQUIRED`) y hostname/SNI válido, sin salida HTTPS general. | No |
| `CAPTIVE_PORTAL` | Se detecta redirección HTTP (301/302/303/307/308/511) o alteración del payload esperado por un portal cautivo o proxy de facturación. | No |
| `REAL_INTERNET` | Handshake TLS auténtico + validación de hostname + código de estado HTTP esperado + firma de contenido verificada contra **hosts web generales no-DNS** (`example.com`, `connectivitycheck.gstatic.com`). | **Sí** |

---

## 3. Separación de Categorías y Criterios de Puntuación (`[0..100]`)

En [`core/connection/multi_method_manager.py`](file:///home/johanxinho/JARO-WPF/core/connection/multi_method_manager.py), los candidatos se evalúan y clasifican en **dos listas independientes** para evitar comparar servicios de resolución de nombres con transporte general de internet:

### A. Transporte General de Internet (`internet_transports` — [`compute_transport_score`](file:///home/johanxinho/JARO-WPF/core/connection/multi_method_manager.py#L54-L93))
| Componente | Rango | Criterio de Cálculo |
| :--- | :---: | :--- |
| `verification_pts` | `0..40` | `40` pts si existe salida `REAL_INTERNET` (no-DNS) + payload HTTPS verificado; `15` pts si solo responde el endpoint puntual; `0` si falla. |
| `stability_pts` | `0..25` | `stability_ratio * 25.0` (proporción de muestras exitosas). |
| `latency_pts` | `0..25` | `25.0 * (1 - min(avg_latency_ms + 1.5 * jitter_ms, 1000) / 1000)`. |
| `cost_pts` | `0..10` | `10` pts para `cost_tier = 0` (Wi-Fi/Ethernet libre), `5` pts para `tier = 1`, `0` pts para `tier >= 2` (celular medido). |

### B. Servicios de Resolución DNS (`dns_resolvers` — [`compute_dns_score`](file:///home/johanxinho/JARO-WPF/core/connection/multi_method_manager.py#L96-L135))
Nunca otorgan `real_internet_verified = True`. Comparan `doq` (UDP 853), `dot` (TCP 853), `tcp_dns` (TCP 53) y `udp_dns` (UDP 53):
| Componente | Rango | Criterio de Cálculo |
| :--- | :---: | :--- |
| `protocol_security_pts` | `0..35` | `35` pts para DNS cifrado y autenticado con X.509 (`doq` RFC 9250 / `dot` RFC 7858); `25` pts para DNS en texto claro (`udp_dns` / `tcp_dns`). |
| `stability_pts` | `0..30` | `stability_ratio * 30.0`. |
| `latency_pts` | `0..25` | `25.0 * (1 - min(avg_latency_ms + 1.5 * jitter_ms, 500) / 500)`. |
| `cost_pts` | `0..10` | `10` pts para `cost_tier = 0`, `5` pts para `tier = 1`, `0` pts para `tier >= 2`. |

---

## 4. Cumplimiento RFC 9250 en `doq_engine.py`
- **ALPN:** `["doq"]` (RFC 9250 Sección 7).
- **Message ID:** Forzado a `0x0000` en consulta y verificado como `0x0000` en respuesta (RFC 9250 Sección 4.2.1).
- **Framing y Cierre de Stream:** Prefijo `uint16` (`!H`) big-endian + envío con `end_stream=True` (`STREAM FIN`), rechazando tramas truncadas o con bytes sobrantes (RFC 9250 Sección 4.2).
- **Eventos de Error QUIC:** Captura explícita de `StreamReset` y `ConnectionTerminated` más limpieza determinista de `Future` internos para evitar fugas o advertencias de `asyncio`.
