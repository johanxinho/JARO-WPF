# Fase 4 — VPS externo y conectividad WireGuard real (JARO WPF)

Arquitectura objetivo: servidor WireGuard permanente en un VPS externo del usuario; el PC (Linux Mint 22.3) queda como cliente/uso auxiliar; iPhone 12 como cliente final con la variante Full de JARO WPF.

## Estado de los entregables de esta fase

- Toolkit VPS en `tools/vps/`: generador de configuraciones validado (`vps_wireguard_config.py`), aprovisionamiento idempotente (`provision_wireguard_server.sh`) y recolector de evidencia (`verify_vps_evidence.sh`).
- 15 pruebas del generador (`tests/test_phase10_vps_toolkit.py`) y **9 pruebas de integración aislada del aprovisionamiento** (`tests/test_phase10_provision_integration.py`, entorno con binarios sustitutos y modo `--prefix`).
- Suite completa local: **100 pruebas OK** (76 previas + 24 nuevas).

## 1. Comparativa de VPS gratuitos (verificado contra fuentes oficiales)

| Proveedor | Oferta gratuita permanente | Límites que afectan a una VPN | Riesgos | Veredicto |
|---|---|---|---|---|
| **Oracle Cloud Always Free** | 2× `VM.Standard.E2.1.Micro` (1/8 OCPU, 1 GB RAM, ~50 Mbps a Internet, IP pública incluida) + Ampere A1.Flex equivalente a 2 OCPU/12 GB (1500 OCPU-h y 9000 GB-h al mes); 200 GB de bloque; **10 TB/mes de salida** | Requiere tarjeta para crear la tenencia; A1 suele dar "Out of capacity"; reclaim de instancias inactivas si durante 7 días el percentil 95 de CPU, red y memoria (A1) queda bajo 20 % | Suspensión/reclaim si la instancia queda ociosa; condiciones pueden cambiar | **RECOMENDADO.** Único con egress y 50 Mbps suficientes para un túnel personal |
| Google Cloud Free Tier | 1× `e2-micro` en 3 regiones de EE. UU. | **1 GB/mes de salida**; el exceso se factura; requiere cuenta de facturación con tarjeta | Cargo inesperado si hay tráfico VPN | Descartado como principal: 1 GB/mes es insuficiente |
| AWS Free Tier | t2.micro/t3.micro 12 meses o programa nuevo con límites mensuales | Créditos expiran o se agotan; requiere tarjeta | Cargos tras agotamiento | No permanente: descartado |
| Azure | Créditos iniciales; sin VM permanente gratuita | Requiere tarjeta | Cargo al agotar crédito | Descartado |

Notas honestas:

- La fuente de Oracle (docs oficiales de Always Free, consultada hoy) mantiene A1 en 2 OCPU/12 GB equivalentes; artículos de terceros hablan de cambios en 2026, pero la documentación oficial citada arriba es la referencia aplicable. Verificar la pantalla de precios al crear la cuenta.
- Oracle no garantiza disponibilidad de A1 en free tier (suele agotarse); los `E2.1.Micro` casi siempre se crean. Para WireGuard, un Micro alcanza de sobra para un iPhone.
- Ninguna opción es verificablemente "permanente para siempre": Oracle reserva el derecho de cambiar condiciones. El reclaim por inactividad se mitiga con uso real del túnel (o un cron ligero de CPU, documentado más abajo).

### Revisión correctiva del toolkit (post-auditoría del usuario)

Defectos reproducibles corregidos en esta revisión:

1. **Directorio del cliente**: `/root/jaro-wireguard/` (o `$PREFIX/root/jaro-wireguard/`) se crea con `mkdir -p` y `chmod 700` **antes** de escribir el perfil; el `.conf` queda 0600. Verificado por la prueba de integración.
2. **Contrato del generador**: el instalador ya no invoca `client-conf` sin `--allowed-ips` ni `--full-tunnel`. Por defecto usa split tunnel (las subredes del túnel); `--full-tunnel` exige DNS válido. Cubierto por pruebas de integración split y full tunnel.
3. **DNS honesto**: `--dns` **fallo cerrado** si no hay resolver: exige `--install-unbound` (instala y configura Unbound escuchando solo en las IPs del túnel, con `access-control` que rechaza el resto) o `--assume-dns-resolver` explícito. Unbound no se expone públicamente.
4. **IPv6 honesto**: se genera `ip6tables MASQUERADE` y reglas `FORWARD` solo si se declara `--tunnel-ipv6`, con aviso explícito de que la salida IPv6 pública debe verificarse aparte; sin IPv6 no se anuncia dual-stack.
5. **Claves fuera de argv/ps**: el generador acepta `--private-key-file` (archivo 0600 obligatorio; rechaza 0644) o `--private-key -` (stdin). El instalador pasa las claves solo por archivos 0600 en `/etc/wireguard/`. Las pruebas verifican que `argv` del proceso no contiene la clave y que los mensajes de error no la revelan.
6. **SSH sin apertura global**: `--manage-firewall` ya no ejecuta `ufw allow 22/tcp`; SSH/22 solo se abre con `--ssh-source <cidr>` explícito, o queda bajo la Security List del proveedor. Verificado por prueba (el plan dry-run muestra la regla restringida y nunca la global).

Hallazgos adicionales corregidos durante la revisión: el derivador de direcciones enumeraba `hosts()` de la subred IPv6 (/64 = 2^64 direcciones), colgando el proceso; ahora deriva primer/segundo host por aritmética (`tunnel-addresses`), y el instalador ya no usa heredocs ad hoc. `SCRIPT_DIR` se define antes de su primer uso. Se añadió modo `--prefix` para ejecutar el aprovisionamiento en un entorno aislado sin systemd real ni cambios de red.

**Estado del toolkit: no declarado listo para producción** hasta completar la ejecución real en el VPS del usuario (sección 5 de evidencias, todos los estados PENDIENTE).

## 2. Qué hizo el agente y qué queda para el usuario (sin autorizaciones concedidas)

El agente **no** creó cuentas, no contrató servicios, no abrió puertos y no tocó el firewall del PC. Todo lo siguiente requiere tu acción:

1. Crear la cuenta Oracle Cloud (tarjeta propia; Oracle hace una autorización temporal de ~1 USD que no es cargo). Sigue solo los pasos de la consola oficial. Región sugerida: la más cercana a Colombia con disponibilidad (probar `us-phoenix-1` o `us-ashburn-1` si la región local da "out of capacity" para A1).
2. Crear la instancia: Ubuntu 24.04, shape `VM.Standard.E2.1.Micro` (o A1.Flex 1 OCPU/6 GB si hay capacidad), boot volume 50 GB, y **subir tu clave SSH pública** (generada en Mint con `ssh-keygen -t ed25519`).
3. En la VCN: Security List / NSG con regla de entrada `UDP/51820` desde `0.0.0.0/0` y `::/0` (solo si lo autorizas tú). SSH/22 restringido a tu IP de casa si es posible.
4. Conectarte por SSH y ejecutar el aprovisionamiento (ver sección 3).
5. Mandar al agente la salida de `verify_vps_evidence.sh` (sin claves privadas) para validar la evidencia.

## 3. Aprovisionamiento del VPS (receta exacta)

En el VPS, como root, tras subir este repositorio o solo el directorio `tools/vps/`:

```bash
sudo bash provision_wireguard_server.sh \
  --endpoint-host <IP_PUBLICA_O_DNS_DEL_VPS> \
  --tunnel-ipv4 10.66.66.0/24 \
  --tunnel-ipv6 fd00:6:6::/64 \
  --listen-port 51820 \
  --client-name iphone12 \
  --dns 10.66.66.1 \
  --manage-firewall
```

Qué hace: instala `wireguard` + `qrencode`, activa `ip_forward` IPv4/IPv6, genera claves con `wg genkey` **dentro del VPS**, escribe `/etc/wireguard/wg0.conf` (0600) con NAT `MASQUERADE` vía `PostUp/PostDown`, autoriza el peer del iPhone y habilita `wg-quick@wg0`. El perfil del cliente queda en `/root/jaro-wireguard/iphone12.conf` (0600): **no se copia al repo, CI ni documentación**. Si `--manage-firewall` no se pasa, no toca UFW.

El DNS del túnel (`--dns 10.66.66.1`) requiere un resolver en el VPS (por ejemplo `unbound` escuchando en la IP del túnel); alternativa sin servicio adicional: omitir `--dns` y el cliente usará el DNS del perfil importado de forma explícita. No se fuerza ningún DNS público por defecto.

**Oracle específico**: además de UFW, la regla `UDP/51820` debe existir en la Security List de la VCN; sin ella no habrá handshake aunque el VPS esté bien configurado.

IPv6: la receta crea el túnel dual-stack si pasas `--tunnel-ipv6`. La salida IPv6 del VPS (GUA asignable a la VCN) depende de la región/cuenta: **queda por verificar al crear la instancia**; si no hay IPv6 pública, opera en IPv4 y no declare dual-stack en full tunnel.

## 4. Recuperación ante pérdida de instancia (reclaim)

Si Oracle reclama la instancia por inactividad: el estado del servidor se reconstruye re-ejecutando el aprovisionamiento (idempotente, regenera claves nuevas). El perfil del iPhone deberá reimportarse con las claves nuevas; los perfiles con claves viejas fallarán de handshake y JARO lo mostrará como "sin handshake reciente", no como conectado. Guarda `/root/jaro-wireguard/` y `/etc/wireguard/*.key` en tu gestión de secretos personal si quieres conservar identidades.

## 5. Pruebas y evidencia (honestas)

| # | Evidencia requerida | Dónde se ejecuta | Estado |
|---|---|---|---|
| 1 | VPS accesible | SSH desde Mint o consola OCI | **PENDIENTE** (sin cuenta creada) |
| 2 | WireGuard instalado y activo | VPS (`systemctl is-active wg-quick@wg0`) | **PENDIENTE** |
| 3 | Peer creado | VPS (`wg show` lista el peer) | **PENDIENTE** |
| 4 | Cliente autorizado | VPS: PublicKey del peer coincide con el perfil importado | **PENDIENTE** |
| 5 | Handshake real | VPS e iPhone: `latest-handshakes` ≤180 s filtrado por PublicKey | **PENDIENTE** |
| 6 | RX/TX incrementándose | VPS: `wg show transfer` en 2 ejecuciones; iPhone: deltas UAPI | **PENDIENTE** |
| 7 | Tráfico bidireccional | ping por el túnel + contadores RX y TX > 0 | **PENDIENTE** |
| 8 | Resolución DNS | iPhone: diagnóstico `verifyDNSResolution` (getaddrinfo con deltas); VPS: `dig @10.66.66.1` | **PENDIENTE** |
| 9 | HTTPS a través del túnel | iPhone: sonda HTTPS con URL del usuario + IP cubierta por AllowedIPs + handshake fresco + RX/TX | **PENDIENTE** |
| 10 | Salida a Internet | VPS: `curl --interface wg0` a URL del usuario; comparar IP de origen | **PENDIENTE** |
| 11 | Reconexión | iPhone: avión ON/OFF; handshake nuevo ≤180 s | **PENDIENTE** |
| 12 | IPv4 e IPv6 | ping6/ping dual por el túnel; depende de IPv6 pública del VPS | **PENDIENTE** |
| 13 | Full tunnel con consentimiento | iPhone: toggle de consentimiento + `includeAllNetworks` + DNS explícito; exenciones del sistema documentadas por Apple | **PENDIENTE** |

Ninguno de estos estados está simulado. Los tests automatizados del repo (91) validan lógica de configuración y contratos; **no** constituyen evidencia de conectividad.

## 6. Flujo de la fase 3 re-auditado para fase 4

`Perfil importado → validación → almacenamiento → WireGuardKit → PacketTunnel → VPS`: verificado con las pruebas existentes. Campos confirmados en el código (fase 3): `PrivateKey`, `PublicKey`, `Endpoint`, `AllowedIPs`, `Address`, `DNS`, `MTU`, `PersistentKeepalive` (25 s recomendado para NAT del VPS; el generador lo fija por defecto). Para la conexión contra este VPS, el perfil del iPhone debe importarse del `.conf` generado o del JSON portable; en full tunnel, activar los consentimientos en la UI (rutas globales + override DNS).

## 7. Bloqueo pendiente de Apple (sin cambios respecto a fase 3)

Para instalar la variante Full con Packet Tunnel en el iPhone 12 se sigue necesitando: cuenta de desarrollador Apple con equipo de pago (o exención/organización), porque el entitlement Network Extensions no está disponible en Personal Team gratuito; App IDs de app y extensión; App Group autorizado en ambos; dos provisioning profiles; certificado de distribución/desarrollo; un Mac con Xcode y el UDID del iPhone registrado. El IPA de Actions sigue siendo *unsigned*: no instalable sin ese proceso. No se han usado ni propuesto mecanismos que evadan la firma.

## 8. Conclusión de fase

Implementado y probado: toolkit completo de VPS (generador + aprovisionamiento + evidencia) con 91 pruebas verdes y CI. Pendiente y dependiente del usuario: crear la cuenta Oracle, la instancia, la regla de firewall (con tu autorización) y ejecutar los scripts; y resolver la firma Apple para el iPhone. La conexión real sigue sin verificarse: no se declara la fase como terminada.
