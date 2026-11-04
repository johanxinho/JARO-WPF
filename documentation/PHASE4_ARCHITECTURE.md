# JARO WPF — Phase 4 Architecture: Connectivity Validation & Real Network Lab

## 1. Overview & Objectives

Phase 4 transforms **JARO WPF** into a fully verifiable connectivity diagnostics, transport validation, and recovery system with strict traceability and zero simulated-as-real ambiguity:

- **Live Tunnel Health & Measured Egress**: Eliminates cached availability checks and synthetic latencies across SSH/SOCKS5 and WireGuard.
- **Granular Capability Matrix (`DiagnosticEngine`)**: Evaluates 20 independent connectivity capabilities without conflating DNS resolution with general web access or process liveness with end-to-end tunnel functionality.
- **Mandatory Traceability (`LabTestRecord`)**: Every local, external, simulated, or skipped test records `execution_scope`, `server`, `protocol`, `timestamp_utc`, `duration_ms`, `bytes_estimated`, `verified_real`, `resultado`/`result`, and `motivo`/`reason`.
- **Dual Network Lab (`NetworkLab`)**:
  - **Local Loopback Suite (`LOCAL_LOOPBACK`)**: Exercises QUIC, HTTP/3, DoQ (RFC 9250), DoT (RFC 7858), UDP/TCP DNS, X.509 certificate validation, RFC 1928 SOCKS5 + TLS/HTTPS relay, and WireGuard config validation strictly on `127.0.0.1` (`0 B` external traffic).
  - **External Real Suite (`EXTERNAL_REAL`)**: Bounded (`<= 64 KB` cap) validation of external DNS (UDP/TCP/DoT/DoQ), general non-DNS HTTPS, HTTP/3 over QUIC, multi-sample stability/loss/jitter, and Cloudflare micro-download/upload (`8 KB` / `4 KB`), requiring explicit authorization whenever the active interface cost profile is `unknown` or `metered`.

---

## 2. Priority Integration Fixes (Section A)

1. **Live SSH & WireGuard Health Verification (`core/connection/failover_controller.py`, `core/protocols/ssh_engine.py`, `core/protocols/vpn_tunnel_engine.py`)**:
   - `FailoverController._default_active_health_check()` queries live `SshSocksTunnel.check_health(verify_https_egress=True)` and `WireGuardTunnelEngine.inspect_state(verify_internet_egress=True)` instances via `TransportManager.get_ssh_tunnel()` / `get_wireguard_engine()`, never trusting cached `available: True` dictionaries.
   - `FailoverController._try_recover_active_tunnel()` attempts bounded in-place SSH reconnection before switching transports.
2. **Real WireGuard Egress Verification & Latency (`core/protocols/vpn_tunnel_engine.py`, `core/network_tests/connectivity_prober.py`, `core/connection/transport_manager.py`)**:
   - Removed `synthetic_latency = 20.0` in `TransportManager._evaluate_wireguard_tunnels()`.
   - `parse_wg_dump_output()` separates `handshake_verified` (`<= 180s` age and `rx_bytes > 0`) from `data_transfer_verified` (`rx_bytes > 180` and `tx_bytes > 180`, exceeding bare handshake overhead).
   - `WireGuardTunnelEngine.inspect_state(verify_internet_egress=True)` binds `probe_https_egress(..., source_address=(wg_ipv4, 0))` directly to the tunnel interface IPv4 without modifying global OS routes.
3. **Elimination of Redundant DNS Probes on Failover (`core/connection/failover_controller.py`, `core/connection/transport_manager.py`, `core/connection/multi_method_manager.py`, `core/network_tests/connectivity_prober.py`)**:
   - Added `include_dns_plane: bool = True` / `include_dns: bool = True` across the evaluation chain; `FailoverController._gather_general_candidates()` passes `include_dns_plane=False`, executing `0` DNS probes during transport failover.
4. **Unified Interface & Cost Classification (`core/connection/cost_manager.py`, `core/connection/multi_method_manager.py`, `configs/network_profiles.json`)**:
   - Unified medium detection (including `enx*` USB Ethernet) and cost tiers (`FREE=0`, `UNKNOWN=1`, `METERED=2`) through `CostManager`. Neither Wi-Fi nor Ethernet is ever assumed free by default.
   - Added `CostManager.evaluate_external_lab_gate()` and `"allow_external_lab_on_unknown_cost": false`.
5. **Legacy Compatibility Preserved**:
   - `core/protocols/udp_engine.py`, `core/protocols/tcp_dns_engine.py`, `core/connection/analyzer.py`, and `core/connection/server_selector.py` remain intact and functional.

---

## 3. DiagnosticEngine (`core/network_tests/diagnostic_engine.py`)

`DiagnosticEngine.run_diagnostics()` produces:
- **`primary_state` (`DiagnosticPrimaryState`)**:
  - `NO_PHYSICAL_CONNECTION`, `COST_POLICY_BLOCKED`, `WIFI_NO_INTERNET`, `ETHERNET_NO_INTERNET`, `CELLULAR_NO_INTERNET`, `CAPTIVE_PORTAL_INTERCEPTED`, `DNS_ONLY_NO_WEB`, `HTTPS_FUNCTIONAL`, `HTTP3_FUNCTIONAL`, `SSH_TUNNEL_FUNCTIONAL`, `WIREGUARD_TUNNEL_FUNCTIONAL`.
- **`capability_matrix` (20 independent boolean flags)**:
  - Physical/media: `physical_connection`, `wifi_connected`, `ethernet_connected`, `cellular_connected`, `cost_policy_blocked`.
  - DNS plane: `dns_udp_functional`, `dns_tcp_functional`, `dns_dot_functional`, `dns_doq_functional`, `dns_any_functional`, `dns_functional_without_web`.
  - Web/QUIC transports: `https_general_functional`, `http3_functional`, `general_internet_functional`.
  - SSH/SOCKS5 granular plane: `local_socks5_functional`, `remote_ssh_tunnel_functional`, `ssh_https_egress_verified`.
  - WireGuard granular plane: `wireguard_handshake_verified`, `wireguard_data_transfer_verified`, `wireguard_https_egress_verified`.

---

## 4. Traceability Schema & NetworkLab (`core/network_tests/network_lab.py`)

Every `LabTestRecord` enforces:
- `execution_scope`: `LOCAL_LOOPBACK` | `EXTERNAL_REAL` | `SIMULATED_FAULT_INJECTION` | `SKIPPED_MISSING_PREREQUISITE`
- `verified_real`: Strictly coerced to `False` whenever `execution_scope` is `SIMULATED_FAULT_INJECTION` or `SKIPPED_MISSING_PREREQUISITE`, or when `result != "PASS"`.
- Full metadata: `server`, `protocol`, `timestamp_utc`, `duration_ms`, `bytes_estimated`, `result`/`resultado`, `reason`/`motivo`.

---

## 5. Verification Summary (Linux Mint 22.3, ~3.3 GB RAM, 0 COP Budget)

- **Automated Test Suite (`tests/`)**: `46/46` passed in `3.19s`, `0 B` external traffic, `VmHWM = 48.85 MB`, `CPU = 0.6853 s`.
- **Local Network Lab (`LOCAL_NETWORK_LAB`)**: `12 PASS` (`LOCAL_LOOPBACK`), `2 SKIPPED` (`sshd` and `wg` absent / unconfigured), `0 FAIL`, `0 B` external traffic (`20,481 B` loopback), `VmHWM = 43.29 MB`.
- **External Network Lab (`EXTERNAL_NETWORK_LAB`, user-authorized one-shot on `wlp2s0`)**: `9 PASS` (`EXTERNAL_REAL`), `2 SKIPPED` (no authorized SSH/WireGuard servers in `configs/servers.json`), `0 FAIL`, `39,764 B` (`38.83 KB`) consumed, `VmHWM = 44.41 MB`.
- **Live DiagnosticEngine (`EXTERNAL_REAL`)**: `primary_state = HTTP3_FUNCTIONAL` with `dns_udp`, `dns_tcp`, `dns_dot`, `dns_doq`, `https_general`, and `http3` verified (`47,135 B` / `46.03 KB` combined session total `< 64 KB` cap).
