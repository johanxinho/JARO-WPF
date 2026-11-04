"""JARO WPF - Micro-Bandwidth, Latency, Jitter & Packet Loss Tester (Phase 3).

Safety & Efficiency Design:
- Uses ONLY explicitly authorized endpoints (e.g., local test server or Cloudflare Speed API).
- Enforces strict configurable byte caps via CostManager (default 16 KB down / 8 KB up; max 64 KB).
- Never downloads multi-megabyte payloads.
- Measures download speed, upload speed, latency, jitter, and probe/packet loss percentage.
"""
import http.client
import json
from pathlib import Path
import socket
import ssl
import statistics
import time
from typing import Any, Callable, Dict, List, Optional
import urllib.parse

from core.connection.cost_manager import CostManager
from core.network_tests.connectivity_prober import _create_verified_ssl_context

HARD_CAP_TRANSFER_BYTES = 131072  # 128 KB absolute ceiling for safety on low-RAM / metered setups
DEFAULT_PROFILES_PATH = Path(__file__).resolve().parents[2] / "configs" / "network_profiles.json"


class BandwidthTester:
    """Measures link quality (latency, jitter, loss) and bounded micro-throughput."""

    def __init__(
        self,
        cost_manager: Optional[CostManager] = None,
        ssl_context_factory: Callable[[], ssl.SSLContext] = _create_verified_ssl_context,
    ) -> None:
        self.cost_manager = cost_manager or CostManager()
        self._ssl_context_factory = ssl_context_factory

    def measure_quality_samples(
        self,
        probe_fn: Callable[[], Dict[str, Any]],
        samples: int = 4,
        estimated_bytes_per_sample: int = 1024,
        active_interfaces: Optional[List[Dict[str, Any]]] = None,
        interface_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Measures latency, jitter, stability, and packet/probe loss across N lightweight samples."""
        count = max(1, min(10, int(samples)))
        if active_interfaces is not None:
            gate = self.cost_manager.evaluate_network_Gate(active_interfaces)
            if not gate["allowed"]:
                return {
                    "allowed": False,
                    "error": gate["reason"],
                    "samples_sent": 0,
                    "samples_received": 0,
                    "packet_loss_pct": 100.0,
                    "stability_ratio": 0.0,
                    "avg_latency_ms": None,
                    "jitter_ms": 0.0,
                }

        total_est = count * max(128, estimated_bytes_per_sample)
        budget_check = self.cost_manager.check_budget_for_transfer(total_est)
        if not budget_check["allowed"]:
            return {
                "allowed": False,
                "error": budget_check["reason"],
                "samples_sent": 0,
                "samples_received": 0,
                "packet_loss_pct": 100.0,
                "stability_ratio": 0.0,
                "avg_latency_ms": None,
                "jitter_ms": 0.0,
            }

        latencies: List[float] = []
        bytes_used = 0
        last_err: Optional[str] = None

        for _ in range(count):
            res = probe_fn()
            sample_bytes = int(res.get("bytes_transferred", estimated_bytes_per_sample))
            bytes_used += sample_bytes
            self.cost_manager.record_consumption(sample_bytes, ifname=interface_name)

            ok = bool(res.get("verified", False))
            lat = res.get("latency_ms")
            if ok and lat is not None:
                latencies.append(float(lat))
            else:
                last_err = res.get("error")

        received = len(latencies)
        lost = count - received
        loss_pct = round((lost / count) * 100.0, 2)
        stability = round(received / count, 2)
        avg_lat = round(statistics.mean(latencies), 2) if latencies else None
        jitter = round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0

        return {
            "allowed": True,
            "samples_sent": count,
            "samples_received": received,
            "packet_loss_pct": loss_pct,
            "stability_ratio": stability,
            "avg_latency_ms": avg_lat,
            "jitter_ms": jitter,
            "bytes_consumed": bytes_used,
            "error": None if received > 0 else (last_err or "All quality probes failed"),
        }

    def measure_download_speed(
        self,
        url: str,
        authorized: bool = False,
        max_bytes: int = 16384,
        connect_host: Optional[str] = None,
        sni_hostname: Optional[str] = None,
        active_interfaces: Optional[List[Dict[str, Any]]] = None,
        interface_name: Optional[str] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Measures bounded download speed without consuming large payloads."""
        if not authorized:
            return {
                "succeeded": False,
                "download_kbps": 0.0,
                "download_mbps": 0.0,
                "bytes_transferred": 0,
                "error": "Endpoint is not marked as authorized for bandwidth testing",
            }

        if active_interfaces is not None:
            gate = self.cost_manager.evaluate_network_Gate(active_interfaces)
            if not gate["allowed"]:
                return {
                    "succeeded": False,
                    "download_kbps": 0.0,
                    "download_mbps": 0.0,
                    "bytes_transferred": 0,
                    "error": gate["reason"],
                }

        capped_bytes = min(max(1024, int(max_bytes)), HARD_CAP_TRANSFER_BYTES)
        budget = self.cost_manager.check_budget_for_transfer(capped_bytes)
        if not budget["allowed"]:
            return {
                "succeeded": False,
                "download_kbps": 0.0,
                "download_mbps": 0.0,
                "bytes_transferred": 0,
                "error": budget["reason"],
            }

        parsed = urllib.parse.urlsplit(url)
        host_header = sni_hostname or parsed.hostname or ""
        target_host = connect_host or parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path_q = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

        bytes_read = 0
        try:
            with socket.create_connection((target_host, port), timeout=timeout) as raw_sock:
                raw_sock.settimeout(timeout)
                if parsed.scheme == "https":
                    ctx = self._ssl_context_factory()
                    sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host_header)
                else:
                    sock = raw_sock

                with sock:
                    req = (
                        f"GET {path_q} HTTP/1.1\r\n"
                        f"Host: {host_header}\r\n"
                        f"Range: bytes=0-{capped_bytes - 1}\r\n"
                        f"User-Agent: JARO-WPF/3.0 MicroBandwidthTester\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("ascii")

                    transfer_start = time.perf_counter()
                    sock.sendall(req)
                    resp = http.client.HTTPResponse(sock)
                    resp.begin()

                    if resp.status not in (200, 206):
                        self.cost_manager.record_consumption(len(req) + 256, ifname=interface_name)
                        return {
                            "succeeded": False,
                            "status_code": resp.status,
                            "download_kbps": 0.0,
                            "download_mbps": 0.0,
                            "bytes_transferred": 0,
                            "error": f"Unexpected HTTP status {resp.status} during download test",
                        }

                    while bytes_read < capped_bytes:
                        to_read = min(4096, capped_bytes - bytes_read)
                        chunk = resp.read(to_read)
                        if not chunk:
                            break
                        bytes_read += len(chunk)

                    elapsed_s = max(0.0005, time.perf_counter() - transfer_start)

            total_wire_bytes = bytes_read + 384  # Include approximate HTTP/TCP framing overhead
            self.cost_manager.record_consumption(total_wire_bytes, ifname=interface_name)

            bits = bytes_read * 8.0
            kbps = round((bits / elapsed_s) / 1000.0, 2)
            mbps = round(kbps / 1000.0, 3)

            return {
                "succeeded": bytes_read > 0,
                "status_code": resp.status,
                "bytes_transferred": bytes_read,
                "elapsed_ms": round(elapsed_s * 1000.0, 2),
                "download_kbps": kbps,
                "download_mbps": mbps,
                "error": None if bytes_read > 0 else "Empty download payload",
            }
        except Exception as exc:
            if bytes_read > 0:
                self.cost_manager.record_consumption(bytes_read, ifname=interface_name)
            return {
                "succeeded": False,
                "download_kbps": 0.0,
                "download_mbps": 0.0,
                "bytes_transferred": bytes_read,
                "error": f"{exc.__class__.__name__}: {exc}",
            }

    def measure_upload_speed(
        self,
        url: str,
        authorized: bool = False,
        payload_bytes: int = 8192,
        connect_host: Optional[str] = None,
        sni_hostname: Optional[str] = None,
        active_interfaces: Optional[List[Dict[str, Any]]] = None,
        interface_name: Optional[str] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Measures bounded upload speed with a tiny payload (default 8 KB)."""
        if not authorized:
            return {
                "succeeded": False,
                "upload_kbps": 0.0,
                "upload_mbps": 0.0,
                "bytes_transferred": 0,
                "error": "Endpoint is not marked as authorized for bandwidth testing",
            }

        if active_interfaces is not None:
            gate = self.cost_manager.evaluate_network_Gate(active_interfaces)
            if not gate["allowed"]:
                return {
                    "succeeded": False,
                    "upload_kbps": 0.0,
                    "upload_mbps": 0.0,
                    "bytes_transferred": 0,
                    "error": gate["reason"],
                }

        capped_bytes = min(max(512, int(payload_bytes)), HARD_CAP_TRANSFER_BYTES)
        budget = self.cost_manager.check_budget_for_transfer(capped_bytes + 512)
        if not budget["allowed"]:
            return {
                "succeeded": False,
                "upload_kbps": 0.0,
                "upload_mbps": 0.0,
                "bytes_transferred": 0,
                "error": budget["reason"],
            }

        parsed = urllib.parse.urlsplit(url)
        host_header = sni_hostname or parsed.hostname or ""
        target_host = connect_host or parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path_q = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

        body = b"J" * capped_bytes
        try:
            with socket.create_connection((target_host, port), timeout=timeout) as raw_sock:
                raw_sock.settimeout(timeout)
                if parsed.scheme == "https":
                    ctx = self._ssl_context_factory()
                    sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host_header)
                else:
                    sock = raw_sock

                with sock:
                    headers = (
                        f"POST {path_q} HTTP/1.1\r\n"
                        f"Host: {host_header}\r\n"
                        f"Content-Type: application/octet-stream\r\n"
                        f"Content-Length: {capped_bytes}\r\n"
                        f"User-Agent: JARO-WPF/3.0 MicroBandwidthTester\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("ascii")

                    transfer_start = time.perf_counter()
                    sock.sendall(headers + body)
                    resp = http.client.HTTPResponse(sock)
                    resp.begin()
                    resp.read(512)
                    elapsed_s = max(0.0005, time.perf_counter() - transfer_start)

            total_wire = capped_bytes + len(headers) + 128
            self.cost_manager.record_consumption(total_wire, ifname=interface_name)

            if resp.status not in (200, 201, 202, 204):
                return {
                    "succeeded": False,
                    "status_code": resp.status,
                    "upload_kbps": 0.0,
                    "upload_mbps": 0.0,
                    "bytes_transferred": capped_bytes,
                    "error": f"Unexpected HTTP status {resp.status} during upload test",
                }

            bits = capped_bytes * 8.0
            kbps = round((bits / elapsed_s) / 1000.0, 2)
            mbps = round(kbps / 1000.0, 3)

            return {
                "succeeded": True,
                "status_code": resp.status,
                "bytes_transferred": capped_bytes,
                "elapsed_ms": round(elapsed_s * 1000.0, 2),
                "upload_kbps": kbps,
                "upload_mbps": mbps,
                "error": None,
            }
        except Exception as exc:
            return {
                "succeeded": False,
                "upload_kbps": 0.0,
                "upload_mbps": 0.0,
                "bytes_transferred": 0,
                "error": f"{exc.__class__.__name__}: {exc}",
            }
