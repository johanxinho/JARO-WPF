"""JARO WPF - Generic QUIC & HTTP/3 Application Transport Engine (RFC 9000 / RFC 9114).

Strictly separated from DNS-over-QUIC (core/protocols/doq_engine.py, RFC 9250).
Provides authenticated QUIC transport probing and real HTTP/3 client requests
with granular handshake, response, and total latency telemetry.
"""
import asyncio
import json
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.h3.exceptions import H3Error
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamReset,
)
from aioquic.quic.packet import QuicErrorCode
import certifi

CRYPTO_ERROR_MIN = 0x0100
CRYPTO_ERROR_MAX = 0x01FF
DEFAULT_MAX_RESPONSE_BYTES = 65536


class QuicTransportError(Exception):
    """Raised on QUIC transport, TLS verification, or HTTP/3 framing errors."""


class QuicHttp3ClientProtocol(QuicConnectionProtocol):
    """Handles generic QUIC handshake telemetry and HTTP/3 request/response streams."""

    def __init__(self, *args: Any, enable_h3: bool = True, max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._enable_h3 = enable_h3
        self._max_response_bytes = max_response_bytes
        self._h3: Optional[H3Connection] = None
        self.handshake_event: Optional[HandshakeCompleted] = None
        self.close_event: Optional[ConnectionTerminated] = None

        self._stream_futures: Dict[int, asyncio.Future[Tuple[List[Tuple[bytes, bytes]], bytes]]] = {}
        self._stream_headers: Dict[int, List[Tuple[bytes, bytes]]] = {}
        self._stream_bodies: Dict[int, bytearray] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self.handshake_event = event
            if self._enable_h3 and event.alpn_protocol in H3_ALPN:
                self._h3 = H3Connection(self._quic)
            return

        if isinstance(event, ConnectionTerminated):
            self.close_event = event
            is_crypto = CRYPTO_ERROR_MIN <= event.error_code <= CRYPTO_ERROR_MAX
            prefix = "TLS/Crypto Alert" if is_crypto else "QUIC ConnectionTerminated"
            err = QuicTransportError(
                f"{prefix} (code={event.error_code:#x}, reason={event.reason_phrase or 'unspecified'})"
            )
            for fut in list(self._stream_futures.values()):
                if not fut.done():
                    fut.set_exception(err)
            self._stream_futures.clear()
            self._stream_headers.clear()
            self._stream_bodies.clear()
            return

        if isinstance(event, StreamReset):
            fut = self._stream_futures.pop(event.stream_id, None)
            self._stream_headers.pop(event.stream_id, None)
            self._stream_bodies.pop(event.stream_id, None)
            if fut and not fut.done():
                fut.set_exception(
                    QuicTransportError(f"QUIC stream {event.stream_id} reset (code={event.error_code:#x})")
                )
            return

        if self._h3 is not None:
            try:
                for h3_event in self._h3.handle_event(event):
                    self._h3_event_received(h3_event)
            except H3Error as exc:
                for fut in list(self._stream_futures.values()):
                    if not fut.done():
                        fut.set_exception(QuicTransportError(f"HTTP/3 framing error: {exc}"))

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            hdrs = self._stream_headers.setdefault(event.stream_id, [])
            hdrs.extend(event.headers)
            if event.stream_ended:
                self._complete_stream(event.stream_id)
        elif isinstance(event, DataReceived):
            buf = self._stream_bodies.setdefault(event.stream_id, bytearray())
            remaining = self._max_response_bytes - len(buf)
            if remaining > 0:
                buf.extend(event.data[:remaining])
            if event.stream_ended:
                self._complete_stream(event.stream_id)

    def _complete_stream(self, stream_id: int) -> None:
        fut = self._stream_futures.pop(stream_id, None)
        headers = self._stream_headers.pop(stream_id, [])
        body = bytes(self._stream_bodies.pop(stream_id, bytearray()))
        if fut and not fut.done():
            fut.set_result((headers, body))

    def detach_shielded_waiters(self) -> None:
        """Prevents unretrieved Future warnings on aioquic shielded _connected_waiter."""
        waiter = getattr(self, "_connected_waiter", None)
        if waiter is not None:
            self._connected_waiter = None
            if waiter.done() and not waiter.cancelled():
                try:
                    waiter.exception()
                except Exception:
                    pass
            elif not waiter.done():
                waiter.cancel()

        for fut in list(self._stream_futures.values()):
            if fut.done() and not fut.cancelled():
                try:
                    fut.exception()
                except Exception:
                    pass
            elif not fut.done():
                fut.cancel()
        self._stream_futures.clear()
        self._stream_headers.clear()
        self._stream_bodies.clear()

    async def send_http3_request(
        self,
        method: str,
        scheme: str,
        authority: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
        timeout: float = 4.5,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Executes an HTTP/3 request over a new bidirectional QUIC stream."""
        if self._h3 is None:
            if self.handshake_event and self.handshake_event.alpn_protocol in H3_ALPN:
                self._h3 = H3Connection(self._quic)
            else:
                raise QuicTransportError("HTTP/3 connection not negotiated via ALPN 'h3'")

        stream_id = self._quic.get_next_available_stream_id()
        fut: asyncio.Future[Tuple[List[Tuple[bytes, bytes]], bytes]] = (
            asyncio.get_running_loop().create_future()
        )
        self._stream_futures[stream_id] = fut
        self._stream_headers[stream_id] = []
        self._stream_bodies[stream_id] = bytearray()

        h3_headers: List[Tuple[bytes, bytes]] = [
            (b":method", method.upper().encode("ascii")),
            (b":scheme", scheme.lower().encode("ascii")),
            (b":authority", authority.encode("utf-8")),
            (b":path", path.encode("utf-8")),
            (b"user-agent", b"JARO-WPF/2.0 QUIC-H3-Engine"),
            (b"accept", b"*/*"),
        ]
        if headers:
            for k, v in headers.items():
                lk = k.lower().encode("ascii")
                if not lk.startswith(b":") and lk not in (b"user-agent", b"accept"):
                    h3_headers.append((lk, v.encode("utf-8")))

        has_body = len(body) > 0
        self._h3.send_headers(stream_id=stream_id, headers=h3_headers, end_stream=not has_body)
        if has_body:
            self._h3.send_data(stream_id=stream_id, data=body, end_stream=True)
        self.transmit()

        try:
            raw_headers, resp_body = await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._stream_futures.pop(stream_id, None)
            self._stream_headers.pop(stream_id, None)
            self._stream_bodies.pop(stream_id, None)

        status_code: Optional[int] = None
        decoded_headers: Dict[str, str] = {}
        for k_bytes, v_bytes in raw_headers:
            k_str = k_bytes.decode("latin1")
            v_str = v_bytes.decode("latin1")
            if k_str == ":status":
                status_code = int(v_str)
            else:
                decoded_headers[k_str.lower()] = v_str

        if status_code is None:
            raise QuicTransportError("Missing ':status' pseudo-header in HTTP/3 response")

        return status_code, decoded_headers, resp_body


def _validate_non_doq_alpn(alpn_protocols: List[str]) -> None:
    """Ensures generic QUIC / HTTP/3 engine is never misused for DNS-over-QUIC ('doq')."""
    if not alpn_protocols:
        raise ValueError("At least one ALPN protocol must be specified for QUIC transport")
    if any(proto.lower() == "doq" for proto in alpn_protocols):
        raise ValueError(
            "ALPN 'doq' belongs exclusively to DNS-over-QUIC (doq_engine.py), not generic QUIC transport"
        )


def _format_close_error(client: Optional[QuicHttp3ClientProtocol], fallback_exc: BaseException) -> Tuple[bool, str]:
    """Extracts exact TLS alert or QUIC termination reason when handshake fails."""
    if client is not None and client.close_event is not None:
        ev = client.close_event
        is_crypto = CRYPTO_ERROR_MIN <= ev.error_code <= CRYPTO_ERROR_MAX
        reason = ev.reason_phrase or fallback_exc.__class__.__name__
        if is_crypto:
            return True, f"TLSVerificationError (alert={ev.error_code:#x}): {reason}"
        return False, f"QuicTerminated (code={ev.error_code:#x}): {reason}"
    msg = str(fallback_exc) or fallback_exc.__class__.__name__
    return False, f"{fallback_exc.__class__.__name__}: {msg}"


async def async_probe_quic_handshake(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    alpn_protocols: Optional[List[str]] = None,
    cafile: Optional[str] = None,
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Performs a generic QUIC v1/v2 cryptographic handshake with strict X.509 validation."""
    alpns = list(alpn_protocols) if alpn_protocols is not None else list(H3_ALPN)
    _validate_non_doq_alpn(alpns)
    server_hostname = sni or host

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=alpns,
        server_name=server_hostname,
        verify_mode=ssl.CERT_REQUIRED,
        cafile=cafile or certifi.where(),
        idle_timeout=timeout,
        max_data=262144,
        max_stream_data=131072,
    )

    start = time.perf_counter()
    client_ref: Optional[QuicHttp3ClientProtocol] = None
    try:
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=lambda *a, **kw: QuicHttp3ClientProtocol(*a, enable_h3=False, **kw),
            wait_connected=False,
        ) as client:
            assert isinstance(client, QuicHttp3ClientProtocol)
            client_ref = client
            client.transmit()
            try:
                await asyncio.wait_for(client.wait_connected(), timeout=timeout)
            except asyncio.TimeoutError as exc:
                client.detach_shielded_waiters()
                raise TimeoutError(
                    f"QUIC handshake timed out on {host}:{port}/UDP after {timeout}s"
                ) from exc

            handshake_ms = round((time.perf_counter() - start) * 1000, 2)
            negotiated_alpn = (
                client.handshake_event.alpn_protocol if client.handshake_event else None
            )
            if negotiated_alpn not in alpns:
                raise QuicTransportError(
                    f"Unexpected negotiated ALPN {negotiated_alpn!r} (expected one of {alpns})"
                )

            client.close(error_code=QuicErrorCode.NO_ERROR, reason_phrase="probe_complete")
            return {
                "layer": "QUIC_TRANSPORT",
                "category": "application_transport",
                "host": host,
                "port": port,
                "sni": server_hostname,
                "alpn_negotiated": negotiated_alpn,
                "quic_connected": True,
                "tls_verified": True,
                "handshake_time_ms": handshake_ms,
                "error": None,
            }
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        is_tls_err, formatted = _format_close_error(client_ref, exc)
        return {
            "layer": "QUIC_TRANSPORT",
            "category": "application_transport",
            "host": host,
            "port": port,
            "sni": server_hostname,
            "alpn_negotiated": None,
            "quic_connected": False,
            "tls_verified": False,
            "tls_alert": is_tls_err,
            "handshake_time_ms": None,
            "error": formatted,
        }
    finally:
        if client_ref is not None:
            client_ref.detach_shielded_waiters()


def probe_quic_handshake(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    alpn_protocols: Optional[List[str]] = None,
    cafile: Optional[str] = None,
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Synchronous wrapper for generic QUIC handshake probing."""
    return asyncio.run(
        async_probe_quic_handshake(
            host=host,
            port=port,
            sni=sni,
            alpn_protocols=alpn_protocols,
            cafile=cafile,
            timeout=timeout,
        )
    )


async def async_request_http3(
    url: str,
    connect_host: Optional[str] = None,
    connect_port: Optional[int] = None,
    sni_hostname: Optional[str] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    expected_status: int = 200,
    expected_substring: str = "",
    cafile: Optional[str] = None,
    timeout: float = 4.5,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> Dict[str, Any]:
    """Executes a real HTTP/3 request over QUIC with TLS verification and split timing telemetry."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        return {
            "layer": "HTTP3_QUIC",
            "category": "application_transport",
            "url": url,
            "quic_connected": False,
            "tls_verified": False,
            "http3_verified": False,
            "captive_portal_suspected": False,
            "status_code": None,
            "handshake_time_ms": None,
            "response_time_ms": None,
            "total_latency_ms": None,
            "error": "ValueError: HTTP/3 requires an 'https://' URL scheme",
        }

    authority_host = sni_hostname or parsed.hostname or ""
    target_host = connect_host or parsed.hostname or ""
    target_port = connect_port or parsed.port or 443
    authority_header = (
        f"{authority_host}:{parsed.port}"
        if parsed.port and parsed.port != 443
        else authority_host
    )
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query += f"?{parsed.query}"

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=list(H3_ALPN),
        server_name=authority_host,
        verify_mode=ssl.CERT_REQUIRED,
        cafile=cafile or certifi.where(),
        idle_timeout=timeout,
        max_data=262144,
        max_stream_data=max(65536, max_response_bytes + 16384),
    )

    total_start = time.perf_counter()
    client_ref: Optional[QuicHttp3ClientProtocol] = None
    quic_connected = False
    handshake_ms: Optional[float] = None

    try:
        async with connect(
            target_host,
            target_port,
            configuration=configuration,
            create_protocol=lambda *a, **kw: QuicHttp3ClientProtocol(
                *a, enable_h3=True, max_response_bytes=max_response_bytes, **kw
            ),
            wait_connected=False,
        ) as client:
            assert isinstance(client, QuicHttp3ClientProtocol)
            client_ref = client
            client.transmit()
            try:
                await asyncio.wait_for(client.wait_connected(), timeout=timeout)
            except asyncio.TimeoutError as exc:
                client.detach_shielded_waiters()
                raise TimeoutError(
                    f"HTTP/3 QUIC handshake timed out on {target_host}:{target_port}/UDP"
                ) from exc

            handshake_ms = round((time.perf_counter() - total_start) * 1000, 2)
            quic_connected = True

            req_start = time.perf_counter()
            status_code, resp_headers, resp_bytes = await client.send_http3_request(
                method=method,
                scheme="https",
                authority=authority_header,
                path=path_and_query,
                headers=headers,
                body=body,
                timeout=timeout,
            )
            response_ms = round((time.perf_counter() - req_start) * 1000, 2)
            total_ms = round((time.perf_counter() - total_start) * 1000, 2)

            client.close(error_code=QuicErrorCode.NO_ERROR, reason_phrase="h3_complete")

            text_body = resp_bytes.decode("utf-8", errors="replace")
            location = resp_headers.get("location")
            is_redirect = status_code in (301, 302, 303, 307, 308) or location is not None
            status_match = status_code == expected_status

            if expected_status == 204 and not expected_substring:
                content_match = len(text_body.strip()) == 0
            elif expected_substring:
                content_match = expected_substring in text_body
            else:
                content_match = True

            http3_verified = status_match and content_match and not is_redirect
            captive_suspected = (
                is_redirect
                or status_code == 511
                or (status_code == 200 and bool(expected_substring) and not content_match)
            )

            err_msg: Optional[str] = None
            if not http3_verified:
                if is_redirect:
                    err_msg = f"Unexpected HTTP/3 redirect ({status_code}) to {location}"
                elif not status_match:
                    err_msg = f"Unexpected HTTP/3 status {status_code} (expected {expected_status})"
                elif not content_match:
                    err_msg = "HTTP/3 response payload did not match expected content signature"

            return {
                "layer": "HTTP3_QUIC",
                "category": "application_transport",
                "url": url,
                "connect_host": target_host,
                "port": target_port,
                "sni": authority_host,
                "alpn": "h3",
                "quic_connected": True,
                "tls_verified": True,
                "http3_verified": http3_verified,
                "captive_portal_suspected": captive_suspected,
                "status_code": status_code,
                "response_bytes": len(resp_bytes),
                "handshake_time_ms": handshake_ms,
                "response_time_ms": response_ms,
                "total_latency_ms": total_ms,
                "error": err_msg,
            }
    except Exception as exc:
        is_tls_err, formatted = _format_close_error(client_ref, exc)
        return {
            "layer": "HTTP3_QUIC",
            "category": "application_transport",
            "url": url,
            "connect_host": target_host,
            "port": target_port,
            "sni": authority_host,
            "alpn": "h3",
            "quic_connected": quic_connected,
            "tls_verified": quic_connected and not is_tls_err,
            "tls_alert": is_tls_err,
            "http3_verified": False,
            "captive_portal_suspected": is_tls_err,
            "status_code": None,
            "response_bytes": 0,
            "handshake_time_ms": handshake_ms,
            "response_time_ms": None,
            "total_latency_ms": None,
            "error": formatted,
        }
    finally:
        if client_ref is not None:
            client_ref.detach_shielded_waiters()


def request_http3(
    url: str,
    connect_host: Optional[str] = None,
    connect_port: Optional[int] = None,
    sni_hostname: Optional[str] = None,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    expected_status: int = 200,
    expected_substring: str = "",
    cafile: Optional[str] = None,
    timeout: float = 4.5,
) -> Dict[str, Any]:
    """Synchronous wrapper for HTTP/3 requests."""
    return asyncio.run(
        async_request_http3(
            url=url,
            connect_host=connect_host,
            connect_port=connect_port,
            sni_hostname=sni_hostname,
            method=method,
            headers=headers,
            body=body,
            expected_status=expected_status,
            expected_substring=expected_substring,
            cafile=cafile,
            timeout=timeout,
        )
    )


def main() -> None:
    result = request_http3(
        url="https://cloudflare-quic.com/",
        expected_status=200,
        expected_substring="Cloudflare",
        timeout=4.5,
    )
    print(json.dumps({"module": "JARO WPF QUIC/HTTP3 ENGINE", "result": result}, indent=4))


if __name__ == "__main__":
    main()
