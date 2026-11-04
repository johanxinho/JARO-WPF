"""JARO WPF - DNS over QUIC (DoQ - RFC 9250) Engine using aioquic."""
import asyncio
import json
import ssl
import struct
import time
from typing import Any, Dict

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)
import certifi

from core.network_tests.connectivity_prober import parse_dns_response_ips
from core.protocols.udp_engine import create_dns_query

DOQ_ALPN = ["doq"]


class DoQProtocolError(Exception):
    """Raised when a peer violates RFC 9250 framing or QUIC stream rules."""


class DoQClientProtocol(QuicConnectionProtocol):
    """RFC 9250 compliant DNS-over-QUIC protocol handler."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._responses: Dict[int, asyncio.Future[bytes]] = {}
        self._buffers: Dict[int, bytearray] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            buf = self._buffers.setdefault(event.stream_id, bytearray())
            buf.extend(event.data)
            if event.end_stream:
                future = self._responses.pop(event.stream_id, None)
                if future and not future.done():
                    future.set_result(bytes(buf))
        elif isinstance(event, StreamReset):
            future = self._responses.pop(event.stream_id, None)
            self._buffers.pop(event.stream_id, None)
            if future and not future.done():
                future.set_exception(
                    DoQProtocolError(f"QUIC stream {event.stream_id} reset with code {event.error_code:#x}")
                )
        elif isinstance(event, ConnectionTerminated):
            err = DoQProtocolError(
                f"QUIC connection terminated (error_code={event.error_code:#x}, reason={event.reason_phrase})"
            )
            for stream_id, future in list(self._responses.items()):
                if not future.done():
                    future.set_exception(err)
            self._responses.clear()
            self._buffers.clear()

    def cleanup_pending_futures(self) -> None:
        """Consumes any exceptions on internal waiters to prevent unretrieved Future warnings."""
        waiter = getattr(self, "_connected_waiter", None)
        if waiter is not None and waiter.done() and not waiter.cancelled():
            try:
                waiter.exception()
            except Exception:
                pass
        for future in self._responses.values():
            if future.done() and not future.cancelled():
                try:
                    future.exception()
                except Exception:
                    pass
            elif not future.done():
                future.cancel()
        self._responses.clear()
        self._buffers.clear()

    async def query(self, dns_wire_query: bytes, timeout: float = 4.0) -> bytes:
        """Sends a 2-byte length-prefixed DNS query over a dedicated QUIC stream (RFC 9250 Section 4.2)."""
        if len(dns_wire_query) < 12:
            raise DoQProtocolError("DNS wire query shorter than 12-byte RFC 1035 header")

        stream_id = self._quic.get_next_available_stream_id()
        future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        self._responses[stream_id] = future
        self._buffers[stream_id] = bytearray()

        # RFC 9250 Section 4.2.1: Message ID MUST be set to 0 for DoQ queries
        zero_id_query = b"\x00\x00" + dns_wire_query[2:]
        framed_payload = struct.pack("!H", len(zero_id_query)) + zero_id_query

        # RFC 9250 Section 4.2: Client MUST indicate STREAM FIN after sending the single query
        self._quic.send_stream_data(stream_id, framed_payload, end_stream=True)
        self.transmit()

        try:
            raw_response = await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._responses.pop(stream_id, None)
            self._buffers.pop(stream_id, None)

        if len(raw_response) < 2:
            raise DoQProtocolError("DoQ response shorter than 2-byte length prefix")

        expected_len = struct.unpack("!H", raw_response[:2])[0]
        if expected_len < 12:
            raise DoQProtocolError(f"DoQ declared DNS message length ({expected_len}) < 12 bytes")

        dns_message = raw_response[2 : 2 + expected_len]
        if len(dns_message) < expected_len:
            raise DoQProtocolError(
                f"Truncated DoQ DNS payload (received {len(dns_message)} of {expected_len} bytes)"
            )
        if len(raw_response) > 2 + expected_len:
            raise DoQProtocolError(
                f"Trailing bytes after DoQ message ({len(raw_response) - 2 - expected_len} extra bytes)"
            )

        return dns_message


async def async_probe_doq(
    host: str = "94.140.14.14",
    port: int = 853,
    sni: str = "dns.adguard-dns.com",
    domain: str = "example.com",
    timeout: float = 3.5,
    cafile: str | None = None,
) -> Dict[str, Any]:
    """Executes a real RFC 9250 DoQ query and verifies the cryptographic QUIC handshake and DNS response."""
    if not sni:
        return {
            "layer": "DOQ_RFC9250",
            "host": host,
            "port": port,
            "sni": sni,
            "alpn": "doq",
            "quic_connected": False,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": "ValueError: SNI hostname is required for RFC 9250 TLS verification",
        }

    _, raw_query = create_dns_query(domain)
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=DOQ_ALPN,
        server_name=sni,
        verify_mode=ssl.CERT_REQUIRED,
        cafile=cafile or certifi.where(),
        idle_timeout=timeout,
        max_data=131072,
        max_stream_data=65536,
    )

    start = time.perf_counter()
    client_ref: Any = None
    try:
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=DoQClientProtocol,
            wait_connected=False,
        ) as client:
            assert isinstance(client, DoQClientProtocol)
            client_ref = client
            client.transmit()
            try:
                await asyncio.wait_for(client.wait_connected(), timeout=timeout)
            except asyncio.TimeoutError as exc:
                # Detach and cancel shielded _connected_waiter BEFORE __aexit__ calls close()
                waiter = getattr(client, "_connected_waiter", None)
                if waiter is not None:
                    client._connected_waiter = None
                    if not waiter.done():
                        waiter.cancel()
                raise TimeoutError(
                    f"QUIC handshake timed out on {host}:{port}/UDP (port filtered or unreachable)"
                ) from exc

            dns_response = await client.query(raw_query, timeout=timeout)
            latency_ms = round((time.perf_counter() - start) * 1000, 2)

            # RFC 9250 Section 4.2.1: Response Message ID MUST be 0
            parsed = parse_dns_response_ips(dns_response, expected_txid=0)
            return {
                "layer": "DOQ_RFC9250",
                "host": host,
                "port": port,
                "sni": sni,
                "alpn": "doq",
                "quic_connected": True,
                "protocol_verified": parsed["valid"],
                "answers": parsed.get("answers", 0),
                "latency_ms": latency_ms if parsed["valid"] else None,
                "error": parsed.get("error"),
            }
    except Exception as exc:
        err_text = str(exc) or exc.__class__.__name__
        return {
            "layer": "DOQ_RFC9250",
            "host": host,
            "port": port,
            "sni": sni,
            "alpn": "doq",
            "quic_connected": False,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": f"{exc.__class__.__name__}: {err_text}",
        }
    finally:
        if client_ref is not None and isinstance(client_ref, DoQClientProtocol):
            client_ref.cleanup_pending_futures()


def probe_doq(
    host: str = "94.140.14.14",
    port: int = 853,
    sni: str = "dns.adguard-dns.com",
    domain: str = "example.com",
    timeout: float = 3.5,
    cafile: str | None = None,
) -> Dict[str, Any]:
    """Synchronous wrapper for DoQ probing."""
    try:
        return asyncio.run(
            async_probe_doq(
                host=host,
                port=port,
                sni=sni,
                domain=domain,
                timeout=timeout,
                cafile=cafile,
            )
        )
    except Exception as exc:
        err_text = str(exc) or exc.__class__.__name__
        return {
            "layer": "DOQ_RFC9250",
            "host": host,
            "port": port,
            "sni": sni,
            "alpn": "doq",
            "quic_connected": False,
            "protocol_verified": False,
            "answers": 0,
            "latency_ms": None,
            "error": f"{exc.__class__.__name__}: {err_text}",
        }


def main() -> None:
    result = probe_doq()
    print(json.dumps({"module": "JARO WPF DOQ ENGINE", "result": result}, indent=4))


if __name__ == "__main__":
    main()
