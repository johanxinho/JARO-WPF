"""JARO WPF - Active Connection Session & Diagnostic State Tracker (Phase 3)."""
from datetime import datetime, timezone
from enum import Enum
import secrets
from typing import Any, Dict, List, Optional


class SessionState(str, Enum):
    """Lifecycle states of an active JARO WPF connectivity session."""
    IDLE = "IDLE"
    EVALUATING = "EVALUATING"
    CONNECTED = "CONNECTED"
    FAILOVER_SWITCHING = "FAILOVER_SWITCHING"
    RECONNECTING = "RECONNECTING"
    BLOCKED_COST_POLICY = "BLOCKED_COST_POLICY"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"


class ConnectionSession:
    """Maintains current connection telemetry, transport switch history, and clear error diagnostics."""

    def __init__(self, max_history_entries: int = 100) -> None:
        self.session_id: str = f"jaro-{secrets.token_hex(4)}"
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self.state: SessionState = SessionState.IDLE
        self.active_protocol: Optional[str] = None
        self.active_server_id: Optional[str] = None
        self.active_server_name: Optional[str] = None
        self.active_host: Optional[str] = None
        self.active_port: Optional[int] = None
        self.active_interface: Optional[str] = None
        self.cost_profile: Optional[str] = None

        self.latency_ms: Optional[float] = None
        self.jitter_ms: Optional[float] = None
        self.packet_loss_pct: Optional[float] = None
        self.download_kbps: Optional[float] = None
        self.upload_kbps: Optional[float] = None
        self.auto_score: Optional[float] = None

        self.last_error_code: Optional[str] = None
        self.diagnostic_message: str = "Session initialized in IDLE state."
        self.failover_count: int = 0

        self._max_history = max(10, max_history_entries)
        self.transport_changes: List[Dict[str, Any]] = []

    def _append_change(self, event_record: Dict[str, Any]) -> None:
        self.transport_changes.append(event_record)
        if len(self.transport_changes) > self._max_history:
            self.transport_changes = self.transport_changes[-self._max_history :]

    def activate_transport(
        self,
        transport: Dict[str, Any],
        interface_name: Optional[str] = None,
        reason: str = "initial_selection",
    ) -> Dict[str, Any]:
        """Activates or switches to a verified transport, logging any failover transition."""
        prev_proto = self.active_protocol
        prev_server = self.active_server_id
        new_proto = transport.get("protocol")
        new_server = transport.get("server_id") or transport.get("tunnel_id")

        is_switch = (
            prev_proto is not None
            and (prev_proto != new_proto or prev_server != new_server)
        )
        if is_switch:
            self.failover_count += 1

        self.state = SessionState.CONNECTED
        self.active_protocol = new_proto
        self.active_server_id = new_server
        self.active_server_name = transport.get("server_name") or new_server
        self.active_host = transport.get("host") or transport.get("interface")
        self.active_port = transport.get("port")
        self.active_interface = interface_name or transport.get("interface")
        self.cost_profile = transport.get("cost_profile")

        self.latency_ms = transport.get("avg_latency_ms")
        self.jitter_ms = transport.get("jitter_ms")
        self.packet_loss_pct = transport.get("packet_loss_pct", 0.0)
        self.download_kbps = transport.get("download_kbps")
        self.upload_kbps = transport.get("upload_kbps")
        self.auto_score = transport.get("auto_score") or transport.get("score")

        self.last_error_code = None
        self.diagnostic_message = (
            f"Connected via verified {self.active_protocol} to {self.active_server_name} "
            f"({self.active_host}:{self.active_port}) at {self.latency_ms} ms."
        )

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "TRANSPORT_FAILOVER" if is_switch else "TRANSPORT_CONNECTED",
            "reason": reason,
            "from_protocol": prev_proto,
            "from_server": prev_server,
            "to_protocol": self.active_protocol,
            "to_server": self.active_server_id,
            "host": self.active_host,
            "latency_ms": self.latency_ms,
            "score": self.auto_score,
        }
        self._append_change(record)
        return record

    def mark_blocked_by_cost(self, reason: str, cost_profile: str = "metered") -> None:
        """Records clear policy block diagnostics when metered connections are unauthorized."""
        self.state = SessionState.BLOCKED_COST_POLICY
        self.cost_profile = cost_profile
        self.last_error_code = "COST_POLICY_BLOCKED"
        self.diagnostic_message = reason
        self._append_change({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "SESSION_BLOCKED_COST",
            "reason": reason,
            "cost_profile": cost_profile,
        })

    def mark_disconnected(self, error_code: str, diagnostic: str) -> None:
        """Clears active transport when network drops or all failover candidates fail."""
        prev_proto = self.active_protocol
        prev_srv = self.active_server_id

        self.state = (
            SessionState.DISCONNECTED
            if error_code == "NO_NETWORK"
            else SessionState.ERROR
        )
        self.active_protocol = None
        self.active_server_id = None
        self.active_server_name = None
        self.active_host = None
        self.active_port = None
        self.latency_ms = None
        self.last_error_code = error_code
        self.diagnostic_message = diagnostic

        self._append_change({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "SESSION_DISCONNECTED",
            "from_protocol": prev_proto,
            "from_server": prev_srv,
            "error_code": error_code,
            "diagnostic": diagnostic,
        })

    def snapshot(self) -> Dict[str, Any]:
        """Returns a serializable status snapshot with full diagnostics."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "state": self.state.value,
            "protocol": self.active_protocol,
            "server_id": self.active_server_id,
            "server_name": self.active_server_name,
            "host": self.active_host,
            "port": self.active_port,
            "interface": self.active_interface,
            "cost_profile": self.cost_profile,
            "telemetry": {
                "latency_ms": self.latency_ms,
                "jitter_ms": self.jitter_ms,
                "packet_loss_pct": self.packet_loss_pct,
                "download_kbps": self.download_kbps,
                "upload_kbps": self.upload_kbps,
                "auto_score": self.auto_score,
            },
            "diagnostics": {
                "error_code": self.last_error_code,
                "message": self.diagnostic_message,
                "failover_count": self.failover_count,
            },
            "transport_changes": list(self.transport_changes),
        }
