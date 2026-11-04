"""JARO WPF - Exponential Backoff, Jitter & Circuit-Breaker Reconnection Manager."""
import random
import time
from typing import Any, Callable, Dict, List, Optional

MAX_ALLOWED_ATTEMPTS = 10


class ExponentialBackoffReconnector:
    """Manages connection retries with exponential backoff, jitter, time budget, and circuit breaking."""

    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        factor: float = 2.0,
        jitter_ratio: float = 0.15,
        max_attempts: int = 5,
        max_total_duration_s: float = 180.0,
        circuit_cooldown_s: float = 30.0,
        sleep_fn: Callable[[float], None] = time.sleep,
        clock_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        if base_delay <= 0 or max_delay < base_delay or factor < 1.0:
            raise ValueError("Invalid backoff delay or factor parameters")
        if not (0.0 <= jitter_ratio <= 0.5):
            raise ValueError("jitter_ratio must be between 0.0 and 0.5")
        if not (1 <= max_attempts <= MAX_ALLOWED_ATTEMPTS):
            raise ValueError(f"max_attempts must be between 1 and {MAX_ALLOWED_ATTEMPTS}")
        if max_total_duration_s <= 0 or circuit_cooldown_s < 0:
            raise ValueError("Duration and cooldown parameters must be non-negative")

        self.base_delay = base_delay
        self.max_delay = max_delay
        self.factor = factor
        self.jitter_ratio = jitter_ratio
        self.max_attempts = max_attempts
        self.max_total_duration_s = max_total_duration_s
        self.circuit_cooldown_s = circuit_cooldown_s
        self._sleep_fn = sleep_fn
        self._clock_fn = clock_fn

        self.attempt = 0
        self.consecutive_exhaustions = 0
        self.circuit_open_until: float = 0.0
        self.history: List[Dict[str, Any]] = []

    def is_circuit_open(self) -> bool:
        """Returns True if the circuit breaker is currently open to prevent reconnection loops."""
        return self._clock_fn() < self.circuit_open_until

    def compute_delay(self, attempt_number: int) -> float:
        """Calculates backoff wait time for a 1-indexed attempt number."""
        raw_delay = min(self.max_delay, self.base_delay * (self.factor ** (attempt_number - 1)))
        jitter_span = raw_delay * self.jitter_ratio
        jitter = random.uniform(-jitter_span, jitter_span) if jitter_span > 0 else 0.0
        return max(0.0, round(raw_delay + jitter, 3))

    def reset(self) -> None:
        """Resets the retry counter and circuit breaker after a verified connection is established."""
        self.attempt = 0
        self.consecutive_exhaustions = 0
        self.circuit_open_until = 0.0

    def execute_with_retry(
        self,
        connect_fn: Callable[[], Dict[str, Any]],
        is_success_fn: Callable[[Dict[str, Any]], bool],
        should_abort_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> Dict[str, Any]:
        """Executes connect_fn up to max_attempts unless circuit is open, aborted, or budget expires."""
        now = self._clock_fn()
        if now < self.circuit_open_until:
            remaining_cooldown = round(self.circuit_open_until - now, 2)
            return {
                "connected": False,
                "circuit_breaker_tripped": True,
                "aborted_non_retryable": False,
                "cooldown_remaining_s": remaining_cooldown,
                "attempts_used": 0,
                "final_result": {"error": f"Circuit breaker open for {remaining_cooldown}s"},
                "history": list(self.history),
            }

        self.history.clear()
        self.attempt = 0
        cycle_start = self._clock_fn()
        total_waited = 0.0
        result: Dict[str, Any] = {}

        while self.attempt < self.max_attempts:
            self.attempt += 1
            start_ts = self._clock_fn()
            try:
                result = connect_fn()
                succeeded = bool(is_success_fn(result))
                error_msg: Optional[str] = None
            except Exception as exc:
                result = {"error": str(exc)}
                succeeded = False
                error_msg = str(exc)

            elapsed_ms = round((self._clock_fn() - start_ts) * 1000, 2)

            if succeeded:
                self.history.append({
                    "attempt": self.attempt,
                    "succeeded": True,
                    "elapsed_ms": elapsed_ms,
                    "backoff_wait_s": 0.0,
                })
                self.reset()
                return {
                    "connected": True,
                    "circuit_breaker_tripped": False,
                    "aborted_non_retryable": False,
                    "attempts_used": len(self.history),
                    "final_result": result,
                    "history": list(self.history),
                }

            if should_abort_fn is not None and should_abort_fn(result):
                self.history.append({
                    "attempt": self.attempt,
                    "succeeded": False,
                    "aborted": True,
                    "elapsed_ms": elapsed_ms,
                    "backoff_wait_s": 0.0,
                    "error": error_msg or result.get("error") or result.get("status"),
                })
                return {
                    "connected": False,
                    "circuit_breaker_tripped": False,
                    "aborted_non_retryable": True,
                    "attempts_used": len(self.history),
                    "final_result": result,
                    "history": list(self.history),
                }

            wait_s = self.compute_delay(self.attempt) if self.attempt < self.max_attempts else 0.0
            elapsed_total = (self._clock_fn() - cycle_start) + total_waited
            if wait_s > 0 and (elapsed_total + wait_s) > self.max_total_duration_s:
                # Cap or stop if retry time budget would be exceeded
                self.history.append({
                    "attempt": self.attempt,
                    "succeeded": False,
                    "budget_exceeded": True,
                    "elapsed_ms": elapsed_ms,
                    "backoff_wait_s": 0.0,
                    "error": "Max total retry duration budget exceeded",
                })
                break

            self.history.append({
                "attempt": self.attempt,
                "succeeded": False,
                "elapsed_ms": elapsed_ms,
                "backoff_wait_s": wait_s,
                "error": error_msg or result.get("error"),
            })

            if wait_s > 0:
                self._sleep_fn(wait_s)
                total_waited += wait_s

        # All attempts exhausted -> trip circuit breaker to prevent rapid outer-loop reconnection storms
        self.consecutive_exhaustions += 1
        self.circuit_open_until = self._clock_fn() + (
            self.circuit_cooldown_s * min(4, self.consecutive_exhaustions)
        )
        return {
            "connected": False,
            "circuit_breaker_tripped": True,
            "aborted_non_retryable": False,
            "attempts_used": len(self.history),
            "final_result": result,
            "history": list(self.history),
        }
