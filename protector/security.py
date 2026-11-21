"""Cryptographic callback signing, ReDoS input safety, and live observability metrics."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# Telegram enforces a 4096-char max message text limit; cap safely to eliminate ReDoS surface
MAX_INSPECT_TEXT_CHARS = 4096
MAX_CALLBACK_DATA_BYTES = 64


class CallbackSigner:
    """Compact HMAC-SHA256 signer with TTL for Telegram inline callback_data (<= 64 bytes).

    Format: `<action>:<payload>:<ts_base36>:<sig10>`
    Prevents forged verification clicks and spoofed admin triage callbacks.
    """

    def __init__(self, secret_key: str | bytes | None = None) -> None:
        if secret_key:
            raw = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
            self._key = hashlib.sha256(b"aegistg-cb-v2:" + raw).digest()
        else:
            self._key = secrets.token_bytes(32)

    def sign(self, action: str, payload: str, now: float | None = None) -> str:
        ts_sec = int(now if now is not None else time.time())
        ts_b36 = _to_base36(ts_sec)
        body = f"{action}:{payload}:{ts_b36}"
        sig = self._mac(body)
        token = f"{body}:{sig}"
        if len(token.encode("utf-8")) > MAX_CALLBACK_DATA_BYTES:
            raise ValueError(
                f"Signed callback_data exceeds Telegram 64-byte limit ({len(token)} bytes): {token}"
            )
        return token

    def verify(
        self, token: str, ttl_seconds: int = 86400, now: float | None = None
    ) -> tuple[str, str] | None:
        """Verify HMAC signature and TTL. Returns (action, payload) or None if invalid/expired."""
        if not token or token.count(":") < 3:
            return None
        try:
            action, rest = token.split(":", 1)
            payload, ts_b36, provided_sig = rest.rsplit(":", 2)
        except ValueError:
            return None

        body = f"{action}:{payload}:{ts_b36}"
        expected_sig = self._mac(body)
        if not hmac.compare_digest(provided_sig, expected_sig):
            return None

        try:
            issued_at = int(ts_b36, 36)
        except ValueError:
            return None

        current = int(now if now is not None else time.time())
        if ttl_seconds > 0 and (current - issued_at > ttl_seconds or issued_at - current > 300):
            return None

        return action, payload

    def _mac(self, body: str) -> str:
        digest = hmac.new(self._key, body.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest[:10]


def _to_base36(num: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if num <= 0:
        return "0"
    chars: list[str] = []
    while num:
        num, rem = divmod(num, 36)
        chars.append(alphabet[rem])
    return "".join(reversed(chars))


def clamp_text_for_inspection(text: str) -> str:
    """Clamp oversized inputs to Telegram's spec limit to prevent ReDoS / CPU spikes."""
    if not text:
        return ""
    if len(text) <= MAX_INSPECT_TEXT_CHARS:
        return text
    return text[:MAX_INSPECT_TEXT_CHARS]


@dataclass
class RuntimeMetrics:
    """Thread-safe observability metrics for /health, /metrics, and /panel telemetry."""

    started_at: float = field(default_factory=time.time)
    updates_processed: int = 0
    threats_blocked: int = 0
    clean_allowed: int = 0
    lockdowns_triggered: int = 0
    api_requests: int = 0
    api_429_retries: int = 0
    api_errors: int = 0
    delete_batches_sent: int = 0
    delete_messages_coalesced: int = 0
    inline_scans: int = 0
    false_positives_healed: int = 0
    _latencies_ms: deque[float] = field(default_factory=lambda: deque(maxlen=500))
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_evaluation(self, blocked: bool, latency_ms: float) -> None:
        with self._lock:
            self.updates_processed += 1
            if blocked:
                self.threats_blocked += 1
            else:
                self.clean_allowed += 1
            self._latencies_ms.append(latency_ms)

    def record_api_call(self, retry_429: bool = False, error: bool = False) -> None:
        with self._lock:
            self.api_requests += 1
            if retry_429:
                self.api_429_retries += 1
            if error:
                self.api_errors += 1

    def record_delete_batch(self, count: int) -> None:
        with self._lock:
            self.delete_batches_sent += 1
            self.delete_messages_coalesced += count

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            lats = sorted(self._latencies_ms)
            avg_ms = round(sum(lats) / len(lats), 2) if lats else 0.0
            p95_ms = round(lats[int(len(lats) * 0.95) - 1], 2) if len(lats) >= 2 else avg_ms
            return {
                "uptime_seconds": int(time.time() - self.started_at),
                "updates_processed": self.updates_processed,
                "threats_blocked": self.threats_blocked,
                "clean_allowed": self.clean_allowed,
                "lockdowns_triggered": self.lockdowns_triggered,
                "inline_scans": self.inline_scans,
                "false_positives_healed": self.false_positives_healed,
                "eval_latency_avg_ms": avg_ms,
                "eval_latency_p95_ms": p95_ms,
                "api_requests": self.api_requests,
                "api_429_retries": self.api_429_retries,
                "api_errors": self.api_errors,
                "delete_batches_sent": self.delete_batches_sent,
                "delete_messages_coalesced": self.delete_messages_coalesced,
            }
