"""Process-wide runtime support: per-thread metrics, response cache, rate budget.

Kept small and dependency-free so it can plug into the existing GitHub/OpenAI
clients without restructuring them.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .models import AnalysisMetrics


_THREAD_METRICS = threading.local()
_THREAD_COST_CAP = threading.local()


def current_metrics() -> AnalysisMetrics:
    """Return the AnalysisMetrics bound to the current thread, creating one if missing."""
    metrics = getattr(_THREAD_METRICS, "current", None)
    if metrics is None:
        metrics = AnalysisMetrics()
        _THREAD_METRICS.current = metrics
    return metrics


def reset_metrics() -> AnalysisMetrics:
    """Bind a fresh AnalysisMetrics to the current thread and return it."""
    metrics = AnalysisMetrics()
    _THREAD_METRICS.current = metrics
    return metrics


def set_cost_cap(cost_cap_usd: float | None) -> None:
    _THREAD_COST_CAP.current = cost_cap_usd


def current_cost_cap() -> float | None:
    return getattr(_THREAD_COST_CAP, "current", None)


class ResponseCache:
    """Small content-addressed JSON cache for idempotent reads.

    The cache is sharded by the first two hex characters of the key to keep
    any one directory manageable. Misses are cheap (one stat); hits are a
    single JSON read. Writes are atomic via a tmp file + rename.
    """

    def __init__(self, base_dir: Path | str, namespace: str):
        self.base = Path(base_dir) / namespace
        self._lock = threading.RLock()

    @staticmethod
    def key(*parts: Any) -> str:
        encoded = "|".join(_canonical(p) for p in parts).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def get(self, key: str) -> Any | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def set(self, key: str, value: Any) -> None:
        path = self._path(key)
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(value, default=str), encoding="utf-8")
            os.replace(tmp, path)

    def _path(self, key: str) -> Path:
        return self.base / key[:2] / f"{key}.json"


def _canonical(value: Any) -> str:
    if isinstance(value, dict):
        return json.dumps({k: value[k] for k in sorted(value)}, default=str, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return json.dumps(list(value), default=str, separators=(",", ":"))
    return str(value)


class RateBudget:
    """Process-wide token bucket for GitHub REST calls.

    A coarse hourly cap (default 4500 — below the 5000 authenticated ceiling)
    plus dynamic adjustments from response headers. Threads block in `acquire`
    when the bucket is empty until it refills, and on secondary-limit
    notifications (`Retry-After`) all callers stall together.
    """

    def __init__(self, per_hour: int = 4500):
        self._cap = per_hour
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._tokens = per_hour
        self._reset_at = time.time() + 3600.0
        self._secondary_wait_until = 0.0

    def acquire(self, timeout: float = 60.0) -> None:
        deadline = time.time() + timeout
        with self._cv:
            while True:
                now = time.time()
                if now < self._secondary_wait_until:
                    wait_for = min(self._secondary_wait_until - now, deadline - now)
                    if wait_for <= 0:
                        raise TimeoutError("rate budget timeout: secondary backoff")
                    self._cv.wait(timeout=wait_for)
                    continue
                if self._tokens > 0:
                    self._tokens -= 1
                    return
                if now >= self._reset_at:
                    self._tokens = self._cap
                    self._reset_at = now + 3600.0
                    continue
                wait_for = min(self._reset_at - now, deadline - now)
                if wait_for <= 0:
                    raise TimeoutError("rate budget timeout: window not yet reset")
                self._cv.wait(timeout=wait_for)

    def update_from_headers(self, headers: dict[str, Any] | None) -> None:
        if not headers:
            return
        remaining = _header(headers, "X-RateLimit-Remaining")
        reset = _header(headers, "X-RateLimit-Reset")
        with self._cv:
            if remaining and remaining.lstrip("-").isdigit():
                self._tokens = max(0, int(remaining))
            if reset and reset.isdigit():
                self._reset_at = float(int(reset))
            self._cv.notify_all()

    def secondary_backoff(self, retry_after_seconds: float) -> None:
        with self._cv:
            self._secondary_wait_until = max(
                self._secondary_wait_until, time.time() + max(retry_after_seconds, 1.0)
            )
            self._cv.notify_all()

    def snapshot(self) -> dict[str, Any]:
        with self._cv:
            return {
                "tokens_remaining": self._tokens,
                "window_resets_at": self._reset_at,
                "secondary_wait_until": self._secondary_wait_until,
            }


def _header(headers: dict[str, Any], name: str) -> str | None:
    for key in (name, name.lower(), name.replace("-", "_")):
        if key in headers:
            return str(headers[key])
    return None
