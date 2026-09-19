"""Sliding-window rate limiter (OWASP API4:2023 / CWE-770, CWE-307).

This in-memory implementation is correct for a single replica. With several
replicas each pod keeps its own counters, so the effective limit becomes
``limit * replicas``; a shared store (Redis) would be the next step, noted in
docs/controls/API4-rate-limiting.md.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from app.metrics import RATE_LIMITED


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: int = 0


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = 100_000) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def hit(self, key: str, limit: int, window_seconds: int) -> Decision:
        now = self._clock()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                if len(self._hits) >= self._max_keys:
                    self._evict(cutoff)
                bucket = self._hits[key] = deque()
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, math.ceil(bucket[0] + window_seconds - now))
                return Decision(allowed=False, retry_after=retry_after)
            bucket.append(now)
            return Decision(allowed=True)

    def _evict(self, cutoff: float) -> None:
        # Drop idle keys so a flood of unique keys (e.g. spoofed usernames)
        # cannot grow memory without bound.
        for key in [k for k, b in self._hits.items() if not b or b[-1] <= cutoff]:
            del self._hits[key]
        if len(self._hits) >= self._max_keys:
            self._hits.clear()

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def client_ip(request: Request) -> str:
    # X-Forwarded-For is deliberately NOT trusted here: it is attacker
    # controlled unless a trusted proxy rewrites it. Behind an ingress, run
    # uvicorn with --forwarded-allow-ips set to the proxy address instead.
    return request.client.host if request.client else "unknown"


def enforce(request: Request, scope: str, key: str, limit: int, window_seconds: int) -> None:
    limiter: RateLimiter = request.app.state.limiter
    decision = limiter.hit(f"{scope}:{key}", limit, window_seconds)
    if not decision.allowed:
        RATE_LIMITED.labels(scope=scope).inc()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(decision.retry_after)},
        )
