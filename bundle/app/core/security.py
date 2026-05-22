"""Small security helpers that can be tested without FastAPI."""
from __future__ import annotations

import time
from dataclasses import dataclass, field


TRUE_VALUES = {"1", "true", "yes", "on", "y"}
FALSE_VALUES = {"0", "false", "no", "off", "n"}


def as_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    return default


@dataclass
class LoginAttemptLimiter:
    """In-memory throttling for repeated login failures.

    This is intentionally process-local. It avoids adding a database or changing
    the deployment shape, while still slowing down brute-force attempts.
    """

    max_attempts: int = 5
    window_seconds: int = 300
    lockout_seconds: int = 300
    now_func: object = time.time
    failures: dict[str, list[float]] = field(default_factory=dict)
    locked_until: dict[str, float] = field(default_factory=dict)

    def _now(self) -> float:
        return float(self.now_func())

    def _prune(self, key: str, now: float) -> list[float]:
        recent = [t for t in self.failures.get(key, []) if now - t <= self.window_seconds]
        if recent:
            self.failures[key] = recent
        else:
            self.failures.pop(key, None)
        return recent

    def retry_after(self, key: str) -> int:
        now = self._now()
        until = self.locked_until.get(key, 0)
        if until <= now:
            self.locked_until.pop(key, None)
            return 0
        return max(1, int(until - now))

    def allow(self, key: str) -> bool:
        return self.retry_after(key) <= 0

    def record_failure(self, key: str) -> int:
        now = self._now()
        recent = self._prune(key, now)
        recent.append(now)
        self.failures[key] = recent
        if len(recent) >= self.max_attempts:
            self.locked_until[key] = now + self.lockout_seconds
            return self.lockout_seconds
        return 0

    def record_success(self, key: str) -> None:
        self.failures.pop(key, None)
        self.locked_until.pop(key, None)
