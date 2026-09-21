"""Time-windowed rate limiting, independent of the existing per-turn caps
(Orchestrator's max_commands_per_request and its 6-round-trip bound).
Those bound a single turn; this bounds activity ACROSS turns -- a user (or
a UI bug, or an attacker who found some way to trigger rapid successive
messages) sending many separate short turns in quick succession, each
individually within the per-turn caps, would otherwise sail through.

Progressive restriction: a category that keeps getting rate-limited has
its effective limit tightened further on each subsequent violation within
the same window, rather than just re-applying the same limit -- repeated
abuse is treated as more suspicious than a one-off burst.
"""
from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    # (max_events, window_seconds) per category. Callers can override via
    # the constructor; these are deliberately generous defaults -- this is
    # a backstop against abuse/bugs, not a UX throttle for normal use.
    _DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        "user_message": (20, 60.0),
        "tool_execution": (40, 60.0),
        "llm_request": (60, 60.0),
    }

    def __init__(self, audit_sink=None, limits: dict[str, tuple[int, float]] | None = None) -> None:
        self.audit_sink = audit_sink
        self._limits = dict(self._DEFAULT_LIMITS)
        if limits:
            self._limits.update(limits)
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = {}
        self._violations: dict[str, int] = {}

    def _audit(self, event_type: str, **data) -> None:
        if self.audit_sink is not None:
            try:
                self.audit_sink.record(event_type=event_type, **data)
            except Exception:
                pass  # rate limiting must not itself become a fail-open path if auditing breaks

    def check_and_record(self, category: str) -> tuple[bool, str | None]:
        """Returns (allowed, reason). If allowed, the event is recorded as
        having happened (counts toward the window) in the same call --
        callers must not call this speculatively and skip recording.
        """
        now = time.monotonic()
        max_events, window = self._limits.get(category, (100, 60.0))

        with self._lock:
            bucket = self._buckets.setdefault(category, deque())
            while bucket and now - bucket[0] > window:
                bucket.popleft()

            violations = self._violations.get(category, 0)
            effective_max = max(1, max_events // (1 + min(violations, 4))) if violations else max_events

            if len(bucket) >= effective_max:
                self._violations[category] = violations + 1
                retry_after = round(window - (now - bucket[0]), 1)
                reason = (f"Rate limit exceeded for '{category}': {effective_max} per {window:.0f}s "
                          f"(tightened after {violations} prior violation(s)). Retry in {retry_after}s.")
                self._audit("rate_limit_exceeded", category=category, effective_max=effective_max,
                            window_seconds=window, violations=violations + 1, retry_after=retry_after)
                return False, reason

            bucket.append(now)
            return True, None

    def reset(self, category: str | None = None) -> None:
        """Manual override, e.g. from the Security Center."""
        with self._lock:
            if category is None:
                self._buckets.clear()
                self._violations.clear()
            else:
                self._buckets.pop(category, None)
                self._violations.pop(category, None)

    def status(self) -> dict:
        now = time.monotonic()
        with self._lock:
            out = {}
            for category, (max_events, window) in self._limits.items():
                bucket = self._buckets.get(category, deque())
                recent = sum(1 for t in bucket if now - t <= window)
                out[category] = {
                    "recent_events": recent,
                    "limit": max_events,
                    "window_seconds": window,
                    "violations": self._violations.get(category, 0),
                }
            return out
