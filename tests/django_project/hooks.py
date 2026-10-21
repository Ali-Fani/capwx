"""Hooks named in the test CAPWX settings. CALLS records invocations for assertions."""

from __future__ import annotations

from typing import Any

from django.core.exceptions import PermissionDenied

CALLS: list[tuple[str, str]] = []
BLOCKED_IP = "203.0.113.9"


def difficulty(request: Any, site: str) -> dict[str, Any] | None:
    CALLS.append(("difficulty", site))
    if request.META.get("HTTP_X_HARD"):
        return {"hashwx_difficulty": 4000}  # d = 1000 per challenge instead of 250
    return None


def before_challenge(request: Any, site: str) -> None:
    CALLS.append(("before", site))
    if request.META.get("REMOTE_ADDR") == BLOCKED_IP:
        raise PermissionDenied("blocked by test hook")


def bad_difficulty(request: Any, site: str) -> str:
    """A misconfigured hook: DIFFICULTY_HOOK must return a dict or None."""
    return "not a mapping"
