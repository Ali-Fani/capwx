"""Shared helpers for the browser e2e tests (kept out of conftest.py so tests can import them)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

BASE_HOST = "127.0.0.1"


@dataclass
class Recorder:
    """Everything one test's page did on the wire and in the widget."""

    page: Any
    context: Any
    requests: list[Any] = field(default_factory=list)  # every request, any frame, any worker
    responses: list[Any] = field(default_factory=list)  # every response
    console: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)

    def responses_ending(self, suffix: str) -> list[Any]:
        return [r for r in self.responses if r.url.endswith(suffix)]

    def widget_events(self) -> list[dict[str, Any]]:
        return list(self.page.evaluate("window.__capEvents || []"))
