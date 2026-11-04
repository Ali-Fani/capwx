"""capwx.contrib.fastapi.config: :class:`Cap`, the object an application configures capwx with.

``Cap`` checks its whole configuration when it is built and raises ``CapwxError`` for anything
wrong: no sites, a store that is not async, a hashwx site on a platform without wasmtime, or a hook
that is not callable. Client input never reaches these checks.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, Request
from starlette.applications import Starlette

from capwx import CapConfig, CapwxError, hashwx_available
from capwx.contrib.fastapi import assets, templates
from capwx.contrib.fastapi.deps import (
    DEFAULT_SITE,
    TOKEN_FIELD,
    TOKEN_HEADER,
    install_handler,
    make_require,
)
from capwx.contrib.fastapi.router import build_router
from capwx.stores import is_async_store

BeforeChallengeHook = Callable[[Request, str], Awaitable[None] | None]
DifficultyHook = Callable[
    [Request, str], Mapping[str, Any] | None | Awaitable[Mapping[str, Any] | None]
]

_SITE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_STORE_METHODS = ("claim", "put", "take")


@dataclass(frozen=True)
class SiteSettings:
    """One site's configuration. ``site_secret`` enables ``/siteverify`` for that site."""

    config: CapConfig
    site_secret: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.site_secret is not None and not self.site_secret:
            raise CapwxError("site_secret must be a non-empty string")


class Cap:
    """The capwx integration for one FastAPI/Starlette application.

    ``sites`` maps a site name to its :class:`CapConfig` (or a :class:`SiteSettings` with a
    ``site_secret``). ``store`` must be an async store, such as
    :class:`capwx.stores.memory.AsyncMemoryStore` or ``AsyncRedisStore``; it holds the replay and
    token state. ``before_challenge(request, site)`` may raise :class:`Blocked` (403) or
    ``HTTPException``. ``difficulty_hook(request, site)`` returns config overrides or None. Both
    may be sync or async. ``script_nonce`` is the default CSP nonce for :meth:`scripts`.
    """

    def __init__(
        self,
        sites: Mapping[str, CapConfig | SiteSettings],
        *,
        store: object,
        before_challenge: BeforeChallengeHook | None = None,
        difficulty_hook: DifficultyHook | None = None,
        script_nonce: str | None = None,
    ) -> None:
        if not sites:
            raise CapwxError("Cap needs at least one site in sites")
        pairs: list[tuple[str, object]] = list(sites.items())
        resolved: dict[str, SiteSettings] = {}
        for name, value in pairs:
            if not _SITE_NAME_RE.fullmatch(name):
                raise CapwxError(f"site name {name!r} must match [A-Za-z0-9_.-]{{1,64}}")
            if isinstance(value, SiteSettings):
                entry = value
            elif isinstance(value, CapConfig):
                entry = SiteSettings(config=value)
            else:
                raise CapwxError(f"site {name!r} must be a CapConfig or a SiteSettings")
            if "hashwx" in entry.config.protocols and not hashwx_available():
                raise CapwxError(
                    f"site {name!r} uses hashwx, but wasmtime is not available on this platform; "
                    "use protocols=('sha256-pow', 'instrumentation') or install wasmtime"
                )
            resolved[name] = entry

        raw_store: object = store
        if not all(callable(getattr(raw_store, m, None)) for m in _STORE_METHODS):
            raise CapwxError("store must provide claim(), put() and take()")
        if not is_async_store(raw_store):
            raise CapwxError(
                "store must be async (its methods are 'async def'), for example "
                "capwx.stores.memory.AsyncMemoryStore; a sync store blocks the event loop"
            )

        for label, hook in (
            ("before_challenge", before_challenge),
            ("difficulty_hook", difficulty_hook),
        ):
            if hook is not None and not callable(hook):
                raise CapwxError(f"{label} must be callable or None")

        self.sites: Mapping[str, SiteSettings] = resolved
        self.store: object = raw_store
        self.before_challenge: BeforeChallengeHook | None = before_challenge
        self.difficulty_hook: DifficultyHook | None = difficulty_hook
        self.script_nonce: str | None = script_nonce
        self.router: APIRouter = build_router(self)

    def _site(self, site: str) -> SiteSettings:
        found = self.sites.get(site)
        if found is None:
            raise CapwxError(f"site {site!r} is not configured in this Cap")
        return found

    def require(
        self, site: str = DEFAULT_SITE, header: str = TOKEN_HEADER, field: str = TOKEN_FIELD
    ) -> Callable[[Request], Awaitable[None]]:
        """A FastAPI dependency: ``Depends(cap.require("login"))``. Raises 403 captcha_required
        unless the request carries a valid, unused token for ``site``."""
        self._site(site)
        return make_require(self, site, header, field)

    def install(self, app: Starlette) -> None:
        """Make :class:`CaptchaRequired` answer ``403 {"error": "captcha_required"}``."""
        install_handler(app)

    def mount_assets(self, app: Starlette, path: str = "/cap-static") -> None:
        """Serve the vendored widget files under ``path`` after checking their hashes."""
        assets.mount_assets(app, path)

    def scripts(self, *, static_path: str = "/cap-static", nonce: str | None = None) -> str:
        """The ``<script>`` tags that configure and load the widget. Put them before the form."""
        return templates.render_scripts(
            static_path, nonce if nonce is not None else self.script_nonce
        )

    def widget(self, site: str, endpoint: str | None = None, field: str = TOKEN_FIELD) -> str:
        """The ``<cap-widget>`` element for ``site``. ``endpoint`` defaults to ``/cap/<site>/``,
        which matches ``app.include_router(cap.router, prefix="/cap")``."""
        self._site(site)
        return templates.render_widget(endpoint or f"/cap/{site}/", field)


__all__ = ["BeforeChallengeHook", "Cap", "DifficultyHook", "SiteSettings"]
