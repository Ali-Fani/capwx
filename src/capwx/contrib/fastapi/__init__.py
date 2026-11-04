"""capwx.contrib.fastapi: FastAPI / Starlette integration for the Cap widget.

Build one :class:`Cap` for the application, mount its router, protect routes with
``Depends(cap.require(...))`` and serve the widget assets::

    from fastapi import Depends, FastAPI
    from capwx import CapConfig
    from capwx.contrib.fastapi import Cap
    from capwx.stores.memory import AsyncMemoryStore

    cap = Cap({"login": CapConfig(secret=SECRET)}, store=AsyncMemoryStore())
    app = FastAPI()
    app.include_router(cap.router, prefix="/cap")
    cap.mount_assets(app)
    cap.install(app)  # 403 body becomes {"error": "captcha_required"}

    @app.post("/orders", dependencies=[Depends(cap.require("login"))])
    async def create_order() -> dict[str, bool]: ...

Install with ``pip install 'capwx[fastapi]'``. Importing this package without fastapi raises
ImportError with that hint. ``import capwx`` never imports fastapi.
"""

from __future__ import annotations

import importlib

try:
    importlib.import_module("fastapi")
except ImportError as exc:
    raise ImportError(
        "capwx.contrib.fastapi needs fastapi, which is not installed. "
        "Install it with: pip install 'capwx[fastapi]'"
    ) from exc

from capwx.contrib.fastapi.config import Cap, SiteSettings
from capwx.contrib.fastapi.router import Blocked

__all__ = ["Blocked", "Cap", "SiteSettings"]
