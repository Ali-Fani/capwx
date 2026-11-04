"""Node interop for the FastAPI router (marker ``node``): router mints, Python solves, capjs-core checks.

Run with: ``uv run pytest -m node -q tests/test_interop_node_fastapi.py``

The challenge comes from ``POST /cap/<site>/challenge`` on the FastAPI router. The solved body is
checked by capjs-core (``validateChallenge``, as ``test_python_mints_and_node_validates`` does),
then redeemed through the router, and the token is accepted once by a ``Depends(cap.require(...))``
endpoint. Reuses the capjs-core install and node scripts from ``tests/test_interop_node.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import test_interop_node as interop
from _solver import body_for
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from test_interop_node import SECRET, _node

from capwx import CapConfig
from capwx.contrib.fastapi import Cap, SiteSettings
from capwx.stores.memory import AsyncMemoryStore

pytestmark = pytest.mark.node

# The session fixture from the Django/core interop module; pytest finds it by this module attribute.
capjs_dir = interop.capjs_dir

SITE = "login"
CFG = CapConfig(secret=SECRET, protocols=("sha256-pow",), sha256_count=2, sha256_difficulty=1)


def _app() -> FastAPI:
    cap = Cap(
        {SITE: SiteSettings(config=CFG, site_secret="site-secret-0123456789")},
        store=AsyncMemoryStore(),
    )
    app = FastAPI()
    app.include_router(cap.router, prefix="/cap")
    cap.install(app)

    @app.post("/orders", dependencies=[Depends(cap.require(SITE))])
    async def orders() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_router_challenge_is_solved_and_checked_by_capjs_core(capjs_dir: Any) -> None:
    client = TestClient(_app())

    challenge = client.post(f"/cap/{SITE}/challenge")
    assert challenge.status_code == 200, challenge.content
    challenge_json = challenge.json()
    assert challenge_json["format"] == 2
    body = body_for(SECRET, challenge_json)  # Python solves the router's challenge

    out = _node(capjs_dir, "validate.mjs", {"secret": SECRET, "body": body, "opts": {}})
    assert out["success"] is True, out

    redeemed = client.post(f"/cap/{SITE}/redeem", json=body)
    assert redeemed.status_code == 200, redeemed.content
    token = redeemed.json()["token"]

    accepted = client.post("/orders", headers={"X-Cap-Token": token})
    assert accepted.status_code == 200
    assert accepted.json() == {"ok": True}

    replayed = client.post("/orders", headers={"X-Cap-Token": token})
    assert replayed.status_code == 403
    assert replayed.json() == {"error": "captcha_required"}
