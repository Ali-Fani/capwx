"""Throughput: capwx cost next to framework overhead, in one ASGI process.

Run with ``uv run python benchmarks/throughput.py`` (needs ``fastapi`` and ``httpx``, which the
unit suite already installs). Requests go through httpx's in-process ASGI transport, so no socket
or network is involved: the number is framework + capwx, with the framework floor measured by the
``/noop`` route.

Sequential requests, one worker: this is a lower bound on a multi-worker deployment.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from fastapi import FastAPI, Request

from capwx import CapConfig, MemoryStore, create_challenge, redeem
from tests._solver import body_for

SECRET = "capwx-throughput-secret-0123"
CONFIG = CapConfig(secret=SECRET, hashwx_difficulty=400)
STORE = MemoryStore()

app = FastAPI()


@app.post("/noop")
async def noop() -> dict[str, bool]:
    return {"ok": True}


@app.post("/challenge")
async def challenge() -> dict[str, Any]:
    return create_challenge(CONFIG)


@app.post("/redeem")
async def redeem_one(request: Request) -> dict[str, Any]:
    body = await request.json()
    return redeem(CONFIG, body, nonce_store=STORE, token_store=STORE).to_widget_json()


WARMUP = 50


async def measure(path: str, payloads: list[dict[str, Any] | None]) -> float:
    """Microseconds per request. One payload per request: a solved body redeems only once."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://bench") as client:
        for payload in payloads[:WARMUP]:  # warm-up: engine, routes, JSON codecs
            await client.post(path, json=payload)
        timed = payloads[WARMUP:]
        started = time.perf_counter()
        for payload in timed:
            await client.post(path, json=payload)
        return (time.perf_counter() - started) / len(timed) * 1e6


async def main() -> None:
    count = 500
    # Solved outside the timed region; each is redeemed exactly once, so /redeem succeeds.
    bodies: list[dict[str, Any] | None] = [
        body_for(SECRET, create_challenge(CONFIG)) for _ in range(WARMUP + count)
    ]
    empty: list[dict[str, Any] | None] = [None] * (WARMUP + count)
    noop_us = await measure("/noop", empty)
    challenge_us = await measure("/challenge", empty)
    redeem_us = await measure("/redeem", bodies)
    print(f"Python {sys.version.split()[0]}, FastAPI + httpx ASGI transport, sequential requests")
    print()
    print("| Route | us/request | requests/s |")
    print("|---|---|---|")
    for name, us in (("/noop", noop_us), ("/challenge", challenge_us), ("/redeem", redeem_us)):
        print(f"| `{name}` | {us:.0f} | {1e6 / us:,.0f} |")
    print()
    print(f"capwx share of a challenge request: {(challenge_us - noop_us) / challenge_us:.0%}")
    print(f"capwx share of a redeem request:    {(redeem_us - noop_us) / redeem_us:.0%}")


if __name__ == "__main__":
    asyncio.run(main())
