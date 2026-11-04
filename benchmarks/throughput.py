"""Throughput: capwx cost next to framework overhead, in one ASGI process.

Run with ``uv run python benchmarks/throughput.py`` (needs ``fastapi`` and ``httpx``, which the
unit suite already installs). Requests go through httpx's in-process ASGI transport, so no socket
or network is involved: the number is framework + capwx, with the framework floor measured by the
``/noop`` route.

Sequential requests, one worker: this is a lower bound on a multi-worker deployment.
"""

from __future__ import annotations

import asyncio
import statistics
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


async def measure(path: str, payload: dict[str, Any] | None, count: int) -> float:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://bench") as client:
        for _ in range(50):  # warm-up: engine, routes, JSON codecs
            await client.post(path, json=payload)
        started = time.perf_counter()
        for _ in range(count):
            await client.post(path, json=payload)
        return (time.perf_counter() - started) / count * 1e6


async def main() -> None:
    count = 500
    bodies = [body_for(SECRET, create_challenge(CONFIG)) for _ in range(count)]
    noop_us = await measure("/noop", None, count)
    challenge_us = await measure("/challenge", None, count)
    redeem_us = statistics.median([await measure("/redeem", body, 20) for body in bodies[:20]])
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
