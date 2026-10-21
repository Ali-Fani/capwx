"""Test-only solver: stands in for the browser widget. NOT part of the package.

Solves sha256-pow and hashwx from the public challenge payloads, and instrumentation from the
decrypted expected entry (state = the expected variable values, no probe).
"""

from __future__ import annotations

import hashlib
from typing import Any

from capwx._crypto import decrypt_gcm, jwt_verify
from capwx.protocols import hashwx

FORMAT_INFO = "cap:fmt2-v1"
_U64 = (1 << 64) - 1


def solve_sha256_pow(payload: dict[str, Any]) -> dict[str, Any]:
    salt, target = payload["salt"], payload["target"]
    nonce = 0
    while not hashlib.sha256((salt + str(nonce)).encode("utf-8")).hexdigest().startswith(target):
        nonce += 1
    return {"nonce": nonce}


def solve_hashwx(payload: dict[str, Any]) -> dict[str, Any]:
    challenge = bytes.fromhex(payload["c"])
    target = _U64 // payload["d"]
    per_hash = payload["n"]
    engine = hashwx.get_engine()
    nonce = 0
    while True:
        block = nonce // per_hash
        seed = hashlib.sha256(challenge + block.to_bytes(8, "little")).digest()
        if engine.hash(seed, nonce) <= target:
            return {"nonce": nonce}
        nonce += 1


def solve_instrumentation(entry: dict[str, Any]) -> dict[str, Any]:
    meta = entry["instrMeta"]
    state = dict(zip(meta["vars"], meta["expectedVals"]))
    return {"instr": {"i": meta["id"], "state": state}}


def expected_entries(secret: str | bytes, token: str) -> list[dict[str, Any]]:
    """Decrypt the expected list from a token (the solver knows what it must answer)."""
    payload = jwt_verify(token, secret)
    assert payload is not None, "token must verify with the secret"
    decrypted = decrypt_gcm(payload["ev"], secret, FORMAT_INFO)
    assert decrypted is not None
    return decrypted["expected"]


def solve(secret: str | bytes, challenge_response: dict[str, Any]) -> list[dict[str, Any]]:
    """Solve every challenge in a create_challenge() response, in order."""
    expected = expected_entries(secret, challenge_response["token"])
    solutions: list[dict[str, Any]] = []
    for public, entry in zip(challenge_response["challenges"], expected):
        proto = public["protocol"]
        if proto == "sha256-pow":
            solutions.append(solve_sha256_pow(public["payload"]))
        elif proto == "hashwx":
            solutions.append(solve_hashwx(public["payload"]))
        elif proto == "instrumentation":
            solutions.append(solve_instrumentation(entry))
        else:  # pragma: no cover - test misuse
            raise AssertionError(f"solver does not know {proto!r}")
    return solutions


def body_for(secret: str | bytes, challenge_response: dict[str, Any]) -> dict[str, Any]:
    """The widget's POST body for a freshly solved challenge."""
    return {
        "token": challenge_response["token"],
        "solutions": solve(secret, challenge_response),
    }
