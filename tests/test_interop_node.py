"""Node interop (marker ``node``): capwx <-> capjs-core 0.1.5 (plan §13.2).

Run with: ``uv run pytest -m node tests/test_interop_node.py``

Installs ``capjs-core@0.1.5`` into a temp directory that has its own package.json, so npm never
walks up into a parent project. Skips (does not fail) when node, npm or the network is missing.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from _solver import body_for

from capwx import CapConfig, MemoryStore, create_challenge, redeem
from capwx.errors import Reason

pytestmark = pytest.mark.node

SECRET = "node-interop-secret-0123456789"  # >= 16 bytes
NODE = shutil.which("node")
NPM = shutil.which("npm")

MINT_MJS = """\
import { generateChallenge } from "capjs-core";
const input = JSON.parse(await readStdin());
const out = await generateChallenge(input.secret, input.opts);
process.stdout.write(JSON.stringify(out));
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}
"""

VALIDATE_MJS = """\
import { validateChallenge } from "capjs-core";
const input = JSON.parse(await readStdin());
const out = await validateChallenge(input.secret, input.body, input.opts || {});
process.stdout.write(JSON.stringify(out));
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}
"""


@pytest.fixture(scope="session")
def capjs_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if NODE is None or NPM is None:
        pytest.skip("node and npm are needed for the interop tests")
    root = tmp_path_factory.mktemp("capjs-core")
    (root / "package.json").write_text(
        json.dumps({"name": "capwx-interop", "private": True, "type": "module"}), encoding="utf-8"
    )
    (root / "mint.mjs").write_text(MINT_MJS, encoding="utf-8")
    (root / "validate.mjs").write_text(VALIDATE_MJS, encoding="utf-8")
    proc = subprocess.run(
        [NPM, "install", "--no-audit", "--no-fund", "--prefix", str(root), "capjs-core@0.1.5"],
        check=False,
        cwd=root,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        pytest.skip(f"npm install capjs-core@0.1.5 failed: {proc.stderr[-400:]}")
    return root


def _node(capjs_dir: Path, script: str, payload: dict[str, Any]) -> Any:
    assert NODE is not None
    proc = subprocess.run(
        [NODE, script],
        input=json.dumps(payload),
        check=False,
        cwd=capjs_dir,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _mint_with_node(capjs_dir: Path, protocols: list[str], **opts: Any) -> dict[str, Any]:
    payload = {"secret": SECRET, "opts": {"format": 2, "protocols": protocols, **opts}}
    return _node(capjs_dir, "mint.mjs", payload)


PROTOCOL_CASES = [
    pytest.param(
        ["sha256-pow"],
        {"challengeCount": 2, "challengeDifficulty": 1},
        {"sha256_count": 2, "sha256_difficulty": 1},
        id="sha256-pow",
    ),
    pytest.param(
        ["hashwx"],
        {"hashwxDifficulty": 20, "hashwxChallengeCount": 2},
        {"hashwx_difficulty": 20, "hashwx_challenge_count": 2},
        id="hashwx",
    ),
    pytest.param(
        ["sha256-pow", "hashwx"],
        {
            "challengeCount": 1,
            "challengeDifficulty": 1,
            "hashwxDifficulty": 20,
            "hashwxChallengeCount": 2,
        },
        {
            "sha256_count": 1,
            "sha256_difficulty": 1,
            "hashwx_difficulty": 20,
            "hashwx_challenge_count": 2,
        },
        id="sha256-pow+hashwx",
    ),
]


@pytest.mark.parametrize("protocols, node_opts, py_opts", PROTOCOL_CASES)
def test_node_mints_and_python_solves_and_redeems(
    capjs_dir: Path, protocols: list[str], node_opts: dict[str, Any], py_opts: dict[str, Any]
) -> None:
    resp = _mint_with_node(capjs_dir, protocols, **node_opts)
    assert resp["format"] == 2
    assert set(resp) >= {"token", "challenges", "expires"}

    cfg = CapConfig(secret=SECRET, protocols=tuple(protocols), **py_opts)
    body = body_for(SECRET, resp)  # solves the Node payloads and decrypts the Node token
    result = redeem(cfg, body, nonce_store=MemoryStore(), token_store=MemoryStore())
    assert result.success, result.reason
    assert result.token is not None


@pytest.mark.parametrize("protocols, node_opts, py_opts", PROTOCOL_CASES)
def test_python_mints_and_node_validates(
    capjs_dir: Path, protocols: list[str], node_opts: dict[str, Any], py_opts: dict[str, Any]
) -> None:
    cfg = CapConfig(secret=SECRET, protocols=tuple(protocols), **py_opts)
    resp = create_challenge(cfg)
    body = body_for(SECRET, resp)

    out = _node(capjs_dir, "validate.mjs", {"secret": SECRET, "body": body, "opts": {}})
    assert out["success"] is True, out


def test_node_rejects_a_wrong_python_solution(capjs_dir: Path) -> None:
    """Proves the Node check is real: a bad nonce from Python is refused by capjs-core."""
    cfg = CapConfig(secret=SECRET, protocols=("sha256-pow",), sha256_count=2, sha256_difficulty=1)
    resp = create_challenge(cfg)
    body = body_for(SECRET, resp)
    # A nonce whose sha256(salt + nonce) misses the target: capjs-core must refuse it.
    # (A string such as "not-a-number" is not a reliable choice: capjs-core accepts any string,
    # and it would pass the check about one time in sixteen.)
    payload = resp["challenges"][0]["payload"]
    nonce = 0
    while (
        hashlib.sha256((payload["salt"] + str(nonce)).encode())
        .hexdigest()
        .startswith(payload["target"])
    ):
        nonce += 1
    body["solutions"][0] = {"nonce": nonce}

    out = _node(capjs_dir, "validate.mjs", {"secret": SECRET, "body": body, "opts": {}})
    assert out["success"] is False
    assert out["reason"] == Reason.INVALID_SOLUTION.value
