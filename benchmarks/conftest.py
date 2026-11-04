"""Fixtures shared by the benchmark suite.

The benchmark configs use a much lower proof-of-work difficulty than production. Solving is the
browser's job; the server-side cost of verifying one solution does not depend on ``d`` or on
``sha256_difficulty``, so solving in Python at the default difficulty would only make the suite
slow without changing what is measured.
"""

from __future__ import annotations

import pytest

from capwx import MemoryStore
from capwx.challenge import create_challenge
from capwx.config import CapConfig, InstrumentationOptions
from capwx.protocols.hashwx import hashwx_ready
from tests._solver import body_for

SECRET = "capwx-benchmarks-0123456789"  # >= 16 bytes
BENCH_HASHWX_DIFFICULTY = 400  # production default is 1_000_000
BENCH_SHA256_COUNT = 4  # production default is 50
BENCH_SHA256_DIFFICULTY = 1  # production default is 4


@pytest.fixture(scope="session", autouse=True)
def _wasmtime_warm() -> None:
    """Compile the module and initialise this thread's instance once, before any benchmark.

    Cold costs (import, module compile, first hash) are measured separately in ``cold_start.py``:
    in-process warm-up would otherwise hide them inside whichever benchmark happened to run first.
    """
    hashwx_ready()


@pytest.fixture(scope="session")
def cfg_default() -> CapConfig:
    """The production default protocol set: hashwx + instrumentation."""
    return CapConfig(secret=SECRET, hashwx_difficulty=BENCH_HASHWX_DIFFICULTY)


@pytest.fixture(scope="session")
def cfg_hashwx() -> CapConfig:
    return CapConfig(
        secret=SECRET, protocols=("hashwx",), hashwx_difficulty=BENCH_HASHWX_DIFFICULTY
    )


@pytest.fixture(scope="session")
def cfg_instrumentation() -> CapConfig:
    return CapConfig(secret=SECRET, protocols=("instrumentation",))


@pytest.fixture(scope="session")
def cfg_instrumentation_level7() -> CapConfig:
    """Level 7 is the heaviest level capwx can produce (8-10 are clamped to 7)."""
    return CapConfig(
        secret=SECRET,
        protocols=("instrumentation",),
        instrumentation=InstrumentationOptions(obfuscation_level=7),
    )


@pytest.fixture(scope="session")
def cfg_sha256() -> CapConfig:
    return CapConfig(
        secret=SECRET,
        protocols=("sha256-pow",),
        sha256_count=BENCH_SHA256_COUNT,
        sha256_difficulty=BENCH_SHA256_DIFFICULTY,
    )


def _solved_body(cfg: CapConfig) -> dict[str, object]:
    return body_for(cfg.secret, create_challenge(cfg))


@pytest.fixture(scope="session")
def default_body(cfg_default: CapConfig) -> dict[str, object]:
    """One solved body, reused: without a nonce store the same solution verifies every time."""
    return _solved_body(cfg_default)


@pytest.fixture(scope="session")
def hashwx_body(cfg_hashwx: CapConfig) -> dict[str, object]:
    return _solved_body(cfg_hashwx)


@pytest.fixture(scope="session")
def instrumentation_body(cfg_instrumentation: CapConfig) -> dict[str, object]:
    return _solved_body(cfg_instrumentation)


@pytest.fixture(scope="session")
def sha256_body(cfg_sha256: CapConfig) -> dict[str, object]:
    return _solved_body(cfg_sha256)


@pytest.fixture(scope="session")
def store_bodies(cfg_default: CapConfig) -> list[dict[str, object]]:
    """A pool of solved bodies: a nonce store makes every solution single-use."""
    return [_solved_body(cfg_default) for _ in range(30)]


@pytest.fixture
def memory_store() -> MemoryStore:
    return MemoryStore()
