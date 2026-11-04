"""Benchmarks for the internal hot paths the challenge lifecycle is built from.

These are the numbers the native-code decision rests on: instrumentation generation and
obfuscation, the JS-semantics helpers, and the HashWX wasm call itself.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from capwx.protocols import hashwx
from capwx.protocols.instrumentation import obfuscate
from capwx.protocols.instrumentation.generator import (
    PROBE_FONT_STACKS,
    build_client_script,
    dom_sum_mock,
    generate_instrumentation,
    hash_with,
)
from capwx.protocols.instrumentation.obfuscate import (
    apply_obfuscation,
    build_blob,
    custom_obfuscate_strings,
)

_CLIENT_VARS = ["abcdefghijkl", "mnopqrstuvwx", "yzabcdefghij", "klmnopqrstuv"]
_INIT_VALS = [12, 34, 56, 78]
_CLIENT_EQS = "".join(
    f"{_CLIENT_VARS[i % 4]} = {_CLIENT_VARS[(i + 1) % 4]} ^ {i};" for i in range(20)
)


def test_generate_instrumentation_level3(benchmark: Any) -> None:
    """The whole generator pipeline: value pipeline, client script, whitespace stripping, deflate."""
    benchmark(generate_instrumentation, {"obfuscation_level": 3})


def test_generate_instrumentation_level7(benchmark: Any) -> None:
    """The whole generator pipeline with the string-table obfuscation pass."""
    benchmark(generate_instrumentation, {"obfuscation_level": 7})


def test_build_client_script(benchmark: Any) -> None:
    """Script assembly only: template substitution, probe, environment checks, block checks."""
    benchmark(
        build_client_script,
        id_="0" * 32,
        vars_=_CLIENT_VARS,
        init_vals=_INIT_VALS,
        client_eqs=_CLIENT_EQS,
        block_automated_browsers=True,
    )


def test_build_client_script_without_block_checks(benchmark: Any) -> None:
    """The same with ``block_automated_browsers=False``, the default: no block-check assembly."""
    benchmark(
        build_client_script,
        id_="0" * 32,
        vars_=_CLIENT_VARS,
        init_vals=_INIT_VALS,
        client_eqs=_CLIENT_EQS,
        block_automated_browsers=False,
    )


@pytest.fixture(scope="module")
def client_script() -> str:
    return build_client_script(
        id_="0" * 32,
        vars_=_CLIENT_VARS,
        init_vals=_INIT_VALS,
        client_eqs=_CLIENT_EQS,
        block_automated_browsers=True,
    )


def test_apply_obfuscation_level3(benchmark: Any, client_script: str) -> None:
    benchmark(apply_obfuscation, client_script, 3)


def test_apply_obfuscation_level7(benchmark: Any, client_script: str) -> None:
    benchmark(apply_obfuscation, client_script, 7)


def test_custom_obfuscate_strings(benchmark: Any, client_script: str) -> None:
    """The string-table pass on its own: regex scan, JS string decoding, table rewrite."""
    benchmark(custom_obfuscate_strings, client_script)


def test_strip_whitespace(benchmark: Any, client_script: str) -> None:
    benchmark(obfuscate.strip_whitespace, client_script)


def test_build_blob(benchmark: Any, client_script: str) -> None:
    """Raw deflate level 1 + base64 of the final script."""
    benchmark(build_blob, client_script)


def test_hash_with_long_input(benchmark: Any) -> None:
    h = hash_with(1_234_567)
    benchmark(h, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0")


def test_hash_with_all_markers(benchmark: Any) -> None:
    """Hash every block-check marker the way ``build_block_checks`` does."""
    h = hash_with(1_234_567)
    markers = [
        "webdriver",
        "userAgent",
        "exposeBindingHandle",
        "renderer",
        "[native code]",
        "Sequentum",
        "chrome",
        "safari",
        "opera",
        "Array",
        "Promise",
        "Symbol",
        *PROBE_FONT_STACKS,
    ]
    benchmark(lambda: [h(m) for m in markers])


def test_dom_sum_mock(benchmark: Any) -> None:
    benchmark(dom_sum_mock, 123_456, 654_321, 987_654)


@pytest.fixture(scope="module")
def wasm_seed() -> bytes:
    return hashlib.sha256(b"benchmark seed").digest()


def test_hashwx_hash_call(benchmark: Any, wasm_seed: bytes) -> None:
    """One HashWX evaluation through wasmtime, warm engine, warm thread instance."""
    engine = hashwx.get_engine()
    benchmark(engine.hash, wasm_seed, 123_456)


def test_hashwx_verify(benchmark: Any) -> None:
    """One full hashwx ``verify``: input validation, seed hashing, one wasm call."""
    challenge = "ab" * 32
    expected = {"protocol": "hashwx", "c": challenge, "d": 100, "n": 65_536}
    solution = {"nonce": 42}
    benchmark(hashwx.verify, expected, solution)


def test_hashwx_engine_cold(benchmark: Any) -> None:
    """Engine construction and wasm module compilation, then a first instance and hash."""
    seed = hashlib.sha256(b"cold").digest()

    def build_and_hash() -> int:
        engine = hashwx.HashwxEngine()
        return engine.hash(seed, 7)

    benchmark.pedantic(build_and_hash, rounds=5, iterations=1)
