"""Cold-start measurements for capwx, in fresh subprocesses.

Run with ``uv run python benchmarks/cold_start.py``. The numbers answer two questions the
pytest benchmarks cannot: what an import costs when nothing is warm, and what wasmtime engine
construction plus module compilation costs at ``AppConfig.ready()``.

Durations are wall-clock medians of ``--repeat`` runs (default 7); the subprocess runs discard
their output, so no pipes are involved.
"""

from __future__ import annotations

import argparse
import statistics
import subprocess
import sys
import time
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"


def _time_subprocess(code: str, repeat: int) -> float:
    """Median wall-clock milliseconds of ``python -c code`` in a fresh interpreter."""
    times: list[float] = []
    for _ in range(repeat):
        started = time.perf_counter()
        subprocess.run(
            [sys.executable, "-c", code],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        times.append((time.perf_counter() - started) * 1000)
    return statistics.median(times)


def _import_cost(module: str, repeat: int) -> tuple[float, float]:
    """(total ms, ms above bare interpreter startup) for importing ``module``."""
    baseline = _time_subprocess("pass", repeat)
    total = _time_subprocess(f"import {module}", repeat)
    return total, total - baseline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()
    repeat = args.repeat

    # In-process timings for the engine lifecycle, in this (otherwise cold) interpreter.
    sys.path.insert(0, str(SRC))
    started = time.perf_counter()
    import wasmtime  # noqa: F401 - imported only to time it

    wasmtime_import_ms = (time.perf_counter() - started) * 1000

    from capwx.protocols import hashwx as hw

    started = time.perf_counter()
    engine = hw.HashwxEngine()
    engine_build_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    engine.thread_instance()
    instance_ms = (time.perf_counter() - started) * 1000

    seed = b"\x00" * 32
    started = time.perf_counter()
    engine.hash(seed, 1)
    first_hash_ms = (time.perf_counter() - started) * 1000

    calls = 200
    started = time.perf_counter()
    for nonce in range(1, calls + 1):
        engine.hash(seed, nonce)
    per_hash_us = (time.perf_counter() - started) / calls * 1e6
    engine.release()

    capwx_total, capwx_net = _import_cost("capwx", repeat)
    hashwx_total, hashwx_net = _import_cost("capwx.protocols.hashwx", repeat)
    wasmtime_total, wasmtime_net = _import_cost("wasmtime", repeat)

    def row(name: str, value: float) -> str:
        return f"| {name} | {value:.2f} |"

    print()
    print(f"Python {sys.version.split()[0]} on {sys.platform}, median of {repeat} runs")
    print()
    print("| Measurement | ms |")
    print("|---|---|")
    print(row("`import capwx` (net of interpreter startup)", capwx_net))
    print(row("`import capwx.protocols.hashwx` (net)", hashwx_net))
    print(row("`import wasmtime` (net)", wasmtime_net))
    print(row("`import wasmtime` (this process)", wasmtime_import_ms))
    print(row("`HashwxEngine()` (module compile)", engine_build_ms))
    print(row("first `thread_instance()` (instantiate + alloc)", instance_ms))
    print(row("first `hash()` after that", first_hash_ms))
    print()
    print(f"| Warm `HashwxEngine.hash()` per call | {per_hash_us:.1f} us |")
    print()
    print(
        f"`import capwx` total: {capwx_total:.1f} ms; "
        f"`import capwx.protocols.hashwx` total: {hashwx_total:.1f} ms; "
        f"`import wasmtime` total: {wasmtime_total:.1f} ms"
    )


if __name__ == "__main__":
    main()
