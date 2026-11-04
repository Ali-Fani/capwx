"""Profile mint and redeem, and break the instrumentation pipeline into stages.

Run with ``uv run python benchmarks/profile_mint.py``. Prints, for each target:

- a stage breakdown (client script, obfuscation, deflate);
- the ``cProfile`` top functions by own time and by cumulative time.

Use it to decide whether a hotspot is worth optimising in pure Python before considering native
code. No tokens, nonces or probe data are printed: only function names and durations.
"""

from __future__ import annotations

import argparse
import cProfile
import io
import pstats
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

# ``tests/_solver.py`` is the reference client stand-in; the repo root must be importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capwx.challenge import create_challenge, redeem
from capwx.config import CapConfig, InstrumentationOptions
from capwx.protocols.hashwx import hashwx_ready
from capwx.protocols.instrumentation.generator import (
    build_client_script,
    generate_instrumentation,
)
from capwx.protocols.instrumentation.obfuscate import apply_obfuscation, build_blob
from tests._solver import body_for

SECRET = "capwx-profile-secret-0123456789"
VARS = ["abcdefghijkl", "mnopqrstuvwx", "yzabcdefghij", "klmnopqrstuv"]
INITS = [12, 34, 56, 78]
EQS = "".join(f"{VARS[i % 4]} = {VARS[(i + 1) % 4]} ^ {i};" for i in range(20))


def _median_ms(fn: Callable[[], Any], repeat: int) -> float:
    times = []
    for _ in range(repeat):
        started = time.perf_counter()
        fn()
        times.append((time.perf_counter() - started) * 1000)
    return statistics.median(times)


def stage_breakdown(repeat: int) -> None:
    """Time each stage of the instrumentation pipeline on its own, in milliseconds."""
    print("\n## Instrumentation pipeline, median per call (ms)\n")
    print("| Stage | level 3 | level 7 |")
    print("|---|---|---|")

    def script_for_level(level: int) -> str:
        return build_client_script(
            id_="0" * 32,
            vars_=VARS,
            init_vals=INITS,
            client_eqs=EQS,
            block_automated_browsers=True,
        )

    def times(level: int) -> dict[str, float]:
        script = script_for_level(level)
        final = apply_obfuscation(script, level)  # what the pipeline actually deflates
        return {
            "generate_instrumentation": _median_ms(
                lambda: generate_instrumentation({"obfuscation_level": level}), repeat
            ),
            "build_client_script": _median_ms(lambda: script_for_level(level), repeat),
            "apply_obfuscation": _median_ms(lambda: apply_obfuscation(script, level), repeat),
            "build_blob": _median_ms(lambda: build_blob(final), repeat),
        }

    level3, level7 = times(3), times(7)
    for stage in (
        "generate_instrumentation",
        "build_client_script",
        "apply_obfuscation",
        "build_blob",
    ):
        print(f"| `{stage}` | {level3[stage]:.2f} | {level7[stage]:.2f} |")
    print("\n`build_client_script` does not depend on the obfuscation level.")


def profile(label: str, fn: Callable[[], Any], repeat: int) -> None:
    """Run ``fn`` under cProfile and print the top functions by own and cumulative time."""
    for _ in range(3):  # warm caches, imports and the wasm instance
        fn()
    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(repeat):
        fn()
    profiler.disable()
    for key, heading in (("tottime", "by own time"), ("cumtime", "by cumulative time")):
        stream = io.StringIO()
        pstats.Stats(profiler, stream=stream).sort_stats(key).print_stats(12)
        print(f"\n## cProfile: {label} {heading} ({repeat} calls)\n")
        print("\n".join(stream.getvalue().splitlines()[4:]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=50)
    args = parser.parse_args()
    repeat = args.repeat

    hashwx_ready()
    cfg = CapConfig(
        secret=SECRET,
        hashwx_difficulty=400,
        instrumentation=InstrumentationOptions(obfuscation_level=3),
    )
    body = body_for(SECRET, create_challenge(cfg))

    stage_breakdown(repeat)
    profile("create_challenge (hashwx + instrumentation)", lambda: create_challenge(cfg), repeat)
    profile("redeem (hashwx + instrumentation)", lambda: redeem(cfg, body), repeat)
    profile(
        "generate_instrumentation (level 3)",
        lambda: generate_instrumentation({"obfuscation_level": 3}),
        repeat,
    )
    profile(
        "generate_instrumentation (level 7)",
        lambda: generate_instrumentation({"obfuscation_level": 7}),
        repeat,
    )


if __name__ == "__main__":
    main()
