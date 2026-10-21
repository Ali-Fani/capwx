"""A process that uses HashWX must exit with empty stderr.

Before the exit hook in ``capwx.protocols.hashwx``, wasmtime's ``Managed.__del__`` finalizers ran
during interpreter teardown and printed ``'NoneType' object is not callable``. The script below
covers the cases that used to leak: a cached engine, a worker thread that verifies, a daemon thread
still holding an instance at exit, a custom wasm path, a directly built engine, and an engine in a
reference cycle that only the garbage collector would free.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT = textwrap.dedent(
    """
    import gc
    import shutil
    import sys
    import threading
    from importlib import resources
    from pathlib import Path

    from capwx.protocols.hashwx import HashwxEngine, get_engine, verify

    custom = Path(sys.argv[1]) / "hashwx-copy.wasm"
    shutil.copyfile(str(resources.files("capwx._vendor.hashwx").joinpath("hashwx.wasm")), custom)

    expected = {"c": "ab" * 32, "d": 1, "n": 1}
    get_engine().hash(b"x" * 32, 0)
    get_engine(str(custom)).hash(b"x" * 32, 0)

    results: list[bool] = []

    def worker() -> None:
        results.append(verify(expected, {"nonce": 0}))
        results.append(verify(expected, {"nonce": "not-a-nonce"}) is False)

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    ready = threading.Event()

    def daemon() -> None:
        get_engine().hash(b"d" * 32, 5)
        ready.set()
        threading.Event().wait()  # still alive when the interpreter exits

    threading.Thread(target=daemon, daemon=True).start()
    ready.wait()

    direct = HashwxEngine()
    direct.hash(b"y" * 32, 1)

    class Holder:
        pass

    cycle = Holder()
    cycle.me = cycle  # type: ignore[attr-defined]
    cycle.engine = HashwxEngine()  # type: ignore[attr-defined]
    del cycle
    gc.collect(0)

    assert results == [True, True], results
    print("OK")
    """
)


ROOT = Path(__file__).resolve().parent.parent


def test_hashwx_process_exits_with_empty_stderr(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert proc.stdout.strip() == "OK"


def test_pytest_run_that_uses_hashwx_exits_with_empty_stderr() -> None:
    # Running pytest over a file that loads HashWX through the Django setup used to print
    # "Exception ignored ... NoneType object is not callable" at exit. The nested run is the
    # reproducer: it shows the real symptom, which a plain script does not.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/test_challenge.py",
            "-k",
            "package_exports or wrong_nonce_is_invalid",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Exception ignored" not in proc.stderr
    assert proc.stderr == ""
