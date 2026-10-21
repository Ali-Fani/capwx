"""Check the built wheel and sdist contain everything a capwx release must ship.

Usage: ``python scripts/check_dist.py [dist_dir]`` (default ``dist``). Prints every problem and
exits non-zero when something is missing or a vendored file does not match its recorded hash.

Checked: the server hashwx.wasm with its LICENSE, COMMIT and SHA256; the browser assets, each
matched against ``VERSIONS.json``; the templates; the management command; ``py.typed``; and the
LICENSE / NOTICE files in the wheel's dist-info.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

STATIC = "capwx/contrib/django/static/capwx"
VENDOR = "capwx/_vendor/hashwx"

WHEEL_REQUIRED = (
    f"{VENDOR}/hashwx.wasm",
    f"{VENDOR}/LICENSE",
    f"{VENDOR}/COMMIT",
    f"{VENDOR}/SHA256",
    f"{STATIC}/hashwx.wasm",
    f"{STATIC}/cap.min.js",
    f"{STATIC}/cap_wasm_bg.wasm",
    f"{STATIC}/pako_inflate.min.js",
    f"{STATIC}/hashwx-LICENSE.txt",
    f"{STATIC}/VERSIONS.json",
    "capwx/contrib/django/templates/capwx/scripts.html",
    "capwx/contrib/django/templates/capwx/widget.html",
    "capwx/contrib/django/management/commands/capwx_check.py",
    "capwx/py.typed",
)
# Relative to the wheel's "<name>-<version>.dist-info/" directory.
WHEEL_LICENSE_FILES = (
    "licenses/LICENSE",
    "licenses/NOTICE",
    f"licenses/src/{VENDOR}/LICENSE",
)
# Relative to the sdist's "<name>-<version>/" directory.
SDIST_REQUIRED = (
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "CHANGELOG.md",
    "SECURITY.md",
    "UPSTREAM.md",
    f"src/{VENDOR}/hashwx.wasm",
    f"src/{VENDOR}/LICENSE",
    f"src/{VENDOR}/COMMIT",
    f"src/{VENDOR}/SHA256",
    f"src/{STATIC}/VERSIONS.json",
    f"src/{STATIC}/hashwx.wasm",
    "src/capwx/py.typed",
    "src/capwx/contrib/django/templates/capwx/widget.html",
    "src/capwx/contrib/django/management/commands/capwx_check.py",
    "scripts/vendor_assets.py",
    "tests/test_challenge.py",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_vendored(read: Callable[[str], bytes], label: str, src_prefix: str = "") -> list[str]:
    """The wasm must match its pinned SHA256 file, and each static file VERSIONS.json."""
    problems: list[str] = []
    pinned = read(f"{src_prefix}{VENDOR}/SHA256").decode("ascii").split()[0].lower()
    if _sha256(read(f"{src_prefix}{VENDOR}/hashwx.wasm")) != pinned:
        problems.append(f"{label}: vendored hashwx.wasm does not match its SHA256 file")
    versions = json.loads(read(f"{src_prefix}{STATIC}/VERSIONS.json"))
    for name, meta in versions["files"].items():
        if _sha256(read(f"{src_prefix}{STATIC}/{name}")) != meta["sha256"]:
            problems.append(f"{label}: static {name} does not match VERSIONS.json")
    return problems


def _verify_or_report(
    read: Callable[[str], bytes], label: str, present: set[str], src_prefix: str = ""
) -> list[str]:
    """Run the hash checks when the vendored files exist; otherwise say they cannot be checked."""
    needed = (f"{VENDOR}/SHA256", f"{VENDOR}/hashwx.wasm", f"{STATIC}/VERSIONS.json")
    if not all(f"{src_prefix}{rel}" in present for rel in needed):
        return [f"{label}: cannot verify vendored hashes (files missing)"]
    return _check_vendored(read, label, src_prefix)


def check_wheel(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        metadata = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
        if metadata is None:
            return [f"{path.name}: no .dist-info/METADATA"]
        dist_info = metadata.rsplit("/", 1)[0]
        problems = [f"{path.name}: missing {r}" for r in WHEEL_REQUIRED if r not in names]
        problems += [
            f"{path.name}: missing {dist_info}/{r}"
            for r in WHEEL_LICENSE_FILES
            if f"{dist_info}/{r}" not in names
        ]
        problems += _verify_or_report(lambda n: zf.read(n), path.name, names)
    return problems


def check_sdist(path: Path) -> list[str]:
    root = path.name.removesuffix(".tar.gz")
    with tarfile.open(path) as tf:
        files = {m.name: m for m in tf.getmembers() if m.isfile()}

        def read(rel: str) -> bytes:
            handle = tf.extractfile(files[f"{root}/{rel}"])
            if handle is None:
                raise OSError(f"{rel} is not a readable file in {path.name}")
            return handle.read()

        present = {name.removeprefix(f"{root}/") for name in files}
        problems = [f"{path.name}: missing {r}" for r in SDIST_REQUIRED if r not in present]
        problems += _verify_or_report(read, path.name, present, src_prefix="src/")
    return problems


def main(argv: list[str]) -> int:
    dist = Path(argv[1] if len(argv) > 1 else "dist")
    wheels = sorted(dist.glob("capwx-*.whl"))
    sdists = sorted(dist.glob("capwx-*.tar.gz"))
    problems: list[str] = []
    if len(wheels) != 1 or len(sdists) != 1:
        problems.append(
            f"expected one wheel and one sdist in {dist}, found {len(wheels)} and {len(sdists)}"
        )
    for wheel in wheels:
        problems += check_wheel(wheel)
    for sdist in sdists:
        problems += check_sdist(sdist)
    for problem in problems:
        print(f"FAIL: {problem}")
    if problems:
        return 1
    print(f"OK: {wheels[0].name} and {sdists[0].name} contain every required file")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
