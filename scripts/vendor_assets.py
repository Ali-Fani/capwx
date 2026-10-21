"""Download, verify and vendor the pinned upstream browser assets for capwx.

Pins (see UPSTREAM.md and capwx.plan.md 11.4):

* cap-widget@0.1.58      -> package/cap.min.js                  -> cap.min.js
* @cap.js/wasm@0.0.8      -> package/browser/hashwx.wasm         -> hashwx.wasm (LGPL-3.0)
* @cap.js/wasm@0.0.8      -> package/browser/cap_wasm_bg.wasm    -> cap_wasm_bg.wasm
* pako@2.1.0             -> package/dist/pako_inflate.min.js    -> pako_inflate.min.js

Each tarball is downloaded into a fresh temporary directory and its sha512 is
checked against the registry's ``dist.integrity``. Only the wanted members are
extracted, after every member name has been validated (no absolute paths, no
``..`` components, no links). The results are copied into
``src/capwx/contrib/django/static/capwx/`` together with ``VERSIONS.json``
(sha256 of every file) and the LGPL licence for ``hashwx.wasm``.

Stdlib only. Run from the repository root:

    uv run python scripts/vendor_assets.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

REGISTRY = "https://registry.npmjs.org"
USER_AGENT = "capwx-vendor-assets/0.1 (+https://github.com/tiagozip/cap)"
TIMEOUT_S = 120

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "src" / "capwx" / "contrib" / "django" / "static" / "capwx"
HASHWX_VENDOR_DIR = ROOT / "src" / "capwx" / "_vendor" / "hashwx"
HASHWX_LICENSE_NAME = "hashwx-LICENSE.txt"

# npm name -> pinned version, and {tarball member: destination file name}.
PACKAGES: dict[str, dict[str, Any]] = {
    "cap-widget": {
        "version": "0.1.58",
        "files": {"package/cap.min.js": "cap.min.js"},
    },
    "@cap.js/wasm": {
        "version": "0.0.8",
        "files": {
            "package/browser/hashwx.wasm": "hashwx.wasm",
            "package/browser/cap_wasm_bg.wasm": "cap_wasm_bg.wasm",
        },
    },
    "pako": {
        "version": "2.1.0",
        "files": {"package/dist/pako_inflate.min.js": "pako_inflate.min.js"},
    },
}


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        return resp.read()


def _fetch_dist_metadata(name: str, version: str) -> dict[str, Any]:
    url = f"{REGISTRY}/{urllib.parse.quote(name, safe='')}/{version}"
    meta = json.loads(_http_get(url).decode("utf-8"))
    if meta.get("version") != version:
        raise RuntimeError(
            f"registry returned version {meta.get('version')!r} for {name}@{version}"
        )
    return meta


def _verify_integrity(data: bytes, integrity: str, label: str) -> None:
    algo, _, expected_b64 = integrity.partition("-")
    if algo != "sha512" or not expected_b64:
        raise RuntimeError(f"{label}: unsupported integrity string {integrity!r}")
    actual_b64 = base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    if actual_b64 != expected_b64:
        raise RuntimeError(f"{label}: sha512 mismatch (registry {expected_b64}, got {actual_b64})")


def _validate_member_name(name: str) -> PurePosixPath:
    if not name or "\\" in name or name.startswith("/"):
        raise RuntimeError(f"unsafe tar member name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", "..") for part in path.parts):
        raise RuntimeError(f"unsafe tar member name: {name!r}")
    if ":" in path.parts[0]:
        raise RuntimeError(f"unsafe tar member name: {name!r}")
    return path


def _extract_wanted(tgz: Path, wanted: list[str], out_dir: Path) -> dict[str, Path]:
    """Validate every member, then extract only the wanted regular files into out_dir."""
    found: dict[str, Path] = {}
    with tarfile.open(tgz, mode="r:gz") as tf:
        for member in tf.getmembers():
            _validate_member_name(member.name)
            if member.issym() or member.islnk():
                raise RuntimeError(f"tarball contains a link member, refusing: {member.name!r}")
        for member in tf.getmembers():
            if member.name not in wanted:
                continue
            if not member.isfile():
                raise RuntimeError(f"wanted member is not a regular file: {member.name!r}")
            src = tf.extractfile(member)
            if src is None:
                raise RuntimeError(f"cannot read member {member.name!r}")
            target = out_dir / _validate_member_name(member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with src, open(target, "wb") as fh:
                shutil.copyfileobj(src, fh)
            found[member.name] = target
    missing = [w for w in wanted if w not in found]
    if missing:
        raise RuntimeError(f"members not found in tarball: {missing}")
    return found


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    tmp_root = Path(tempfile.mkdtemp(prefix="capwx-vendor-"))
    print(f"scratch dir: {tmp_root}")
    versions: dict[str, Any] = {
        "generated_by": "scripts/vendor_assets.py",
        "packages": {},
        "files": {},
        "licenses": {},
    }
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

    for name, spec in PACKAGES.items():
        version = spec["version"]
        label = f"{name}@{version}"
        meta = _fetch_dist_metadata(name, version)
        dist = meta["dist"]
        pkg_dir = tmp_root / name.replace("/", "__").replace("@", "")
        pkg_dir.mkdir(parents=True)
        tgz = pkg_dir / "package.tgz"
        tgz.write_bytes(_http_get(dist["tarball"]))
        _verify_integrity(tgz.read_bytes(), dist["integrity"], label)
        print(f"{label}: tarball sha512 verified ({tgz.stat().st_size} bytes)")

        extract_dir = pkg_dir / "extracted"
        extract_dir.mkdir()
        found = _extract_wanted(tgz, list(spec["files"]), extract_dir)

        versions["packages"][label] = {
            "tarball": dist["tarball"],
            "integrity": dist["integrity"],
            "license": meta.get("license"),
        }
        for member, dest_name in spec["files"].items():
            dest = STATIC_DIR / dest_name
            shutil.copyfile(found[member], dest)
            versions["files"][dest_name] = {
                "source": f"{label}:{member}",
                "sha256": _sha256(dest),
                "bytes": dest.stat().st_size,
            }
            print(f"  {member} -> {dest.relative_to(ROOT)} ({dest.stat().st_size} bytes)")

    wasm_path = STATIC_DIR / "hashwx.wasm"
    if wasm_path.read_bytes()[:4] != b"\0asm":
        raise RuntimeError("static hashwx.wasm is not a WebAssembly module")

    # The browser copy and the server copy are separate artifacts; report whether they match.
    server_wasm = HASHWX_VENDOR_DIR / "hashwx.wasm"
    same = _sha256(server_wasm) == _sha256(wasm_path) if server_wasm.exists() else None
    print(f"hashwx.wasm: browser copy identical to server copy in _vendor: {same}")

    licence_src = HASHWX_VENDOR_DIR / "LICENSE"
    licence_dst = STATIC_DIR / HASHWX_LICENSE_NAME
    shutil.copyfile(licence_src, licence_dst)
    versions["licenses"][HASHWX_LICENSE_NAME] = {
        "source": "src/capwx/_vendor/hashwx/LICENSE",
        "sha256": _sha256(licence_dst),
        "applies_to": ["hashwx.wasm"],
    }

    (STATIC_DIR / "VERSIONS.json").write_text(
        json.dumps(versions, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {(STATIC_DIR / 'VERSIONS.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
