"""capwx.contrib.fastapi.assets: serve the vendored widget files, after checking their hashes.

The files are served from the installed package (no copy). Before mounting, every file listed in
``VERSIONS.json`` is read and compared with its recorded sha256; a missing or altered file raises
``CapwxError`` and nothing is mounted.
"""

from __future__ import annotations

import hashlib
import json

from starlette.applications import Starlette
from starlette.staticfiles import StaticFiles

from capwx._assets_path import ASSETS_DIR
from capwx._types import as_json_dict
from capwx.errors import CapwxError

MANIFEST = "VERSIONS.json"


def check_assets() -> None:
    """Raise CapwxError unless every file in VERSIONS.json exists and matches its sha256."""
    manifest_path = ASSETS_DIR / MANIFEST
    try:
        manifest = as_json_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise CapwxError(f"cannot read the asset manifest {manifest_path}: {exc}") from exc
    files = as_json_dict(manifest.get("files")) if manifest is not None else None
    if files is None:
        raise CapwxError(f"the asset manifest {manifest_path} has no 'files' object")
    for name, meta in files.items():
        entry = as_json_dict(meta)
        expected = entry.get("sha256") if entry is not None else None
        if not isinstance(expected, str):
            raise CapwxError(f"the asset manifest has no sha256 for {name}")
        path = ASSETS_DIR / name
        if not path.is_file():
            raise CapwxError(f"vendored asset {name} is missing from {ASSETS_DIR}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise CapwxError(f"vendored asset {name} does not match {MANIFEST} (sha256 mismatch)")


def mount_assets(app: Starlette, path: str) -> None:
    """Hash-check the assets, then serve them under ``path`` (for example ``/cap-static``)."""
    check_assets()
    app.mount(path, StaticFiles(directory=ASSETS_DIR), name="capwx-assets")
