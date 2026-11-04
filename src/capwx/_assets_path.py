"""Location of the vendored browser assets. Pure pathlib, so any framework can import it."""

from pathlib import Path

ASSETS_DIR = Path(__file__).resolve().parent / "_assets"
