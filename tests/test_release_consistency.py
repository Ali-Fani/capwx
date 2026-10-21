"""Guards against shipping a release whose docs or version numbers disagree.

PyPI renders the README from the tagged commit and a published version can never be edited, so these
checks run in every CI build, not only at release time. See the release checklist in CLAUDE.md.
"""

from __future__ import annotations

import re
from pathlib import Path

import capwx

ROOT = Path(__file__).resolve().parent.parent


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _pyproject_version() -> str:
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', _read("pyproject.toml"))
    assert match, "no version in pyproject.toml"
    return match.group(1)


def test_package_version_matches_pyproject() -> None:
    assert capwx.__version__ == _pyproject_version()


def test_changelog_has_a_dated_entry_for_this_version() -> None:
    version = re.escape(_pyproject_version())
    assert re.search(rf"(?m)^## \[{version}\] - \d{{4}}-\d{{2}}-\d{{2}}\s*$", _read("CHANGELOG.md"))


def test_readme_status_names_the_current_version() -> None:
    match = re.search(r"(?m)^\*\*Status: (\d+\.\d+\.\d+)", _read("README.md"))
    assert match, "README.md needs a '**Status: X.Y.Z, ...**' line"
    assert match.group(1) == _pyproject_version()


def test_docs_do_not_claim_pre_release_or_not_on_pypi() -> None:
    for name in ("README.md", "SECURITY.md"):
        text = _read(name).lower()
        assert "pre-release" not in text, f"{name} still says pre-release"
        assert "not on pypi" not in text, f"{name} still says it is not on PyPI"
        assert "unreleased" not in text, f"{name} still says unreleased"


def test_security_policy_lists_the_current_minor_series() -> None:
    major, minor, _ = _pyproject_version().split(".")
    assert f"| {major}.{minor}.x |" in _read("SECURITY.md")
