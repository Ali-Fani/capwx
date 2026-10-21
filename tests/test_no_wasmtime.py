"""Behaviour on platforms without a wasmtime wheel (armv7, i686, ppc64le, s390x, ...).

wasmtime is not installed there, so ``pip install capwx`` succeeds and the package must still work
with ``("sha256-pow", "instrumentation")``. HashWX must fail with an actionable ``CapwxError``
instead of a raw ``ImportError``.

The subprocess tests block the import with a meta-path finder before capwx is imported, which is
what a missing wheel looks like to the interpreter. The in-process tests block it with
``sys.modules["wasmtime"] = None``. Neither needs wasmtime installed, so this file also runs in the
CI job that uninstalls it (see ``.github/workflows/ci.yml``).
"""

from __future__ import annotations

import copy
import hashlib
import platform
import subprocess
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from _solver import FORMAT_INFO, body_for
from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

import capwx
from capwx import CapConfig, CapwxError, MemoryStore, create_challenge, redeem
from capwx._crypto import encrypt_gcm, jwt_sign, random_hex
from capwx.protocols import hashwx, sha256_pow
from capwx.protocols.hashwx import missing_wasmtime_message

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
SECRET = "test-secret-0123456789abcdef"
NOW = 1_700_000_000_000
TTL_MS = 60_000
SHA_ONLY = ["sha256-pow", "instrumentation"]

# Runs before any capwx import in the child process. The finder raises ModuleNotFoundError for
# wasmtime, which is what the import system does when the wheel is absent.
BLOCK_WASMTIME = f"""
import importlib.abc, sys
sys.path.insert(0, {str(TESTS_DIR)!r})

class _NoWasmtime(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name == "wasmtime" or name.startswith("wasmtime."):
            raise ModuleNotFoundError("No module named 'wasmtime' (blocked by test)", name="wasmtime")
        return None

sys.meta_path.insert(0, _NoWasmtime())
try:
    import wasmtime  # noqa: F401
except ImportError:
    pass
else:
    raise SystemExit("the block did not work")
"""


def _run(code: str) -> str:
    done = subprocess.run(
        [sys.executable, "-c", BLOCK_WASMTIME + code],
        capture_output=True,
        text=True,
        check=True,
        timeout=180,
    )
    return done.stdout.strip()


# --------------------------------------------------------------------------- subprocess


def test_import_capwx_succeeds_and_reports_hashwx_unavailable() -> None:
    out = _run("import capwx\nprint(capwx.hashwx_available())\n")
    assert out == "False"


def test_sha256_and_instrumentation_round_trip_without_wasmtime() -> None:
    out = _run(
        """
from _solver import body_for
from capwx import CapConfig, MemoryStore, create_challenge, redeem
cfg = CapConfig(secret='test-secret-0123456789abcdef', protocols=('sha256-pow', 'instrumentation'),
                sha256_difficulty=1, sha256_count=2)
resp = create_challenge(cfg)
assert {c['protocol'] for c in resp['challenges']} == {'sha256-pow', 'instrumentation'}
store = MemoryStore()
result = redeem(cfg, body_for(cfg.secret, resp), nonce_store=store, token_store=store)
print(result.success, result.reason)
"""
    )
    assert out == "True None"


def test_hashwx_mint_fails_with_the_actionable_error_in_a_fresh_process() -> None:
    out = _run(
        """
from capwx import CapConfig, CapwxError, create_challenge
try:
    create_challenge(CapConfig(secret='test-secret-0123456789abcdef'))  # default: hashwx
except CapwxError as exc:
    print(type(exc).__name__, str(exc))
else:
    print('no error')
"""
    )
    assert out.startswith("CapwxError HashWX needs the `wasmtime` package")
    assert "sha256-pow" in out


# --------------------------------------------------------------------------- in-process


@pytest.fixture
def no_wasmtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """``import wasmtime`` raises ImportError for the rest of the test."""
    monkeypatch.setitem(sys.modules, "wasmtime", None)


def _cfg(protocols: tuple[str, ...] = ("hashwx", "instrumentation")) -> CapConfig:
    return CapConfig(secret=SECRET, protocols=protocols, hashwx_difficulty=20)


def test_hashwx_available_is_false_without_wasmtime(no_wasmtime: None) -> None:
    assert capwx.hashwx_available() is False
    assert hashwx.hashwx_available() is False


def test_hashwx_available_is_true_with_wasmtime() -> None:
    pytest.importorskip("wasmtime")
    assert capwx.hashwx_available() is True


def test_missing_wasmtime_message_names_the_platform_and_the_fix() -> None:
    text = missing_wasmtime_message()
    assert "no wheel for this platform/arch" in text
    assert platform.machine() in text
    assert "protocols=('sha256-pow','instrumentation')" in text
    assert "install wasmtime manually" in text


def test_missing_wasmtime_message_keeps_the_import_failure_as_context() -> None:
    assert "(import failed: boom)" in missing_wasmtime_message(ImportError("boom"))


def test_hashwx_mint_raises_capwx_error(no_wasmtime: None) -> None:
    with pytest.raises(CapwxError, match="HashWX needs the `wasmtime` package"):
        hashwx.mint(_cfg())


def test_create_challenge_with_default_protocols_raises_capwx_error(no_wasmtime: None) -> None:
    with pytest.raises(CapwxError, match="sha256-pow"):
        create_challenge(CapConfig(secret=SECRET))


def test_sha256_pow_still_mints_and_verifies_without_wasmtime(no_wasmtime: None) -> None:
    cfg = _cfg(SHA_ONLY)
    resp = create_challenge(cfg, now_ms=NOW)
    store = MemoryStore()
    result = redeem(
        cfg,
        body_for(SECRET, resp),
        nonce_store=store,
        token_store=store,
        now_ms=NOW,
    )
    assert result.success is True


def test_hashwx_verify_raises_instead_of_returning_false(no_wasmtime: None) -> None:
    expected = {"protocol": "hashwx", "c": "00" * 32, "d": 1, "n": 1}
    with pytest.raises(CapwxError, match="HashWX needs the"):
        hashwx.verify(expected, {"nonce": 0})


def test_hashwx_verify_raises_even_for_malformed_input(no_wasmtime: None) -> None:
    # The wasmtime check runs before input parsing, so garbage cannot hide the misconfiguration.
    with pytest.raises(CapwxError):
        hashwx.verify("garbage", None)


def test_sha256_verify_is_unaffected_by_missing_wasmtime(no_wasmtime: None) -> None:
    salt = "salt"
    nonce = next(n for n in range(10_000) if _sha(salt, n).startswith("0"))
    expected = {"protocol": "sha256-pow", "salt": salt, "target": "0"}
    assert sha256_pow.verify(expected, {"nonce": nonce}) is True


def test_hashwx_token_minted_elsewhere_surfaces_as_capwx_error(no_wasmtime: None) -> None:
    """A token signed with the shared secret carrying a hashwx entry: a config error, not a 'no'."""
    entries = [{"protocol": "hashwx", "c": "00" * 32, "d": 1, "n": 1}]
    token = jwt_sign(
        {
            "f": 2,
            "n": random_hex(16),
            "exp": NOW + TTL_MS,
            "iat": NOW,
            "ev": encrypt_gcm({"expected": entries}, SECRET, FORMAT_INFO),
        },
        SECRET,
    )
    body = {"token": token, "solutions": [{"nonce": 0}]}
    with pytest.raises(CapwxError, match="HashWX needs the"):
        redeem(_cfg(), body, now_ms=NOW)


def _sha(salt: str, nonce: int) -> str:
    return hashlib.sha256((salt + str(nonce)).encode()).hexdigest()


# --------------------------------------------------------------------------- django


def _settings_with(protocols: list[str]) -> dict[str, Any]:
    cfg = copy.deepcopy(settings.CAPWX)
    cfg["PROTOCOLS"] = protocols
    return cfg


def test_django_ready_starts_a_sha256_only_app_without_wasmtime(no_wasmtime: None) -> None:
    with override_settings(CAPWX=_settings_with(SHA_ONLY)):
        apps.get_app_config("capwx").ready()  # must not raise


def test_django_ready_refuses_a_hashwx_site_without_wasmtime(no_wasmtime: None) -> None:
    with (
        override_settings(CAPWX=_settings_with(["hashwx", "instrumentation"])),
        pytest.raises(ImproperlyConfigured, match="no wheel for this platform/arch") as info,
    ):
        apps.get_app_config("capwx").ready()
    assert "Sites using hashwx:" in str(info.value)
    assert "default" in str(info.value)


def test_capwx_check_skips_hashwx_when_no_site_uses_it(no_wasmtime: None) -> None:
    out, err = StringIO(), StringIO()
    with override_settings(CAPWX=_settings_with(SHA_ONLY)):
        call_command("capwx_check", stdout=out, stderr=err)
    text = out.getvalue()
    assert "[skip] hashwx" in text
    assert "capwx_check: OK" in text
    assert "FAIL" not in text
    assert err.getvalue() == ""


def test_capwx_check_fails_when_a_site_uses_hashwx_without_wasmtime(no_wasmtime: None) -> None:
    err = StringIO()
    with (
        override_settings(CAPWX=_settings_with(["hashwx", "instrumentation"])),
        pytest.raises(CommandError, match="capwx_check failed"),
    ):
        call_command("capwx_check", stdout=StringIO(), stderr=err)
    assert "no wheel for this platform/arch" in err.getvalue()


# --------------------------------------------------------------------------- packaging


def test_pyproject_gates_wasmtime_on_the_platform_machine() -> None:
    """The requirement must be skipped on CPUs without a wheel, not made unconditional."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.lstrip().startswith('"wasmtime')]
    assert len(lines) == 1, lines
    line = lines[0]
    assert "wasmtime>=49,<50" in line
    assert "platform_machine in 'x86_64 AMD64 arm64 ARM64 aarch64'" in line
