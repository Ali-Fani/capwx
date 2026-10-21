"""Settings-validation and capwx_check failure paths (M13 coverage pass).

``settings.CAPWX`` errors must surface as ``ImproperlyConfigured`` at first use, naming the bad key,
and ``capwx_check`` must report a failing check instead of crashing. The happy paths are covered by
test_django.py.
"""

from __future__ import annotations

import copy
import re
from io import StringIO
from typing import Any

import pytest
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from capwx.contrib.django import conf
from capwx.contrib.django.management.commands import capwx_check

BASE: dict[str, Any] = copy.deepcopy(settings.CAPWX)


def _capwx(sites: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    cfg = copy.deepcopy(BASE)
    for name, change in (sites or {}).items():
        if change is None:
            cfg["SITES"][name] = None
        else:
            cfg["SITES"].setdefault(name, {}).update(change)
    cfg.update(changes)
    return cfg


class _AsyncStore:
    """A store with async methods: the Django views need a synchronous one."""

    async def claim(self, key: str, ttl_seconds: int) -> bool:
        return True

    async def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        return None

    async def take(self, key: str) -> int | None:
        return None


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"SECRET": None}, "must be a string or bytes"),
        ({"SITES": []}, "CAPWX['SITES'] must be a dict"),
        ({"SITES": {"bad name!": {}}}, "must match"),
        ({"SITES": {"login": 5}}, "must be a dict"),
        ({"SITES": {"login": {"SITE_SECRET": ""}}}, "non-empty string"),
        ({"SITES": {"login": {"INSTRUMENTATION": 5}}}, "INSTRUMENTATION must be a dict"),
        (
            {"SITES": {"login": {"INSTRUMENTATION": {"NOPE": 1}}}},
            "INSTRUMENTATION has unknown key",
        ),
        (
            {"SITES": {"login": {"INSTRUMENTATION": {"OBFUSCATION_LEVEL": 0}}}},
            "INSTRUMENTATION:",
        ),
        ({"SITES": {"login": {"HASHWX_DIFFICULTY": 0}}}, "login"),
        ({"CSRF_EXEMPT": "yes"}, "CAPWX['CSRF_EXEMPT'] must be a bool"),
        ({"PROTOCOLS": "hashwx"}, "PROTOCOLS must be a list of names"),
        ({"STORE_OPTIONS": 5}, "CAPWX['STORE_OPTIONS'] must be a dict"),
        ({"STORE": "no_such_module.Store"}, "cannot be imported"),
        ({"STORE": "capwx.stores.memory.MemoryStore", "STORE_OPTIONS": {"bogus": 1}}, "rejected"),
        ({"STORE": object()}, "must provide claim"),
        ({"STORE": _AsyncStore()}, "is async"),
        ({"DIFFICULTY_HOOK": 5}, "must be a dotted path or a callable"),
        ({"DIFFICULTY_HOOK": "no_such_module.hook"}, "cannot be imported"),
    ],
)
def test_bad_settings_raise_improperly_configured(changes: dict[str, Any], message: str) -> None:
    cfg = _capwx(**changes)
    with (
        override_settings(CAPWX=cfg),
        pytest.raises(ImproperlyConfigured, match=re.escape(message)),
    ):
        conf.get_conf()


def test_settings_must_be_a_mapping() -> None:
    with override_settings(CAPWX=[1]), pytest.raises(ImproperlyConfigured, match="must be a dict"):
        conf.get_conf()


def test_keys_must_be_strings_and_unique_after_upper_casing() -> None:
    with override_settings(CAPWX={1: "x"}), pytest.raises(ImproperlyConfigured, match="strings"):
        conf.get_conf()
    duplicated = dict(BASE)
    duplicated["secret"] = BASE["SECRET"]  # same key after upper-casing as "SECRET"
    with override_settings(CAPWX=duplicated), pytest.raises(ImproperlyConfigured, match="twice"):
        conf.get_conf()


def test_a_site_entry_set_to_none_means_defaults() -> None:
    with override_settings(CAPWX=_capwx(sites={"login": None})):
        site = conf.require_site("login")
        assert site.config.secret == BASE["SECRET"]
        assert site.site_secret is None


def test_require_site_names_an_unconfigured_site() -> None:
    with pytest.raises(ImproperlyConfigured, match="not configured"):
        conf.require_site("no-such-site")
    assert conf.get_site("no-such-site") is None


# --------------------------------------------------------------------------- capwx_check


def test_capwx_check_fails_when_the_static_wasm_differs(monkeypatch, tmp_path) -> None:
    tampered = tmp_path / "hashwx.wasm"
    tampered.write_bytes(b"not the vendored wasm")
    monkeypatch.setattr(capwx_check.finders, "find", lambda name: str(tampered))
    err = StringIO()
    with pytest.raises(CommandError, match="capwx_check failed"):
        call_command("capwx_check", stdout=StringIO(), stderr=err)
    assert "static hashwx.wasm sha256 mismatch" in err.getvalue()


def test_capwx_check_fails_when_the_static_wasm_is_not_found(monkeypatch) -> None:
    monkeypatch.setattr(capwx_check.finders, "find", lambda name: None)
    err = StringIO()
    with pytest.raises(CommandError, match="capwx_check failed"):
        call_command("capwx_check", stdout=StringIO(), stderr=err)
    assert "static hashwx.wasm not found" in err.getvalue()


def test_capwx_check_reports_a_crashing_site_as_a_failed_check(monkeypatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("mint exploded")

    monkeypatch.setattr(capwx_check, "create_challenge", boom)
    out, err = StringIO(), StringIO()
    with pytest.raises(CommandError, match="capwx_check failed"):
        call_command("capwx_check", stdout=out, stderr=err)
    assert "RuntimeError: mint exploded" in out.getvalue()
