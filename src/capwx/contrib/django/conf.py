"""capwx.contrib.django.conf: parses, validates and caches ``settings.CAPWX``.

Settings shape (see plan section 11.1)::

    CAPWX = {
        "SECRET": env("CAPWX_SECRET"),             # required, >= 16 bytes
        "SITES": {"login": {"HASHWX_DIFFICULTY": 1_000_000,
                            "INSTRUMENTATION": {"BLOCK_AUTOMATED_BROWSERS": True},
                            "SITE_SECRET": "..."}},  # SITE_SECRET enables /siteverify
        "STORE": "capwx.stores.django_cache.DjangoCacheStore",
        "STORE_OPTIONS": {"alias": "default"},
        "PROTOCOLS": ["hashwx", "instrumentation"],
        "CSRF_EXEMPT": True,
        "DIFFICULTY_HOOK": None,
        "BEFORE_CHALLENGE_HOOK": None,
        ...any other CapConfig field in UPPER_CASE...
    }

Every ``CapConfig`` field is accepted in UPPER_CASE, at the top level (global default) or inside
a site. ``INSTRUMENTATION`` takes ``ENABLED``, ``BLOCK_AUTOMATED_BROWSERS`` and
``OBFUSCATION_LEVEL``. ``SECRET`` is global only. The site name ``"default"`` always exists, even
when it is not listed in ``SITES``.

The parsed result is cached. The cache is dropped when ``CAPWX`` changes (``override_settings``) and
by :func:`reset_conf_cache`. Settings errors raise ``ImproperlyConfigured``.
"""

from __future__ import annotations

import dataclasses
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string  # pyright: ignore[reportUnknownVariableType]

from capwx._types import as_json_list, as_mapping
from capwx.config import CapConfig, InstrumentationOptions
from capwx.errors import CapwxError
from capwx.stores import is_async_store

SETTING_NAME = "CAPWX"
DEFAULT_SITE = "default"
TOKEN_FIELD = "cap-token"  # the hidden input the widget fills; read by CapField and require_cap
TOKEN_HEADER = "X-Cap-Token"
MAX_BODY_BYTES = 64 * 1024
DEFAULT_STORE = "capwx.stores.django_cache.DjangoCacheStore"

_SITE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_CONFIG_FIELDS = {field.name.upper(): field.name for field in dataclasses.fields(CapConfig)}
_INSTRUMENTATION_FIELDS = {
    "ENABLED": "enabled",
    "BLOCK_AUTOMATED_BROWSERS": "block_automated_browsers",
    "OBFUSCATION_LEVEL": "obfuscation_level",
}
_GLOBAL_ONLY = {
    "SITES",
    "STORE",
    "STORE_OPTIONS",
    "CSRF_EXEMPT",
    "DIFFICULTY_HOOK",
    "BEFORE_CHALLENGE_HOOK",
}
_SITE_ONLY = {"SITE_SECRET"}


@dataclass(frozen=True)
class SiteConf:
    """Resolved configuration for one site (scope). ``site_secret`` is None when siteverify is off."""

    name: str
    config: CapConfig
    site_secret: str | bytes | None = field(repr=False)


@dataclass(frozen=True)
class CapwxConf:
    sites: Mapping[str, SiteConf]
    store: Any  # one instance shared by the nonce store and the token store
    csrf_exempt: bool
    difficulty_hook: Callable[..., Any] | None
    before_challenge_hook: Callable[..., Any] | None


_lock = threading.Lock()
_cached: CapwxConf | None = None


# --------------------------------------------------------------------------- parsing helpers


def _upper_keys(raw: Mapping[Any, Any], where: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            raise ImproperlyConfigured(f"{where}: keys must be strings, got {key!r}")
        upper = key.upper()
        if upper in out:
            raise ImproperlyConfigured(f"{where}: key {key!r} given twice")
        out[upper] = value
    return out


def _instrumentation(value: object, where: str) -> InstrumentationOptions:
    if isinstance(value, InstrumentationOptions):
        return value
    mapping = as_mapping(value)
    if mapping is None:
        raise ImproperlyConfigured(f"{where}: INSTRUMENTATION must be a dict")
    raw = _upper_keys(mapping, f"{where} INSTRUMENTATION")
    unknown = set(raw) - set(_INSTRUMENTATION_FIELDS)
    if unknown:
        raise ImproperlyConfigured(
            f"{where} INSTRUMENTATION has unknown key(s): {', '.join(sorted(unknown))}"
        )
    kwargs = {_INSTRUMENTATION_FIELDS[key]: val for key, val in raw.items()}
    try:
        return InstrumentationOptions(**kwargs)
    except CapwxError as exc:
        raise ImproperlyConfigured(f"{where} INSTRUMENTATION: {exc}") from exc


def _config_kwargs(raw: Mapping[str, Any], where: str) -> dict[str, Any]:
    """Map UPPER_CASE keys that are CapConfig fields onto field names (SECRET is handled apart)."""
    kwargs: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in _CONFIG_FIELDS:
            continue
        name = _CONFIG_FIELDS[key]
        if name == "secret":
            continue
        if name == "instrumentation":
            value = _instrumentation(value, where)
        elif name == "protocols":
            names = as_json_list(value)
            if names is not None:
                value = tuple(names)
            if not isinstance(value, tuple):
                raise ImproperlyConfigured(f"{where}: PROTOCOLS must be a list of names")
        kwargs[name] = value
    return kwargs


def _check_unknown(raw: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise ImproperlyConfigured(f"{where} has unknown key(s): {', '.join(sorted(unknown))}")


def _hook(value: object, name: str) -> Callable[..., Any] | None:
    if value is None:
        return None
    target: object = value
    if isinstance(value, str):
        try:
            target = import_string(value)
        except ImportError as exc:
            raise ImproperlyConfigured(f"{name} cannot be imported: {exc}") from exc
    if not callable(target):
        raise ImproperlyConfigured(f"{name} must be a dotted path or a callable")
    return target


def _store(raw: Mapping[str, Any]) -> Any:
    path = raw.get("STORE", DEFAULT_STORE)
    options = as_mapping(raw.get("STORE_OPTIONS", {}))
    if options is None:
        raise ImproperlyConfigured("CAPWX['STORE_OPTIONS'] must be a dict")
    if isinstance(path, str):
        try:
            cls: Any = import_string(path)
        except ImportError as exc:
            raise ImproperlyConfigured(f"CAPWX['STORE'] cannot be imported: {exc}") from exc
        try:
            store = cls(**dict(options))
        except TypeError as exc:
            raise ImproperlyConfigured(f"CAPWX['STORE'] rejected STORE_OPTIONS: {exc}") from exc
    else:
        store = path
    if not all(callable(getattr(store, name, None)) for name in ("claim", "put", "take")):
        raise ImproperlyConfigured("CAPWX['STORE'] must provide claim(), put() and take()")
    if is_async_store(store):
        raise ImproperlyConfigured(
            "CAPWX['STORE'] is async; the Django views need a synchronous store"
        )
    return store


def _site_secret(value: object, name: str) -> str | bytes:
    if not isinstance(value, (str, bytes)) or not value:
        raise ImproperlyConfigured(f"CAPWX site {name!r}: SITE_SECRET must be a non-empty string")
    return value


# --------------------------------------------------------------------------- build


def _build(raw: object) -> CapwxConf:
    raw_mapping = as_mapping(raw)
    if raw_mapping is None:
        raise ImproperlyConfigured("settings.CAPWX is required and must be a dict")
    top = _upper_keys(raw_mapping, "CAPWX")
    _check_unknown(top, _GLOBAL_ONLY | set(_CONFIG_FIELDS), "CAPWX")

    if "SECRET" not in top:
        raise ImproperlyConfigured(
            "CAPWX['SECRET'] is required (at least 16 bytes; use 32 random bytes from the "
            "environment, not DJANGO SECRET_KEY)"
        )
    secret = top["SECRET"]
    if not isinstance(secret, (str, bytes)):
        raise ImproperlyConfigured("CAPWX['SECRET'] must be a string or bytes")

    sites_raw = as_mapping(top.get("SITES", {}))
    if sites_raw is None:
        raise ImproperlyConfigured("CAPWX['SITES'] must be a dict")
    sites_upper: dict[str, object] = {str(name): value for name, value in sites_raw.items()}
    global_kwargs = _config_kwargs(top, "CAPWX")

    sites: dict[str, SiteConf] = {}
    for name in dict.fromkeys([DEFAULT_SITE, *sites_upper]):
        if not _SITE_NAME_RE.fullmatch(name):
            raise ImproperlyConfigured(
                f"CAPWX site name {name!r} must match [A-Za-z0-9_.-]{{1,64}}"
            )
        raw_site = sites_upper.get(name)
        site_mapping: Mapping[Any, Any] | None = {} if raw_site is None else as_mapping(raw_site)
        if site_mapping is None:
            raise ImproperlyConfigured(f"CAPWX site {name!r} must be a dict")
        where = f"CAPWX site {name!r}"
        site_raw = _upper_keys(site_mapping, where)
        if "SECRET" in site_raw:
            raise ImproperlyConfigured(f"{where}: SECRET is global only")
        _check_unknown(site_raw, _SITE_ONLY | set(_CONFIG_FIELDS), where)

        site_secret = None
        if "SITE_SECRET" in site_raw:
            site_secret = _site_secret(site_raw.pop("SITE_SECRET"), name)

        kwargs: dict[str, Any] = {**global_kwargs, **_config_kwargs(site_raw, where)}
        kwargs["secret"] = secret
        try:
            config = CapConfig(**kwargs)
        except CapwxError as exc:
            raise ImproperlyConfigured(f"{where}: {exc}") from exc
        sites[name] = SiteConf(name=name, config=config, site_secret=site_secret)

    csrf_exempt = top.get("CSRF_EXEMPT", True)
    if not isinstance(csrf_exempt, bool):
        raise ImproperlyConfigured("CAPWX['CSRF_EXEMPT'] must be a bool")

    return CapwxConf(
        sites=sites,
        store=_store(top),
        csrf_exempt=csrf_exempt,
        difficulty_hook=_hook(top.get("DIFFICULTY_HOOK"), "CAPWX['DIFFICULTY_HOOK']"),
        before_challenge_hook=_hook(
            top.get("BEFORE_CHALLENGE_HOOK"), "CAPWX['BEFORE_CHALLENGE_HOOK']"
        ),
    )


# --------------------------------------------------------------------------- public helpers


def get_conf() -> CapwxConf:
    """Return the parsed, cached configuration. Raises ``ImproperlyConfigured`` if invalid."""
    global _cached
    with _lock:
        if _cached is None:
            _cached = _build(getattr(settings, SETTING_NAME, None))
        return _cached


def validate_settings() -> CapwxConf:
    """Alias of :func:`get_conf`, used at startup (``AppConfig.ready``)."""
    return get_conf()


def get_site(name: str) -> SiteConf | None:
    """The site's configuration, or None for an unknown site (the views answer 404)."""
    return get_conf().sites.get(name)


def require_site(name: str) -> SiteConf:
    """Like :func:`get_site`, but an unknown site is a template or code error."""
    site = get_site(name)
    if site is None:
        raise ImproperlyConfigured(f"capwx: site {name!r} is not configured (see CAPWX['SITES'])")
    return site


def reset_conf_cache() -> None:
    """Forget the parsed configuration (tests, and after changing settings at runtime)."""
    global _cached
    with _lock:
        _cached = None


def endpoint_base(site: str) -> str:
    """The widget's ``data-cap-api-endpoint`` for a site, e.g. ``/cap/login/`` (ends in '/')."""
    from django.urls import reverse  # pyright: ignore[reportUnknownVariableType]

    url = str(reverse("capwx:challenge", kwargs={"site": site}))  # pyright: ignore[reportUnknownArgumentType]
    return url[: -len("challenge")]


def _on_setting_changed(*, setting: str, **kwargs: object) -> None:
    if setting == SETTING_NAME:
        reset_conf_cache()


setting_changed.connect(_on_setting_changed, dispatch_uid="capwx.conf.reset")  # pyright: ignore[reportUnknownMemberType]

__all__ = [
    "DEFAULT_SITE",
    "DEFAULT_STORE",
    "MAX_BODY_BYTES",
    "TOKEN_FIELD",
    "TOKEN_HEADER",
    "CapwxConf",
    "SiteConf",
    "endpoint_base",
    "get_conf",
    "get_site",
    "require_site",
    "reset_conf_cache",
    "validate_settings",
]
