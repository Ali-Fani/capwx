"""capwx.challenge: create_challenge() and redeem(), the challenge lifecycle (M8).

Port of upstream ``generateChallengeV2`` and ``validateChallengeV2`` (``core/src/index.js``,
capjs-core 0.1.5, format 2). Where the plan and upstream disagree, upstream wins.

Rules:

- Client input never raises. Bad bodies, tokens and solutions come back as
  ``RedeemResult(success=False, reason=...)``.
- The replay claim happens only after every solution has verified, so garbage submissions cannot
  burn a real user's nonce.
- Only programmer errors raise ``CapwxError``: invalid config or overrides, an unknown protocol,
  a scope containing ``':'``, or an async store passed to a sync function.
- Protocol modules are imported lazily, so a ``sha256-pow``-only setup never imports wasmtime.
- Logs never contain tokens, solutions or probe data: logger ``"capwx"`` gets one INFO line per
  redeem.

Adding a protocol: add its module name to ``_PROTOCOL_MODULES``, a mint function to ``_MINTERS``
and a verify function to ``_VERIFIERS``. Then add the name to ``config.KNOWN_PROTOCOLS``.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import logging
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from capwx._crypto import decrypt_gcm, encrypt_gcm, jwt_sig_hex, jwt_sign, jwt_verify, random_hex
from capwx._types import JsonDict, as_json_dict, as_json_list
from capwx.config import CapConfig
from capwx.errors import CapwxError, Reason
from capwx.stores import is_async_store
from capwx.tokens import aissue_token, issue_token

__all__ = [
    "RedeemResult",
    "acreate_challenge",
    "aredeem",
    "create_challenge",
    "redeem",
    "set_event_callback",
]

logger = logging.getLogger("capwx")

FORMAT = 2
_FORMAT_INFO = "cap:fmt2-v1"  # HKDF-style info string for the encrypted ``ev`` claim
_NONCE_KEY_PREFIX = "capwx:nonce:"
_DEFAULT_SITE = "default"

# Protocol name -> module, imported on first use. hashwx pulls in wasmtime, so it must stay lazy.
_PROTOCOL_MODULES: dict[str, str] = {
    "sha256-pow": "capwx.protocols.sha256_pow",
    "hashwx": "capwx.protocols.hashwx",
    "instrumentation": "capwx.protocols.instrumentation",
}

EventCallback = Callable[..., None]
_event_callback: EventCallback | None = None
_warned_no_nonce_store = False


# --------------------------------------------------------------------------- result


@dataclass
class RedeemResult:
    """Outcome of :func:`redeem`. ``reason`` is set iff ``success`` is False.

    ``reason`` is a :class:`Reason` member, or a plain string for the few instrumentation
    reasons that upstream passes through unchanged (for example ``"missing_meta"``).
    """

    success: bool
    reason: Reason | str | None = None
    token: str | None = None  # verification token for the widget
    expires: int | None = None  # ms epoch
    scope: str | None = None
    risk_flags: list[str] = field(default_factory=list[str])
    blocked_by: list[str] = field(default_factory=list[str])
    instr_error: bool = False

    def to_widget_json(self) -> dict[str, Any]:
        """The JSON the Cap widget expects from ``POST .../redeem``."""
        if self.success:
            return {"success": True, "token": self.token, "expires": self.expires}
        return {"success": False, "error": _reason_str(self.reason)}


def _reason_str(reason: Reason | str | None) -> str:
    if reason is None:
        return "unknown"
    return reason.value if isinstance(reason, Reason) else str(reason)


def _failed(
    reason: Reason | str, *, instr_error: bool = False, blocked_by: tuple[str, ...] = ()
) -> RedeemResult:
    return RedeemResult(
        success=False, reason=reason, instr_error=instr_error, blocked_by=list(blocked_by)
    )


# --------------------------------------------------------------------------- events and logs


def set_event_callback(callback: EventCallback | None) -> None:
    """Install ``callback(name, **labels)`` for metrics, or ``None`` to remove it.

    Events: ``"challenge_created"`` (labels ``site``, ``protocol``) and ``"redeem"`` (labels
    ``site``, ``reason``; ``reason`` is ``"success"`` or a :class:`Reason` value). Labels are
    low-cardinality. Exceptions raised by the callback are logged and never reach the caller.
    """
    global _event_callback
    _event_callback = callback


def _emit(name: str, **labels: str) -> None:
    callback = _event_callback
    if callback is None:
        return
    try:
        callback(name, **labels)
    except Exception:  # a metrics hook must never break verification
        logger.exception("capwx: event callback failed for %r", name)


def _warn_no_nonce_store() -> None:
    global _warned_no_nonce_store
    if _warned_no_nonce_store:
        return
    _warned_no_nonce_store = True
    logger.warning(
        "capwx: redeem() called without a nonce_store; a solved challenge can be replayed "
        "until it expires. Pass a shared NonceStore in production."
    )


def _finish(result: RedeemResult, site: str, started: float) -> RedeemResult:
    duration_ms = (time.perf_counter() - started) * 1000
    reason = "success" if result.success else _reason_str(result.reason)
    logger.info(
        "redeem site=%s success=%s reason=%s duration_ms=%.1f",
        site,
        result.success,
        reason,
        duration_ms,
    )
    _emit("redeem", site=site, reason=reason)
    return result


# --------------------------------------------------------------------------- helpers


def _resolve_now(now_ms: object) -> int:
    if now_ms is None:
        return int(time.time() * 1000)
    if isinstance(now_ms, bool) or not isinstance(now_ms, int):
        raise CapwxError("now_ms must be an int or None")
    return now_ms


def _scope_claim(scope: object) -> str | None:
    """``sk`` claim value: None/'' mean no scope. ``':'`` is refused (stored tokens use it)."""
    if scope is None or scope == "":
        return None
    text = str(scope)
    if ":" in text:
        raise CapwxError("scope must not contain ':'")
    return text


def _site_label(scope: str | None) -> str:
    return scope or _DEFAULT_SITE


def _apply_overrides(config: CapConfig, overrides: Mapping[str, Any] | None) -> CapConfig:
    """Per-request config changes (adaptive difficulty). Invalid values raise CapwxError.

    Those are programmer errors: the overrides are chosen by the application, not the client.
    """
    if not overrides:
        return config
    try:
        return dataclasses.replace(config, **dict(overrides))
    except TypeError as exc:
        raise CapwxError(f"invalid config override: {exc}") from exc


def _reject_async(name: str, store: object) -> None:
    if store is not None and is_async_store(store):
        raise CapwxError(f"{name} is async; use aredeem / acreate_challenge")


def _load(name: str) -> Any:
    """Import a protocol module on first use (keeps wasmtime out of sha256-only setups)."""
    module_name = _PROTOCOL_MODULES.get(name)
    if module_name is None:
        raise CapwxError(f"unknown protocol {name!r}")
    return importlib.import_module(module_name)


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


# --------------------------------------------------------------------------- minting

Minted = list[tuple[JsonDict, JsonDict]]  # [(public_payload, expected), ...]


def _mint_sha256_pow(config: CapConfig, expires_ms: int) -> Minted:
    return _load("sha256-pow").mint(config)


def _mint_hashwx(config: CapConfig, expires_ms: int) -> Minted:
    return _load("hashwx").mint(config)


def _mint_instrumentation(config: CapConfig, expires_ms: int) -> Minted:
    return _load("instrumentation").mint(config, expires_ms=expires_ms)


_MINTERS: dict[str, Callable[[CapConfig, int], Minted]] = {
    "sha256-pow": _mint_sha256_pow,
    "hashwx": _mint_hashwx,
    "instrumentation": _mint_instrumentation,
}


def _mint_all(config: CapConfig, exp: int, site: str) -> tuple[list[JsonDict], list[JsonDict]]:
    challenges: list[JsonDict] = []
    expected: list[JsonDict] = []
    for name in config.protocols:
        if name == "instrumentation" and not config.instrumentation.enabled:
            # ``instrumentation`` is listed in protocols but switched off in its options.
            # The protocol's mint() ignores ``enabled``, so skip it here.
            continue
        minter = _MINTERS.get(name)
        if minter is None:
            raise CapwxError(f"unknown protocol {name!r}")
        for payload, entry in minter(config, exp):
            challenges.append({"protocol": name, "payload": payload})
            expected.append(entry)
        _emit("challenge_created", site=site, protocol=name)
    if not challenges:
        raise CapwxError("no challenge protocol is enabled")
    return challenges, expected


def create_challenge(
    config: CapConfig,
    *,
    scope: str | None = None,
    extra: dict[str, Any] | None = None,
    overrides: Mapping[str, Any] | None = None,
    now_ms: int | None = None,
) -> dict[str, Any]:
    """Mint a format-2 challenge for the widget (port of ``generateChallengeV2``).

    Returns exactly ``{"token", "format": 2, "challenges": [{"protocol", "payload"}...], "expires"}``.
    ``scope`` becomes the ``sk`` claim. ``extra`` becomes the ``x`` claim if it is a dict, and the
    client can read it, so never put secrets there. ``overrides`` is applied with
    ``dataclasses.replace`` before minting. Invalid overrides raise ``CapwxError``.
    """
    cfg = _apply_overrides(config, overrides)
    sk = _scope_claim(scope)
    now = _resolve_now(now_ms)
    exp = now + cfg.challenge_ttl_ms
    challenges, expected = _mint_all(cfg, exp, _site_label(sk))

    token_payload: dict[str, Any] = {
        "f": FORMAT,
        "n": random_hex(16),
        "exp": exp,
        "iat": now,
        "ev": encrypt_gcm({"expected": expected}, cfg.secret, _FORMAT_INFO),
    }
    if sk is not None:
        token_payload["sk"] = sk
    if isinstance(extra, dict):
        token_payload["x"] = extra
    return {
        "token": jwt_sign(token_payload, cfg.secret),
        "format": FORMAT,
        "challenges": challenges,
        "expires": exp,
    }


async def acreate_challenge(
    config: CapConfig,
    *,
    scope: str | None = None,
    extra: dict[str, Any] | None = None,
    overrides: Mapping[str, Any] | None = None,
    now_ms: int | None = None,
) -> dict[str, Any]:
    """Async twin of :func:`create_challenge`. Minting does no I/O, so this only awaits nothing."""
    return create_challenge(config, scope=scope, extra=extra, overrides=overrides, now_ms=now_ms)


# --------------------------------------------------------------------------- verification


@dataclass(frozen=True)
class _Step:
    """Outcome of verifying one solution. ``reason`` is None when the solution is valid."""

    reason: Reason | str | None = None
    instr_error: bool = False
    risk_flags: tuple[str, ...] = ()
    blocked_by: tuple[str, ...] = ()


def _verify_sha256_pow(
    config: CapConfig,
    expected: JsonDict,
    solution: JsonDict,
    body: JsonDict,
    now: int,
) -> _Step:
    ok = bool(_load("sha256-pow").verify(expected, solution))
    return _Step() if ok else _Step(reason=Reason.INVALID_SOLUTION)


def _verify_hashwx(
    config: CapConfig,
    expected: JsonDict,
    solution: JsonDict,
    body: JsonDict,
    now: int,
) -> _Step:
    hw = _load("hashwx")
    ok = bool(hw.verify(expected, solution, engine=hw.get_engine(config.hashwx_wasm_path)))
    return _Step() if ok else _Step(reason=Reason.INVALID_SOLUTION)


def _verify_instrumentation(
    config: CapConfig,
    expected: JsonDict,
    solution: JsonDict,
    body: JsonDict,
    now: int,
) -> _Step:
    # Legacy top-level flags: the widget sends these in one code path instead of inside the solution.
    res = _load("instrumentation").verify(
        expected,
        solution,
        now_ms=now,
        blocked=body.get("instr_blocked") is True,
        timeout=body.get("instr_timeout") is True,
    )
    if res.valid:
        return _Step(risk_flags=tuple(res.risk_flags), blocked_by=tuple(res.blocked_by))
    return _Step(
        reason=res.reason or Reason.INSTR_FAILED,
        instr_error=True,
        blocked_by=tuple(res.blocked_by),
    )


_Verifier = Callable[[CapConfig, JsonDict, JsonDict, JsonDict, int], _Step]

_VERIFIERS: dict[str, _Verifier] = {
    "sha256-pow": _verify_sha256_pow,
    "hashwx": _verify_hashwx,
    "instrumentation": _verify_instrumentation,
}


def _verify_step(
    config: CapConfig, entry: object, solution: object, body: JsonDict, now: int
) -> _Step:
    expected = as_json_dict(entry)
    sol = as_json_dict(solution)
    if expected is None or sol is None:
        return _Step(reason=Reason.INVALID_SOLUTION)
    proto = expected.get("protocol")
    handler = _VERIFIERS.get(proto) if isinstance(proto, str) else None
    if handler is None:
        return _Step(reason=Reason.INVALID_SOLUTION)
    return handler(config, expected, sol, body, now)


@dataclass(frozen=True)
class _Verified:
    """Everything redeem needs after verification: the sk claim and the replay-claim arguments."""

    scope: str | None
    nonce_key: str
    nonce_ttl_s: int
    risk_flags: tuple[str, ...]
    blocked_by: tuple[str, ...]


def _verify_body(
    config: CapConfig, raw_body: object, expected_scope: str | None, now: int
) -> RedeemResult | _Verified:
    """Checks 1-7 of plan §8.2. Never raises on client input."""
    body = as_json_dict(raw_body)
    if body is None:
        return _failed(Reason.INVALID_BODY)
    token = body.get("token")
    if not isinstance(token, str) or not token:
        return _failed(Reason.MISSING_TOKEN)
    solutions = as_json_list(body.get("solutions"))
    if solutions is None:
        return _failed(Reason.MISSING_SOLUTIONS)

    payload = jwt_verify(token, config.secret)
    if payload is None or type(payload.get("f")) is not int or payload["f"] != FORMAT:
        return _failed(Reason.INVALID_TOKEN)  # format 1 is not supported
    sig = jwt_sig_hex(token)
    if sig is None:  # unreachable after jwt_verify succeeded; kept as a guard
        return _failed(Reason.INVALID_TOKEN)

    sk = payload.get("sk")
    token_scope = sk if isinstance(sk, str) and sk else None
    if expected_scope is not None and sk != expected_scope:
        return _failed(Reason.SCOPE_MISMATCH)

    exp = payload.get("exp")
    if (
        isinstance(exp, bool)
        or not isinstance(exp, (int, float))
        or not math.isfinite(exp)
        or exp < now
    ):
        return _failed(Reason.EXPIRED)

    decrypted = as_json_dict(decrypt_gcm(payload.get("ev"), config.secret, _FORMAT_INFO))
    expected = as_json_list(decrypted.get("expected")) if decrypted is not None else None
    if expected is None:
        return _failed(Reason.INVALID_TOKEN)
    if len(solutions) != len(expected):
        return _failed(Reason.INVALID_SOLUTIONS)

    risk_flags: list[str] = []
    blocked_by: list[str] = []
    for entry, solution in zip(expected, solutions):
        step = _verify_step(config, entry, solution, body, now)
        if step.reason is not None:
            return _failed(step.reason, instr_error=step.instr_error, blocked_by=step.blocked_by)
        risk_flags.extend(step.risk_flags)
        blocked_by.extend(step.blocked_by)

    return _Verified(
        scope=token_scope,
        nonce_key=_NONCE_KEY_PREFIX + sig,
        nonce_ttl_s=max(1, math.ceil((exp - now) / 1000)),
        risk_flags=tuple(risk_flags),
        blocked_by=tuple(blocked_by),
    )


def _success(checked: _Verified, token: str, expires: int) -> RedeemResult:
    return RedeemResult(
        success=True,
        token=token,
        expires=expires,
        scope=checked.scope,
        risk_flags=list(checked.risk_flags),
        blocked_by=list(checked.blocked_by),
    )


def redeem(
    config: CapConfig,
    body: object,
    *,
    scope: str | None = None,
    nonce_store: Any = None,
    token_store: Any = None,
    now_ms: int | None = None,
) -> RedeemResult:
    """Verify a widget solution and issue a verification token (port of ``validateChallenge``).

    Checks run in plan §8.2 order. The replay claim (``nonce_store``) comes after every solution
    has verified. ``token_store`` makes the issued token single-use; without it the token is
    stateless. Sync stores only; use :func:`aredeem` with async stores.
    """
    started = time.perf_counter()
    expected_scope = _scope_claim(scope)
    _reject_async("nonce_store", nonce_store)
    _reject_async("token_store", token_store)
    now = _resolve_now(now_ms)
    site = _site_label(expected_scope)

    checked = _verify_body(config, body, expected_scope, now)
    if isinstance(checked, RedeemResult):
        return _finish(checked, site, started)

    if nonce_store is None:
        _warn_no_nonce_store()
    else:
        try:
            claimed = nonce_store.claim(checked.nonce_key, checked.nonce_ttl_s)
        except Exception:  # noqa: BLE001 - a store outage is a reason, not a crash
            return _finish(_failed(Reason.NONCE_STORE_ERROR), site, started)
        if not claimed:
            return _finish(_failed(Reason.ALREADY_REDEEMED), site, started)

    token, expires = issue_token(config, scope=checked.scope, token_store=token_store)
    return _finish(_success(checked, token, expires), site, started)


async def aredeem(
    config: CapConfig,
    body: object,
    *,
    scope: str | None = None,
    nonce_store: Any = None,
    token_store: Any = None,
    now_ms: int | None = None,
) -> RedeemResult:
    """Async twin of :func:`redeem`. Awaits the stores when they are async; sync stores also work."""
    started = time.perf_counter()
    expected_scope = _scope_claim(scope)
    now = _resolve_now(now_ms)
    site = _site_label(expected_scope)

    checked = _verify_body(config, body, expected_scope, now)
    if isinstance(checked, RedeemResult):
        return _finish(checked, site, started)

    if nonce_store is None:
        _warn_no_nonce_store()
    else:
        try:
            claimed = await _await(nonce_store.claim(checked.nonce_key, checked.nonce_ttl_s))
        except Exception:  # noqa: BLE001 - a store outage is a reason, not a crash
            return _finish(_failed(Reason.NONCE_STORE_ERROR), site, started)
        if not claimed:
            return _finish(_failed(Reason.ALREADY_REDEEMED), site, started)

    token, expires = await aissue_token(config, scope=checked.scope, token_store=token_store)
    return _finish(_success(checked, token, expires), site, started)
