"""Benchmarks for the public challenge lifecycle: mint, redeem, validate.

Run with ``uv run pytest benchmarks -q``. ``pytest-benchmark`` prints mean/median/stddev and the
number of rounds; add ``--benchmark-columns=mean,median,stddev,ops`` for request rates.
"""

from __future__ import annotations

from typing import Any

from capwx.challenge import create_challenge, redeem
from capwx.config import CapConfig
from capwx.tokens import issue_token, siteverify, validate_token


def test_mint_default(benchmark: Any, cfg_default: CapConfig) -> None:
    """POST /cap/challenge for the default protocol set (hashwx + instrumentation)."""
    response = benchmark(create_challenge, cfg_default)
    assert {c["protocol"] for c in response["challenges"]} == {"hashwx", "instrumentation"}


def test_mint_hashwx_only(benchmark: Any, cfg_hashwx: CapConfig) -> None:
    """hashwx mint is random bytes and dict building; this isolates that from the wasm engine."""
    benchmark(create_challenge, cfg_hashwx)


def test_mint_instrumentation_level3(benchmark: Any, cfg_instrumentation: CapConfig) -> None:
    """Instrumentation at its default obfuscation level (whitespace stripping only)."""
    benchmark(create_challenge, cfg_instrumentation)


def test_mint_instrumentation_level7(benchmark: Any, cfg_instrumentation_level7: CapConfig) -> None:
    """Instrumentation at the heaviest supported level (string table + whitespace stripping)."""
    benchmark(create_challenge, cfg_instrumentation_level7)


def test_mint_sha256_pow(benchmark: Any, cfg_sha256: CapConfig) -> None:
    benchmark(create_challenge, cfg_sha256)


def test_redeem_default(
    benchmark: Any, cfg_default: CapConfig, default_body: dict[str, Any]
) -> None:
    """POST /cap/redeem: verify hashwx + instrumentation, then issue a stateless token.

    No nonce store is passed, so the pre-solved body is reusable; the verification cost measured
    here is the same as with a store (the store call is benchmarked separately below).
    """
    result = benchmark(redeem, cfg_default, default_body)
    assert result.success


def test_redeem_hashwx_only(
    benchmark: Any, cfg_hashwx: CapConfig, hashwx_body: dict[str, Any]
) -> None:
    result = benchmark(redeem, cfg_hashwx, hashwx_body)
    assert result.success


def test_redeem_instrumentation_only(
    benchmark: Any, cfg_instrumentation: CapConfig, instrumentation_body: dict[str, Any]
) -> None:
    result = benchmark(redeem, cfg_instrumentation, instrumentation_body)
    assert result.success


def test_redeem_sha256_pow(
    benchmark: Any, cfg_sha256: CapConfig, sha256_body: dict[str, Any]
) -> None:
    result = benchmark(redeem, cfg_sha256, sha256_body)
    assert result.success


def test_redeem_with_nonce_and_token_store(
    benchmark: Any,
    cfg_default: CapConfig,
    store_bodies: list[dict[str, Any]],
    memory_store: Any,
) -> None:
    """The full production shape: single-use nonce claim plus a stored verification token."""
    bodies = iter(store_bodies)
    result = benchmark.pedantic(
        lambda: redeem(
            cfg_default, next(bodies), nonce_store=memory_store, token_store=memory_store
        ),
        rounds=5,
        iterations=5,
    )
    assert result.success


def test_issue_token_stateless(benchmark: Any, cfg_default: CapConfig) -> None:
    """The signing half of redeem: HS256 JWT with a random nonce."""
    benchmark(issue_token, cfg_default)


def test_validate_token_stateless(benchmark: Any, cfg_default: CapConfig) -> None:
    """The form handler's check: HMAC verify + JSON decode, no store."""
    token, _ = issue_token(cfg_default)
    assert benchmark(validate_token, cfg_default, token) is True


def test_validate_token_stored(benchmark: Any, cfg_default: CapConfig, memory_store: Any) -> None:
    """Stored token check without consuming it (``peek`` is the cheap non-destructive read)."""
    token, _ = issue_token(cfg_default, token_store=memory_store)
    assert benchmark(validate_token, cfg_default, token, token_store=memory_store, consume=False)


def test_siteverify_stateless(benchmark: Any, cfg_default: CapConfig) -> None:
    """Standalone-style siteverify: constant-time secret check + token validation."""
    token, _ = issue_token(cfg_default)
    result = benchmark(
        siteverify, cfg_default, cfg_default.secret, token, site_secret=cfg_default.secret
    )
    assert result == {"success": True}
