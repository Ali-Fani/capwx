"""Config validation bounds (config.py)."""

import dataclasses

import pytest

from capwx.config import CapConfig, InstrumentationOptions
from capwx.errors import CapwxError

SECRET = "0123456789abcdef"  # exactly 16 bytes


def test_defaults_are_valid():
    cfg = CapConfig(secret=SECRET)
    assert cfg.protocols == ("hashwx", "instrumentation")
    assert cfg.hashwx_difficulty == 1_000_000
    assert cfg.hashwx_challenge_count == 4
    assert cfg.hashwx_nonces_per_hash == 65_536
    assert cfg.sha256_count == 50
    assert cfg.sha256_size == 16  # keeps the browser's wasm sha256 solver working (see config.py)
    assert cfg.sha256_difficulty == 4
    assert cfg.challenge_ttl_ms == 600_000
    assert cfg.token_ttl_ms == 1_200_000
    assert cfg.instrumentation == InstrumentationOptions()
    assert cfg.hashwx_wasm_path is None


def test_instrumentation_defaults():
    opts = InstrumentationOptions()
    assert opts.enabled is True
    assert opts.block_automated_browsers is False
    assert opts.obfuscation_level == 3
    assert opts.allow_csp_eval_blocked is False


def test_config_is_frozen():
    cfg = CapConfig(secret=SECRET)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.hashwx_difficulty = 5  # type: ignore[misc]


# --- secret -----------------------------------------------------------------


def test_secret_exactly_16_bytes_ok():
    CapConfig(secret="a" * 16)
    CapConfig(secret=b"a" * 16)


def test_short_secret_rejected():
    with pytest.raises(CapwxError, match="at least 16 bytes"):
        CapConfig(secret="a" * 15)
    with pytest.raises(CapwxError, match="at least 16 bytes"):
        CapConfig(secret=b"a" * 15)


def test_secret_length_counts_utf8_bytes():
    CapConfig(secret="é" * 8)  # 16 bytes in UTF-8
    with pytest.raises(CapwxError):
        CapConfig(secret="é" * 7)  # 14 bytes


def test_empty_secret_rejected():
    with pytest.raises(CapwxError):
        CapConfig(secret="")


@pytest.mark.parametrize("bad", [None, 123, ["a" * 32]])
def test_secret_wrong_type_rejected(bad):
    with pytest.raises(CapwxError, match="str or bytes"):
        CapConfig(secret=bad)


# --- int bounds -------------------------------------------------------------

INT_BOUNDS = [
    ("hashwx_difficulty", 1, 1_000_000_000),
    ("hashwx_challenge_count", 1, 64),
    ("hashwx_nonces_per_hash", 1, 1_048_576),
    ("sha256_count", 1, 1000),
    ("sha256_size", 1, 256),
    ("sha256_difficulty", 1, 16),
    ("challenge_ttl_ms", 1, 2**53 - 1),
    ("token_ttl_ms", 1, 2**53 - 1),
]


@pytest.mark.parametrize(("field", "lo", "hi"), INT_BOUNDS)
def test_int_bounds_inclusive(field, lo, hi):
    CapConfig(secret=SECRET, **{field: lo})
    CapConfig(secret=SECRET, **{field: hi})


@pytest.mark.parametrize(("field", "lo", "hi"), INT_BOUNDS)
def test_int_bounds_outside_rejected(field, lo, hi):
    with pytest.raises(CapwxError, match=rf"^{field} must be an integer in \[{lo}, {hi}\]$"):
        CapConfig(secret=SECRET, **{field: lo - 1})
    with pytest.raises(CapwxError, match=rf"^{field} must be an integer in \[{lo}, {hi}\]$"):
        CapConfig(secret=SECRET, **{field: hi + 1})


def test_message_example_from_plan():
    with pytest.raises(CapwxError) as exc:
        CapConfig(secret=SECRET, hashwx_difficulty=0)
    assert str(exc.value) == "hashwx_difficulty must be an integer in [1, 1000000000]"


@pytest.mark.parametrize(("field", "lo", "hi"), INT_BOUNDS)
def test_bool_rejected_for_int_fields(field, lo, hi):
    with pytest.raises(CapwxError):
        CapConfig(secret=SECRET, **{field: True})
    with pytest.raises(CapwxError):
        CapConfig(secret=SECRET, **{field: False})


@pytest.mark.parametrize(("field", "lo", "hi"), INT_BOUNDS)
def test_float_rejected_for_int_fields(field, lo, hi):
    with pytest.raises(CapwxError):
        CapConfig(secret=SECRET, **{field: float(lo)})


# --- protocols --------------------------------------------------------------


def test_protocols_list_coerced_to_tuple():
    cfg = CapConfig(secret=SECRET, protocols=["sha256-pow", "hashwx"])  # type: ignore[arg-type]
    assert cfg.protocols == ("sha256-pow", "hashwx")
    assert isinstance(cfg.protocols, tuple)


def test_all_known_protocols_accepted():
    CapConfig(secret=SECRET, protocols=("hashwx", "sha256-pow", "instrumentation"))


@pytest.mark.parametrize(
    "bad",
    [(), [], ("rsw",), ("hashwx", "nope"), ("hashwx", "hashwx"), "hashwx", None, (1,)],
)
def test_protocols_invalid_rejected(bad):
    with pytest.raises(CapwxError, match="protocols must be a non-empty tuple"):
        CapConfig(secret=SECRET, protocols=bad)


# --- instrumentation ---------------------------------------------------------


@pytest.mark.parametrize("level", [1, 5, 10])
def test_obfuscation_level_bounds_ok(level):
    InstrumentationOptions(obfuscation_level=level)


@pytest.mark.parametrize("level", [0, 11, -1])
def test_obfuscation_level_out_of_range_rejected(level):
    with pytest.raises(CapwxError, match=r"^instrumentation.obfuscation_level must be"):
        InstrumentationOptions(obfuscation_level=level)


def test_allow_csp_eval_blocked_must_be_bool():
    assert InstrumentationOptions(allow_csp_eval_blocked=True).allow_csp_eval_blocked is True
    with pytest.raises(CapwxError, match=r"^instrumentation.allow_csp_eval_blocked must be a bool"):
        InstrumentationOptions(allow_csp_eval_blocked=1)  # type: ignore[arg-type]


def test_obfuscation_level_bool_rejected():
    with pytest.raises(CapwxError):
        InstrumentationOptions(obfuscation_level=True)


def test_instrumentation_flags_must_be_bool():
    with pytest.raises(CapwxError):
        InstrumentationOptions(enabled=1)  # type: ignore[arg-type]
    with pytest.raises(CapwxError):
        InstrumentationOptions(block_automated_browsers="yes")  # type: ignore[arg-type]


def test_instrumentation_wrong_type_rejected():
    with pytest.raises(CapwxError, match="InstrumentationOptions"):
        CapConfig(secret=SECRET, instrumentation={"enabled": True})  # type: ignore[arg-type]


def test_instrumentation_options_are_frozen():
    opts = InstrumentationOptions()
    with pytest.raises(dataclasses.FrozenInstanceError):
        opts.enabled = False  # type: ignore[misc]


# --- wasm path ---------------------------------------------------------------


def test_wasm_path_none_or_str_ok():
    CapConfig(secret=SECRET, hashwx_wasm_path=None)
    CapConfig(secret=SECRET, hashwx_wasm_path="/opt/hashwx.wasm")


def test_wasm_path_wrong_type_rejected():
    with pytest.raises(CapwxError, match="hashwx_wasm_path"):
        CapConfig(secret=SECRET, hashwx_wasm_path=123)  # type: ignore[arg-type]
