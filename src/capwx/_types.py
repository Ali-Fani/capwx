"""capwx._types: shared typing helpers for the JSON-shaped payloads.

Challenge payloads, solutions and decrypted claims are JSON values whose contents are checked
at runtime. They are typed ``Any`` at the boundary and narrowed with the helpers below, which
cast once after an ``isinstance`` check, instead of leaving bare ``dict`` / ``list`` types behind.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeAlias, cast

JsonDict: TypeAlias = dict[str, Any]
JsonList: TypeAlias = list[Any]


def as_json_dict(value: object) -> JsonDict | None:
    """Return ``value`` as a JSON object (``dict``) or None. Never raises."""
    if not isinstance(value, dict):
        return None
    return cast(JsonDict, value)


def as_mapping(value: object) -> Mapping[Any, Any] | None:
    """Return ``value`` as a mapping (dict-like) or None. Never raises."""
    if not isinstance(value, Mapping):
        return None
    return cast("Mapping[Any, Any]", value)


def as_json_list(value: object) -> JsonList | None:
    """Return ``value`` as a JSON array (``list``) or None. Never raises."""
    if not isinstance(value, list):
        return None
    return cast(JsonList, value)
