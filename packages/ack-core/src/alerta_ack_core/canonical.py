"""Canonical JSON encoding and strict decoding for signed intents.

Encoding matches Zabalack v1 byte for byte: sorted keys, compact separators,
UTF-8 without ASCII escaping, and no NaN or infinity.
"""
from __future__ import annotations

import json
from typing import Any


class CanonicalError(ValueError):
    """A payload cannot be encoded or decoded canonically. ``args[0]`` is a stable reason."""


def canonical_json(payload: Any, max_bytes: int) -> bytes:
    try:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (UnicodeError, ValueError, TypeError):
        raise CanonicalError("encoding") from None
    if len(data) > max_bytes:
        raise CanonicalError("oversized")
    return data


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError("duplicate_key")
        result[key] = value
    return result


def _reject_float(text: str) -> Any:
    raise CanonicalError("float")


def _reject_constant(text: str) -> Any:
    raise CanonicalError("constant")


def strict_loads(data: bytes, max_bytes: int) -> Any:
    """Decode JSON, refusing duplicate keys, floats, NaN/Infinity, invalid UTF-8 and lone surrogates.

    The decoded value round-trips through :func:`canonical_json`, so a signed payload has one
    accepted spelling only.
    """
    if not isinstance(data, bytes) or len(data) > max_bytes:
        raise CanonicalError("oversized")
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicates,
                           parse_float=_reject_float, parse_constant=_reject_constant)
    except CanonicalError:
        raise
    except (UnicodeDecodeError, ValueError):
        raise CanonicalError("decoding") from None
    if canonical_json(value, max_bytes) != data:
        raise CanonicalError("not_canonical")
    return value
