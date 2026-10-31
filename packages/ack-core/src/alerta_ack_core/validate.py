"""Strict field validators shared by intent consumers.

Behaviour matches the corresponding helpers in zabalack.crypto at 494768d.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone


class FieldError(ValueError):
    """A field fails validation. ``args[0]`` is a stable reason."""


def canonical_uuid(value: object) -> str:
    """Accept only the canonical lowercase hyphenated form."""
    if not isinstance(value, str):
        raise FieldError("invalid_uuid")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise FieldError("invalid_uuid") from None
    return value


def bounded_text(value: object, limit: int = 128) -> str:
    """1..limit UTF-8 bytes, no C0 control characters."""
    if (not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= limit
            or any(ord(c) < 32 for c in value)):
        raise FieldError("invalid_string")
    return value


def utc_timestamp(value: datetime) -> str:
    """ISO 8601, microsecond precision, ``Z`` suffix."""
    if value.tzinfo is None:
        raise FieldError("timezone_required")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_utc(value: object) -> datetime:
    """Parse a UTC timestamp. A naive ``datetime`` is taken as UTC (PostgreSQL ``timestamp``)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if not isinstance(value, str) or len(value) > 40:
        raise FieldError("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise FieldError("invalid_timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise FieldError("utc_timestamp_required")
    return parsed.astimezone(timezone.utc)
