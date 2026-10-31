"""Signed intent v2 for Voalack: the exact envelope, its ONE comment, and MAC sign/verify.

Pure functions (design "Signed intent v2" and "Projection, ONE-visible attribution"). They
build and check bytes only; where each value comes from, and when it is signed inside the ACK
transaction, belongs to the capture boundary. The trusted caller always supplies the expected
deployment, provider and purpose; a payload never selects its own key or validator.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Mapping

from alerta_ack_core import (INTENT_V2, CanonicalError, FieldError, KeyUnavailable, ProofError, canonical_json,
                             canonical_uuid, mac_hex, parse_utc, strict_loads, utc_timestamp, verify_mac)
from alerta_ack_core.profiles import KID_RE

VERSION = 2
PURPOSE = "human_ack_intent"
ALGORITHM = "HMAC-SHA256"
PROVIDER = "veeam_one"
ACTION = "ack"
TARGET_KIND = "triggered_alarm"   # the supported cohort: a single triggered alarm (no grouped/child)
MAX_CAPTURE_WINDOW = timedelta(seconds=60)
MAX_EXECUTION_WINDOW = timedelta(hours=4)
MESSAGE_LIMIT_UTF16 = 1024
MAX_NOTE_BYTES = 8 * 1024
LOGICAL_ID_BYTES = 128
LOGIN_BYTES = 256

ENVELOPE_KEYS = frozenset({
    "version", "purpose", "algorithm", "kid",
    "deployment_id", "provider", "customer", "source_namespace", "instance_id",
    "alert_id", "action_id", "request_id",
    "generation", "binding_id", "binding_revision",
    "source", "actor", "route", "action",
    "message", "message_policy_revision",
    "issued_at", "capture_expires_at", "execution_expires_at",
})
SOURCE_KEYS = frozenset({"target_kind", "target_id", "occurrence_ref", "occurrence_evidence_sha256",
                         "snapshot_sha256"})
ACTOR_KEYS = frozenset({"user_id", "login", "auth_type", "authorization_policy_revision",
                        "authorized_customer"})

SNAPSHOT_PROJECTION = "alerta-9.1.0/stable-identity/v1"
SNAPSHOT_FIELDS = ("id", "customer", "resource", "event", "environment", "origin")

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_TARGET_ID_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
_PROVIDER_RE = re.compile(r"[a-z0-9_.-]{1,32}\Z")
_MAX_INT = 2 ** 63 - 1


class EnvelopeError(ValueError):
    """An envelope, message or snapshot is not acceptable. ``args[0]`` is a stable reason."""


def _fail(reason: str):
    raise EnvelopeError(reason)


def _utf16_units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _has_lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def _is_control(c: str) -> bool:
    code = ord(c)
    return code < 0x20 or 0x7F <= code <= 0x9F or c in "  "


def _text(value: object, limit: int, reason: str) -> str:
    """1..limit UTF-8 bytes, no controls, no lone surrogates, no surrounding whitespace."""
    if (not isinstance(value, str) or _has_lone_surrogate(value)
            or not 1 <= len(value.encode("utf-8")) <= limit
            or any(_is_control(c) for c in value) or value != value.strip()):
        _fail(reason)
    return value


def _positive_int(value: object, reason: str) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_INT:
        _fail(reason)
    return value


def _sha256(value: object, reason: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        _fail(reason)
    return value


def _uuid(value: object, reason: str) -> str:
    try:
        return canonical_uuid(value)
    except FieldError:
        _fail(reason)


def _timestamp(value: object, reason: str):
    try:
        parsed = parse_utc(value)
    except FieldError:
        _fail(reason)
    if not isinstance(value, str) or utc_timestamp(parsed) != value:
        _fail(reason)              # one accepted spelling: microseconds and a Z suffix
    return parsed


def _exact_keys(value: object, keys: frozenset, reason: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(reason)
    return value


@dataclass(frozen=True)
class Context:
    """What the trusted consumer expects; never read from the payload."""
    deployment_id: str
    allowed_auth_providers: frozenset = field(default_factory=frozenset)
    provider: str = PROVIDER
    purpose: str = PURPOSE


class KeyRing:
    """Signing keys addressed by (deployment_id, provider, purpose, kid), plus the active kid.

    Key bytes are never included in errors, representations or envelopes.
    """

    def __init__(self, keys: Mapping[tuple, bytes], active: Mapping[tuple, str]):
        self._keys = dict(keys)
        self._active = dict(active)

    def __repr__(self) -> str:
        return f"KeyRing({len(self._keys)} keys)"

    def active_kid(self, ctx: Context) -> str:
        kid = self._active.get((ctx.deployment_id, ctx.provider, ctx.purpose))
        if kid is None:
            raise KeyUnavailable("no_active_key")
        return kid

    def key(self, ctx: Context, kid: str) -> bytes:
        key = self._keys.get((ctx.deployment_id, ctx.provider, ctx.purpose, kid))
        if key is None:
            raise KeyUnavailable("key_unavailable")
        return key


def auth_type(branch: str, provider: str | None, ctx: Context) -> str:
    """``basic`` for the Basic branch; ``bearer:<provider>`` for a verified, allowed JWT provider."""
    if branch == "basic" and provider is None:
        return "basic"
    if branch == "bearer" and isinstance(provider, str) and _PROVIDER_RE.fullmatch(provider) \
            and provider in ctx.allowed_auth_providers:
        return f"bearer:{provider}"
    _fail("auth_type_unsupported")


def _check_auth_type(value: object, ctx: Context) -> str:
    if value == "basic":
        return value
    if isinstance(value, str) and value.startswith("bearer:"):
        provider = value[len("bearer:"):]
        if _PROVIDER_RE.fullmatch(provider) and provider in ctx.allowed_auth_providers:
            return value
    _fail("auth_type_unsupported")


def route(alert_id: str) -> str:
    return f"PUT /alert/{alert_id}/action"


def _message_prefix(action_id: str, login: str, issued_at: str, alert_id: str) -> str:
    return (f"[AlertaAck:{action_id}] via Voalack; Alerta user={login}; "
            f"Alerta ACK requested={issued_at}; alert={alert_id}; note=")


def normalize_note(note: object) -> str:
    """Single-line note: controls become spaces, runs of spaces collapse, ends are trimmed."""
    if note is None:
        return ""
    if not isinstance(note, str) or _has_lone_surrogate(note):
        _fail("note_invalid")
    if len(note.encode("utf-8")) > MAX_NOTE_BYTES:
        _fail("note_oversized")
    spaced = "".join(" " if _is_control(c) else c for c in note)
    return " ".join(spaced.split())


def build_message(action_id: str, login: str, issued_at: str, alert_id: str, note: object,
                  limit: int = MESSAGE_LIMIT_UTF16) -> str:
    """The final single-line ONE comment, at most ``limit`` UTF-16 code units.

    The operator note is truncated first, on code point boundaries; if the attribution alone
    does not fit, the message is refused rather than truncated.
    """
    prefix = _message_prefix(_uuid(action_id, "action_id_invalid"), _text(login, LOGIN_BYTES, "login_invalid"),
                             issued_at, _uuid(alert_id, "alert_id_invalid"))
    _timestamp(issued_at, "issued_at_invalid")
    room = limit - _utf16_units(prefix)
    if room < 0:
        _fail("attribution_overflow")
    text = normalize_note(note)
    kept, used = [], 0
    for c in text:
        units = 2 if ord(c) > 0xFFFF else 1
        if used + units > room:
            break
        kept.append(c)
        used += units
    return prefix + "".join(kept).rstrip()


def snapshot_digest(alert: Mapping[str, Any]) -> str:
    """SHA-256 of the named stable comparison projection of an alert (no coercion, no defaults)."""
    values = {}
    for name in SNAPSHOT_FIELDS:
        value = alert.get(name) if isinstance(alert, Mapping) else None
        if name == "id":
            values[name] = _uuid(value, "snapshot_field_invalid")
        else:
            values[name] = _text(value, LOGICAL_ID_BYTES if name == "customer" else 1024,
                                 "snapshot_field_invalid")
    data = canonical_json({"projection": SNAPSHOT_PROJECTION, "fields": values}, 16384)
    return hashlib.sha256(data).hexdigest()


def validate_envelope(envelope: object, ctx: Context) -> Mapping[str, Any]:
    """Strict shape, type, bound and consistency checks; used before signing and when verifying."""
    env = _exact_keys(envelope, ENVELOPE_KEYS, "envelope_keys")
    if type(env["version"]) is not int or env["version"] != VERSION:
        _fail("version_invalid")
    if env["purpose"] != ctx.purpose or env["purpose"] != PURPOSE:
        _fail("purpose_invalid")
    if env["algorithm"] != ALGORITHM:
        _fail("algorithm_invalid")
    if not isinstance(env["kid"], str) or not KID_RE.fullmatch(env["kid"]):
        _fail("kid_invalid")
    if env["deployment_id"] != ctx.deployment_id:
        _fail("deployment_mismatch")
    if env["provider"] != ctx.provider or env["provider"] != PROVIDER:
        _fail("provider_mismatch")
    for name in ("deployment_id", "customer", "source_namespace", "instance_id", "binding_id"):
        _text(env[name], LOGICAL_ID_BYTES, f"{name}_invalid")
    alert_id = _uuid(env["alert_id"], "alert_id_invalid")
    action_id = _uuid(env["action_id"], "action_id_invalid")
    _uuid(env["request_id"], "request_id_invalid")
    _positive_int(env["generation"], "generation_invalid")
    _positive_int(env["binding_revision"], "binding_revision_invalid")
    _positive_int(env["message_policy_revision"], "message_policy_revision_invalid")

    source = _exact_keys(env["source"], SOURCE_KEYS, "source_keys")
    if source["target_kind"] != TARGET_KIND:
        _fail("target_kind_invalid")
    if (not isinstance(source["target_id"], str) or not _TARGET_ID_RE.fullmatch(source["target_id"])
            or int(source["target_id"]) > _MAX_INT):        # ONE triggered-alarm IDs are signed 64-bit
        _fail("target_id_invalid")
    _text(source["occurrence_ref"], LOGICAL_ID_BYTES, "occurrence_ref_invalid")
    _sha256(source["occurrence_evidence_sha256"], "occurrence_evidence_invalid")
    _sha256(source["snapshot_sha256"], "snapshot_invalid")

    actor = _exact_keys(env["actor"], ACTOR_KEYS, "actor_keys")
    _text(actor["user_id"], LOGICAL_ID_BYTES, "user_id_invalid")   # a logical ID; only login has 256
    login = _text(actor["login"], LOGIN_BYTES, "login_invalid")
    _check_auth_type(actor["auth_type"], ctx)
    _positive_int(actor["authorization_policy_revision"], "policy_revision_invalid")
    if actor["authorized_customer"] != env["customer"]:
        _fail("authorized_customer_mismatch")

    if env["route"] != route(alert_id):
        _fail("route_invalid")
    if env["action"] != ACTION:
        _fail("action_invalid")

    issued = _timestamp(env["issued_at"], "issued_at_invalid")
    capture = _timestamp(env["capture_expires_at"], "capture_expires_at_invalid")
    execution = _timestamp(env["execution_expires_at"], "execution_expires_at_invalid")
    # Differences, not sums: a sum near the datetime maximum would overflow.
    if not (issued < capture and capture - issued <= MAX_CAPTURE_WINDOW):
        _fail("capture_window_invalid")
    if not (capture <= execution and execution - issued <= MAX_EXECUTION_WINDOW):
        _fail("execution_window_invalid")

    message = env["message"]
    prefix = _message_prefix(action_id, login, env["issued_at"], alert_id)
    if (not isinstance(message, str) or _has_lone_surrogate(message)
            or _utf16_units(message) > MESSAGE_LIMIT_UTF16 or any(_is_control(c) for c in message)
            or not message.startswith(prefix)):
        _fail("message_invalid")
    note = message[len(prefix):]
    if normalize_note(note) != note:      # exactly the form build_message produces
        _fail("message_invalid")
    try:
        canonical_json(env, INTENT_V2.max_payload_bytes)
    except CanonicalError as exc:
        _fail(f"envelope_{exc.args[0]}")
    return env


def build_envelope(*, ctx: Context, kid: str, customer: str, source_namespace: str, instance_id: str,
                   alert_id: str, action_id: str, request_id: str, generation: int, binding_id: str,
                   binding_revision: int, source: Mapping[str, Any], actor: Mapping[str, Any], note: object,
                   message_policy_revision: int, issued_at: str, capture_expires_at: str,
                   execution_expires_at: str) -> dict:
    """Assemble the complete envelope; the message is built here, before signing."""
    envelope = {
        "version": VERSION, "purpose": ctx.purpose, "algorithm": ALGORITHM, "kid": kid,
        "deployment_id": ctx.deployment_id, "provider": ctx.provider, "customer": customer,
        "source_namespace": source_namespace, "instance_id": instance_id,
        "alert_id": alert_id, "action_id": action_id, "request_id": request_id,
        "generation": generation, "binding_id": binding_id, "binding_revision": binding_revision,
        "source": dict(source), "actor": dict(actor),
        "route": route(alert_id), "action": ACTION,
        "message": build_message(action_id, actor.get("login"), issued_at, alert_id, note),
        "message_policy_revision": message_policy_revision,
        "issued_at": issued_at, "capture_expires_at": capture_expires_at,
        "execution_expires_at": execution_expires_at,
    }
    validate_envelope(envelope, ctx)
    return envelope


@dataclass(frozen=True)
class Signed:
    canonical: bytes
    sha256: str
    kid: str
    mac: str


def sign(envelope: Mapping[str, Any], ctx: Context, keys: KeyRing) -> Signed:
    env = validate_envelope(envelope, ctx)
    if env["kid"] != keys.active_kid(ctx):
        _fail("kid_not_active")
    canonical = canonical_json(env, INTENT_V2.max_payload_bytes)
    mac = mac_hex(INTENT_V2, env, env["kid"], keys.key(ctx, env["kid"]))
    return Signed(canonical, hashlib.sha256(canonical).hexdigest(), env["kid"], mac)


def verify(canonical: bytes, mac: object, ctx: Context, keys: KeyRing) -> Mapping[str, Any]:
    """Return the envelope only if the exact bytes are canonical, valid for ``ctx`` and authentic.

    Raises EnvelopeError for malformed input, KeyUnavailable when no key exists for the expected
    context and kid (a hold, not a forgery verdict), and ProofError for a malformed MAC.
    """
    try:
        envelope = strict_loads(canonical, INTENT_V2.max_payload_bytes)
    except CanonicalError as exc:
        _fail(f"bytes_{exc.args[0]}")
    env = validate_envelope(envelope, ctx)
    key = keys.key(ctx, env["kid"])
    if not verify_mac(INTENT_V2, env, env["kid"], key, mac):
        _fail("mac_mismatch")
    return env


__all__ = ["ACTION", "ALGORITHM", "Context", "ENVELOPE_KEYS", "EnvelopeError", "KeyRing", "KeyUnavailable",
           "PROVIDER", "PURPOSE", "ProofError", "SNAPSHOT_FIELDS", "SNAPSHOT_PROJECTION", "Signed", "TARGET_KIND", "VERSION",
           "auth_type", "build_envelope", "build_message", "normalize_note", "route", "sign",
           "snapshot_digest", "validate_envelope", "verify"]
