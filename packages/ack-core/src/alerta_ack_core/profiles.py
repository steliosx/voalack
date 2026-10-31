"""Fixed signing profiles with domain-separated HMAC-SHA256.

A profile is chosen by the trusted consumer, never by an untrusted payload. Each profile
prefixes the canonical bytes with its own domain, so a MAC made under one profile never
verifies under another, even when the same key is reused by mistake.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from .canonical import canonical_json

KID_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z")
MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 128
MAC_RE = re.compile(r"[0-9a-f]{64}\Z")


class KeyUnavailable(Exception):
    """No usable key: a hold, not evidence of forgery."""


class ProofError(ValueError):
    """A key ID or MAC is malformed. ``args[0]`` is a stable reason."""


@dataclass(frozen=True)
class Profile:
    name: str
    domain: bytes
    max_payload_bytes: int
    # Longest key accepted when verifying; None means no upper bound. Signing always
    # requires MIN_KEY_BYTES..MAX_KEY_BYTES.
    max_verify_key_bytes: int | None = MAX_KEY_BYTES

    def signing_bytes(self, payload: object) -> bytes:
        return self.domain + canonical_json(payload, self.max_payload_bytes)


# Zabalack v1: byte-identical to zabalack.crypto.canonical_bytes at 494768d. Verification
# keeps v1's legacy key rule (at least 32 bytes, no upper bound).
ZABALACK_V1 = Profile("zabalack-v1", b"zabalack\x00v1\x00", 16384, max_verify_key_bytes=None)
# Voalack signed intent v2 (design: "Signed intent v2").
INTENT_V2 = Profile("alerta-ack-core-intent-v2", b"alerta-ack-core\x00intent\x00v2\x00", 16384)


def _check_key(kid: object, key: object, maximum: int | None, reason: str) -> bytes:
    if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
        raise ProofError("key_id_invalid")
    if (not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES
            or (maximum is not None and len(key) > maximum)):
        raise KeyUnavailable(reason)
    return key


def _mac(profile: Profile, payload: object, key: bytes) -> str:
    return hmac.new(key, profile.signing_bytes(payload), hashlib.sha256).hexdigest()


def mac_hex(profile: Profile, payload: object, kid: str, key: bytes) -> str:
    """Sign: lowercase hex HMAC-SHA256 of ``payload`` under ``profile``. Keys must be 32..128 bytes."""
    return _mac(profile, payload, _check_key(kid, key, MAX_KEY_BYTES, "signing_key_unavailable"))


def verify_mac(profile: Profile, payload: object, kid: str, key: bytes, mac: object) -> bool:
    """Constant-time check of ``mac`` against ``payload`` under ``profile``'s verification key rule."""
    if not isinstance(mac, str) or not MAC_RE.fullmatch(mac):
        raise ProofError("mac_invalid")
    key = _check_key(kid, key, profile.max_verify_key_bytes, "verification_key_unavailable")
    return hmac.compare_digest(_mac(profile, payload, key), mac)
