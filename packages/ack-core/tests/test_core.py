from datetime import datetime, timedelta, timezone

import pytest

from alerta_ack_core import (INTENT_V2, ZABALACK_V1, CanonicalError, FieldError, KeyUnavailable, Outcome,
                             ProofError, bounded_text, canonical_json, canonical_uuid, mac_hex, parse_utc,
                             strict_loads, utc_timestamp, verify_mac)

KEY = bytes(range(32))
PAYLOAD = {"alert_id": "6f562a40-9e65-4214-9b69-7283de2c11c0", "note": "Prüfung ✓", "n": 7, "ok": True,
           "list": ["b", "a"]}
CANONICAL = ('{"alert_id":"6f562a40-9e65-4214-9b69-7283de2c11c0","list":["b","a"],"n":7,'
             '"note":"Prüfung ✓","ok":true}').encode("utf-8")
# Regression vectors: any change to encoding, domain or MAC construction changes these.
V1_MAC = "1fffda5fce25ace41d0b626c3d0753562e672d537662bb8444c2239a3d69f555"
V2_MAC = "656e9bd600e87aba37d63c5f346ec3a416a3c6b7be8793d538055b059d2c7d4f"


def test_canonical_encoding_is_sorted_compact_utf8():
    assert canonical_json(PAYLOAD, 16384) == CANONICAL


def test_profiles_have_distinct_domains():
    assert ZABALACK_V1.domain == b"zabalack\x00v1\x00"
    assert INTENT_V2.domain == b"alerta-ack-core\x00intent\x00v2\x00"
    assert ZABALACK_V1.signing_bytes(PAYLOAD) == b"zabalack\x00v1\x00" + CANONICAL


def test_golden_macs():
    assert mac_hex(ZABALACK_V1, PAYLOAD, "k1", KEY) == V1_MAC
    assert mac_hex(INTENT_V2, PAYLOAD, "k1", KEY) == V2_MAC


def test_mac_from_one_profile_never_verifies_under_another_with_the_same_key():
    assert verify_mac(ZABALACK_V1, PAYLOAD, "k1", KEY, V1_MAC)
    assert not verify_mac(INTENT_V2, PAYLOAD, "k1", KEY, V1_MAC)
    assert verify_mac(INTENT_V2, PAYLOAD, "k1", KEY, V2_MAC)
    assert not verify_mac(ZABALACK_V1, PAYLOAD, "k1", KEY, V2_MAC)


@pytest.mark.parametrize("field,value", [("note", "Prüfung ✗"), ("n", 8), ("ok", False), ("list", ["a", "b"])])
def test_any_payload_change_breaks_the_mac(field, value):
    changed = dict(PAYLOAD, **{field: value})
    assert not verify_mac(INTENT_V2, changed, "k1", KEY, V2_MAC)


def test_wrong_key_fails():
    assert not verify_mac(INTENT_V2, PAYLOAD, "k1", bytes(32), V2_MAC)


@pytest.mark.parametrize("kid", ["", "a" * 33, "k 1", "k/1", None, 1])
def test_bad_key_id_is_rejected(kid):
    with pytest.raises(ProofError, match="key_id_invalid"):
        mac_hex(INTENT_V2, PAYLOAD, kid, KEY)


@pytest.mark.parametrize("key", [b"", bytes(31), bytes(129), "x" * 32, None])
def test_unusable_key_is_a_hold(key):
    with pytest.raises(KeyUnavailable):
        mac_hex(INTENT_V2, PAYLOAD, "k1", key)


@pytest.mark.parametrize("mac", ["", "A" * 64, "0" * 63, "0" * 65, None, b"0" * 64])
def test_malformed_mac_is_rejected(mac):
    with pytest.raises(ProofError, match="mac_invalid"):
        verify_mac(INTENT_V2, PAYLOAD, "k1", KEY, mac)


def test_oversized_payload_is_rejected():
    with pytest.raises(CanonicalError, match="oversized"):
        INTENT_V2.signing_bytes({"x": "a" * 20000})


@pytest.mark.parametrize("payload", [{"x": float("nan")}, {"x": object()}, {"x": "\ud800"}])
def test_unencodable_payload_is_rejected(payload):
    with pytest.raises(CanonicalError):
        canonical_json(payload, 16384)


def test_strict_loads_round_trips_canonical_bytes():
    assert strict_loads(CANONICAL, 16384) == PAYLOAD


@pytest.mark.parametrize("data,reason", [
    (b'{"a":1,"a":2}', "duplicate_key"),
    (b'{"a":1.0}', "float"),
    (b'{"a":NaN}', "constant"),
    (b'{"a":Infinity}', "constant"),
    (b'{"b":1,"a":2}', "not_canonical"),
    (b'{"a": 1}', "not_canonical"),
    (b'{"a":"\\u00fc"}', "not_canonical"),
    (b'{"a":"\\ud800"}', "encoding"),
    (b'\xff', "decoding"),
    (b'{"a":', "decoding"),
])
def test_strict_loads_refuses_noncanonical_and_ambiguous_input(data, reason):
    with pytest.raises(CanonicalError, match=reason):
        strict_loads(data, 16384)


def test_strict_loads_size_limit():
    with pytest.raises(CanonicalError, match="oversized"):
        strict_loads(b'{"a":"' + b"x" * 100 + b'"}', 50)


def test_uuid_must_be_canonical():
    value = "6f562a40-9e65-4214-9b69-7283de2c11c0"
    assert canonical_uuid(value) == value
    for bad in [value.upper(), "{" + value + "}", value.replace("-", ""), "", None, 1]:
        with pytest.raises(FieldError, match="invalid_uuid"):
            canonical_uuid(bad)


def test_bounded_text():
    assert bounded_text("ok") == "ok"
    assert bounded_text("é" * 64) == "é" * 64          # 128 bytes
    for bad in ["", "é" * 65, "a\nb", "a\x00", None, 1]:
        with pytest.raises(FieldError, match="invalid_string"):
            bounded_text(bad)
    assert bounded_text("x" * 256, 256)


def test_timestamps():
    moment = datetime(2026, 10, 1, 12, 0, 0, 5, tzinfo=timezone.utc)
    text = utc_timestamp(moment)
    assert text == "2026-10-01T12:00:00.000005Z"
    assert parse_utc(text) == moment
    assert parse_utc(moment.replace(tzinfo=None)) == moment            # naive = UTC
    assert parse_utc(moment.astimezone(timezone(timedelta(hours=2)))) == moment
    with pytest.raises(FieldError, match="timezone_required"):
        utc_timestamp(moment.replace(tzinfo=None))
    with pytest.raises(FieldError, match="utc_timestamp_required"):
        parse_utc("2026-10-01T12:00:00+02:00")
    with pytest.raises(FieldError, match="utc_timestamp_required"):
        parse_utc("2026-10-01T12:00:00")
    for bad in ["not a time", "2026-10-01T12:00:00Z" + " " * 30, 5, None]:
        with pytest.raises(FieldError, match="invalid_timestamp"):
            parse_utc(bad)


def test_outcomes():
    assert {o.value for o in Outcome} == {"local_ack", "queued", "remote_confirmed", "already_acked",
                                          "blocked", "superseded", "uncertain"}
    assert not Outcome.UNCERTAIN.terminal and not Outcome.QUEUED.terminal and not Outcome.LOCAL_ACK.terminal
    assert Outcome.REMOTE_CONFIRMED.terminal


def test_core_has_no_runtime_imports():
    import sys
    import alerta_ack_core  # noqa: F401
    for name in ("alerta", "flask", "psycopg", "psycopg2", "httpx", "requests", "zabalack"):
        assert name not in sys.modules


def test_verification_key_rules_per_profile():
    long_key = bytes(range(200))
    mac = __import__("hmac").new(long_key, ZABALACK_V1.signing_bytes(PAYLOAD), "sha256").hexdigest()
    # v1 keeps the legacy rule: any key of at least 32 bytes verifies, valid and tampered.
    assert verify_mac(ZABALACK_V1, PAYLOAD, "k1", long_key, mac)
    assert not verify_mac(ZABALACK_V1, PAYLOAD, "k1", long_key, "0" * 64)
    # v2 bounds verification keys to 32..128 bytes.
    with pytest.raises(KeyUnavailable, match="verification_key_unavailable"):
        verify_mac(INTENT_V2, PAYLOAD, "k1", long_key, mac)
    for profile in (ZABALACK_V1, INTENT_V2):
        with pytest.raises(KeyUnavailable, match="verification_key_unavailable"):
            verify_mac(profile, PAYLOAD, "k1", bytes(31), mac)
        with pytest.raises(KeyUnavailable, match="signing_key_unavailable"):
            mac_hex(profile, PAYLOAD, "k1", long_key)
