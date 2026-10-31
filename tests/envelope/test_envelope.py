"""M1: signed intent v2 envelope, message and MAC (pure functions; synthetic fixtures only)."""
import copy
import hashlib
import hmac
import json
import uuid

import pytest
from alerta_ack_core import ZABALACK_V1, KeyUnavailable, ProofError, canonical_json, mac_hex

from voalack import envelope as v2

KEY = b"k" * 32                       # synthetic test key, never a real secret
OTHER_KEY = b"o" * 32
CTX = v2.Context(deployment_id="lab-deployment", allowed_auth_providers=frozenset({"basic", "openid"}))
KEYS = v2.KeyRing({("lab-deployment", "veeam_one", "human_ack_intent", "lab-k1"): KEY},
                  {("lab-deployment", "veeam_one", "human_ack_intent"): "lab-k1"})
ALERT = "2f4b7f2e-8a0c-4d63-9d6c-2f1a5b8e9c01"
ACTION = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
REQUEST = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
ISSUED = "2026-10-02T11:00:00.000000Z"


def fields(**overrides):
    base = dict(
        ctx=CTX, kid="lab-k1", customer="lab-customer", source_namespace="lab-feed", instance_id="lab-one",
        alert_id=ALERT, action_id=ACTION, request_id=REQUEST, generation=1, binding_id="lab-binding",
        binding_revision=3,
        source={"target_kind": "triggered_alarm", "target_id": "4711", "occurrence_ref": "lab-occurrence-1",
                "occurrence_evidence_sha256": "a" * 64, "snapshot_sha256": "b" * 64},
        actor={"user_id": "lab-user-1", "login": "operator@example.test", "auth_type": "basic",
               "authorization_policy_revision": 2, "authorized_customer": "lab-customer"},
        note="synthetic ack", message_policy_revision=1, issued_at=ISSUED,
        capture_expires_at="2026-10-02T11:01:00.000000Z", execution_expires_at="2026-10-02T15:00:00.000000Z")
    base.update(overrides)
    return base


def envelope(**overrides):
    return v2.build_envelope(**fields(**overrides))


def test_round_trip_and_independent_mac():
    env = envelope()
    signed = v2.sign(env, CTX, KEYS)
    assert signed.canonical == json.dumps(env, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False).encode("utf-8")
    expected = hmac.new(KEY, b"alerta-ack-core\x00intent\x00v2\x00" + signed.canonical, hashlib.sha256).hexdigest()
    assert signed.mac == expected and signed.sha256 == hashlib.sha256(signed.canonical).hexdigest()
    assert v2.verify(signed.canonical, signed.mac, CTX, KEYS) == env
    assert set(env) == v2.ENVELOPE_KEYS and len(env) == 24
    assert env["message"] == (f"[AlertaAck:{ACTION}] via Voalack; Alerta user=operator@example.test; "
                              f"Alerta ACK requested={ISSUED}; alert={ALERT}; note=synthetic ack")


def _mutations():
    yield "customer", lambda e: e.update(customer="other-customer", actor={**e["actor"], "authorized_customer": "other-customer"})
    for name, value in (("kid", "lab-k1"), ("source_namespace", "other-feed"), ("instance_id", "other-one"),
                        ("alert_id", str(uuid.uuid4())), ("action_id", str(uuid.uuid4())),
                        ("request_id", str(uuid.uuid4())), ("generation", 2), ("binding_id", "other-binding"),
                        ("binding_revision", 4), ("message_policy_revision", 2),
                        ("execution_expires_at", "2026-10-02T14:00:00.000000Z")):
        if name != "kid":
            yield name, (lambda n, val: lambda e: e.update({n: val}))(name, value)
    for key, value in (("target_id", "4712"), ("occurrence_ref", "lab-occurrence-2"),
                       ("occurrence_evidence_sha256", "c" * 64), ("snapshot_sha256", "d" * 64),
                       ("target_kind", "other_kind")):
        yield f"source.{key}", (lambda k, val: lambda e: e["source"].update({k: val}))(key, value)
    for key, value in (("user_id", "lab-user-2"), ("auth_type", "bearer:openid"),
                       ("authorization_policy_revision", 3)):
        yield f"actor.{key}", (lambda k, val: lambda e: e["actor"].update({k: val}))(key, value)
    yield "message", lambda e: e.update(message=e["message"] + "!")


@pytest.mark.parametrize("name,mutate", list(_mutations()), ids=[n for n, _ in _mutations()])
def test_every_signed_field_is_covered(name, mutate):
    env = envelope()
    signed = v2.sign(env, CTX, KEYS)
    changed = copy.deepcopy(env)
    mutate(changed)
    if name in ("alert_id", "action_id"):        # the route/message must follow, or validation rejects first
        changed["route"] = v2.route(changed["alert_id"])
        changed["message"] = v2.build_message(changed["action_id"], changed["actor"]["login"], ISSUED,
                                              changed["alert_id"], "synthetic ack")
    data = canonical_json(changed, 16384)
    # Amended (review R16): only triggered_alarm is a valid kind, so the schema rejects
    # the changed kind before the MAC is checked. Was: mac_mismatch for every case.
    reason = "target_kind_invalid" if name == "source.target_kind" else "mac_mismatch"
    with pytest.raises(v2.EnvelopeError, match=reason):
        v2.verify(data, signed.mac, CTX, KEYS)


@pytest.mark.parametrize("change", ["extra", "missing", "extra_source", "extra_actor"])
def test_exact_key_sets(change):
    env = envelope()
    if change == "extra":
        env["extension"] = {}
    elif change == "missing":
        del env["request_id"]
    elif change == "extra_source":
        env["source"]["url"] = "https://example.test"
    else:
        env["actor"]["customers"] = ["lab-customer"]
    with pytest.raises(v2.EnvelopeError):
        v2.validate_envelope(env, CTX)


def test_only_canonical_bytes_verify():
    signed = v2.sign(envelope(), CTX, KEYS)
    spaced = json.dumps(json.loads(signed.canonical), sort_keys=True).encode()
    duplicate = signed.canonical[:-1] + b',"version":2}'
    floated = signed.canonical.replace(b'"generation":1', b'"generation":1.0')
    for data, reason in ((spaced, "bytes_not_canonical"), (duplicate, "bytes_duplicate_key"),
                         (floated, "bytes_float")):
        with pytest.raises(v2.EnvelopeError, match=reason):
            v2.verify(data, signed.mac, CTX, KEYS)


@pytest.mark.parametrize("name,value,reason", [
    ("generation", True, "generation_invalid"), ("generation", 0, "generation_invalid"),
    ("binding_revision", "3", "binding_revision_invalid"), ("version", True, "version_invalid"),
    ("alert_id", ALERT.upper(), "alert_id_invalid"), ("request_id", "not-a-uuid", "request_id_invalid"),
    ("customer", " lab-customer", "customer_invalid"), ("deployment_id", "other", "deployment_mismatch"),
    ("provider", "zabbix", "provider_mismatch"), ("purpose", "other", "purpose_invalid"),
    ("route", "PUT /alert/x/action", "route_invalid"), ("action", "close", "action_invalid"),
    ("issued_at", "2026-10-02T11:00:00Z", "issued_at_invalid"),
])
def test_field_rules(name, value, reason):
    env = envelope()
    env[name] = value
    with pytest.raises(v2.EnvelopeError, match=reason):
        v2.validate_envelope(env, CTX)


@pytest.mark.parametrize("key,value,reason", [
    ("target_id", "04711", "target_id_invalid"), ("target_id", 4711, "target_id_invalid"),
    ("target_id", str(2 ** 63), "target_id_invalid"), ("target_id", "9" * 19, "target_id_invalid"),
    ("snapshot_sha256", "B" * 64, "snapshot_invalid"), ("occurrence_ref", "x\ny", "occurrence_ref_invalid"),
])
def test_source_rules(key, value, reason):
    env = envelope()
    env["source"][key] = value
    with pytest.raises(v2.EnvelopeError, match=reason):
        v2.validate_envelope(env, CTX)


@pytest.mark.parametrize("key,value,reason", [
    ("auth_type", "bearer", "auth_type_unsupported"), ("auth_type", "bearer:saml", "auth_type_unsupported"),
    ("auth_type", "apikey", "auth_type_unsupported"), ("authorized_customer", "other", "authorized_customer_mismatch"),
    ("login", "a" * 257, "login_invalid"),
])
def test_actor_rules(key, value, reason):
    env = envelope()
    env["actor"][key] = value
    with pytest.raises(v2.EnvelopeError, match=reason):
        v2.validate_envelope(env, CTX)


def test_target_id_upper_bound_is_accepted():
    env = envelope()
    env["source"]["target_id"] = str(2 ** 63 - 1)
    v2.validate_envelope(env, CTX)


def test_auth_type_labels():
    assert v2.auth_type("basic", None, CTX) == "basic"
    assert v2.auth_type("bearer", "openid", CTX) == "bearer:openid"
    for branch, provider in (("bearer", None), ("bearer", "saml"), ("key", None), ("basic", "openid")):
        with pytest.raises(v2.EnvelopeError, match="auth_type_unsupported"):
            v2.auth_type(branch, provider, CTX)


@pytest.mark.parametrize("capture,execution,reason", [
    ("2026-10-02T11:01:00.000001Z", "2026-10-02T15:00:00.000000Z", "capture_window_invalid"),
    ("2026-10-02T11:00:00.000000Z", "2026-10-02T15:00:00.000000Z", "capture_window_invalid"),
    ("2026-10-02T11:01:00.000000Z", "2026-10-02T15:00:00.000001Z", "execution_window_invalid"),
    ("2026-10-02T11:01:00.000000Z", "2026-10-02T11:00:30.000000Z", "execution_window_invalid"),
])
def test_lifetime_windows(capture, execution, reason):
    env = envelope()
    env["capture_expires_at"], env["execution_expires_at"] = capture, execution
    with pytest.raises(v2.EnvelopeError, match=reason):
        v2.validate_envelope(env, CTX)


def test_expected_context_selects_the_key():
    signed = v2.sign(envelope(), CTX, KEYS)
    other_deployment = v2.Context(deployment_id="other", allowed_auth_providers=CTX.allowed_auth_providers)
    with pytest.raises(v2.EnvelopeError, match="deployment_mismatch"):
        v2.verify(signed.canonical, signed.mac, other_deployment, KEYS)
    unknown_kid = json.loads(signed.canonical)
    unknown_kid["kid"] = "lab-k2"
    with pytest.raises(KeyUnavailable):
        v2.verify(canonical_json(unknown_kid, 16384), signed.mac, CTX, KEYS)
    with pytest.raises(ProofError):
        v2.verify(signed.canonical, "not-hex", CTX, KEYS)


def test_signing_needs_the_active_kid():
    env = envelope(kid="lab-k2")
    with pytest.raises(v2.EnvelopeError, match="kid_not_active"):
        v2.sign(env, CTX, KEYS)
    empty = v2.KeyRing({}, {})
    with pytest.raises(KeyUnavailable):
        v2.sign(envelope(), CTX, empty)
    assert "k" * 32 not in repr(KEYS)


def test_v1_and_cross_provider_macs_do_not_verify():
    env = envelope()
    signed = v2.sign(env, CTX, KEYS)
    v1_mac = mac_hex(ZABALACK_V1, env, "lab-k1", KEY)            # same key, same payload, v1 domain
    assert v1_mac != signed.mac
    with pytest.raises(v2.EnvelopeError, match="mac_mismatch"):
        v2.verify(signed.canonical, v1_mac, CTX, KEYS)
    zabbix_ctx = v2.Context(deployment_id="lab-deployment", allowed_auth_providers=CTX.allowed_auth_providers,
                            provider="zabbix")
    with pytest.raises(v2.EnvelopeError, match="provider_mismatch"):
        v2.verify(signed.canonical, signed.mac, zabbix_ctx, KEYS)


def test_message_is_bounded_in_utf16_units():
    emoji = "\U0001F600"                                         # two UTF-16 units
    message = v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, emoji * 2000)
    assert len(message.encode("utf-16-le")) // 2 <= 1024
    assert not any(0xD800 <= ord(c) <= 0xDFFF for c in message)  # never split a surrogate pair
    prefix = v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, "")
    room = 1024 - len(prefix.encode("utf-16-le")) // 2
    exact = v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, "x" * room)
    assert len(exact.encode("utf-16-le")) // 2 == 1024 and exact.endswith("x" * room)
    over = v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, "x" * (room + 1))
    assert over == exact


def test_message_normalises_the_note_and_refuses_bad_input():
    message = v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, "line one\r\nline\ttwo \x00 end")
    assert message.endswith("note=line one line two end")
    with pytest.raises(v2.EnvelopeError, match="attribution_overflow"):
        v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, "x", limit=50)
    with pytest.raises(v2.EnvelopeError, match="note_oversized"):
        v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, "x" * (8 * 1024 + 1))
    with pytest.raises(v2.EnvelopeError, match="note_invalid"):
        v2.build_message(ACTION, "operator@example.test", ISSUED, ALERT, "bad \ud800 surrogate")
    with pytest.raises(v2.EnvelopeError, match="login_invalid"):
        v2.build_message(ACTION, "operator\n@example.test", ISSUED, ALERT, "x")


@pytest.mark.parametrize("suffix", ["a  b", "a b ", " a", "a\u00a0b"])
def test_message_note_must_be_normalized(suffix):
    env = envelope()
    env["message"] = env["message"][:-len("synthetic ack")] + suffix
    with pytest.raises(v2.EnvelopeError, match="message_invalid"):
        v2.validate_envelope(env, CTX)


def test_actor_user_id_is_a_logical_id():
    env = envelope()
    env["actor"]["user_id"] = "u" * 129
    with pytest.raises(v2.EnvelopeError, match="user_id_invalid"):
        v2.validate_envelope(env, CTX)
    env["actor"]["user_id"] = "u" * 128
    v2.validate_envelope(env, CTX)


def test_message_must_carry_the_signed_attribution():
    env = envelope()
    env["message"] = env["message"].replace("operator@example.test", "someone@example.test")
    with pytest.raises(v2.EnvelopeError, match="message_invalid"):
        v2.validate_envelope(env, CTX)


def test_snapshot_digest_is_a_named_projection():
    alert = {"id": ALERT, "customer": "lab-customer", "resource": "lab-vm", "event": "VeeamOneAlarm",
             "environment": "Production", "origin": "veeam-one", "severity": "major", "value": "x",
             "attributes": {"captureId": "1"}}
    digest = v2.snapshot_digest(alert)
    expected = hashlib.sha256(canonical_json({"projection": "alerta-9.1.0/stable-identity/v1", "fields": {
        k: alert[k] for k in ("id", "customer", "resource", "event", "environment", "origin")}}, 16384)).hexdigest()
    assert digest == expected
    assert v2.snapshot_digest({**alert, "severity": "minor", "attributes": {}}) == digest
    for broken in ({**alert, "customer": None}, {k: v for k, v in alert.items() if k != "origin"},
                   {**alert, "id": ALERT.upper()}, {**alert, "resource": 7}):
        with pytest.raises(v2.EnvelopeError, match="snapshot_field_invalid"):
            v2.snapshot_digest(broken)
