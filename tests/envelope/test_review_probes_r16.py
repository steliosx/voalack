"""Independent M1 schema witnesses; synthetic data only, run in smolvm."""
import copy

import pytest
from alerta_ack_core import INTENT_V2, canonical_json, mac_hex
from test_envelope import CTX, KEY, KEYS, envelope
from voalack import envelope as v2


@pytest.mark.parametrize("kind", ["grouped_alarm", "child_alarm"])
def test_one_builder_refuses_unsupported_target_kind(kind):
    original = envelope()
    source = {**original["source"], "target_kind": kind}
    from test_envelope import fields
    with pytest.raises(v2.EnvelopeError, match="target_kind_invalid"):
        v2.build_envelope(**fields(source=source))


@pytest.mark.parametrize("kind", ["grouped_alarm", "child_alarm"])
def test_one_verifier_refuses_authenticated_unsupported_target_kind(kind):
    changed = copy.deepcopy(envelope())
    changed["source"]["target_kind"] = kind
    canonical = canonical_json(changed, 16384)
    mac = mac_hex(INTENT_V2, changed, "lab-k1", KEY)
    with pytest.raises(v2.EnvelopeError, match="target_kind_invalid"):
        v2.verify(canonical, mac, CTX, KEYS)


def test_valid_short_lifetime_near_datetime_limit_does_not_overflow():
    from test_envelope import fields
    env = v2.build_envelope(**fields(
        issued_at="9999-12-31T23:59:00.000000Z",
        capture_expires_at="9999-12-31T23:59:30.000000Z",
        execution_expires_at="9999-12-31T23:59:45.000000Z"))
    signed = v2.sign(env, CTX, KEYS)
    assert v2.verify(signed.canonical, signed.mac, CTX, KEYS) == env
