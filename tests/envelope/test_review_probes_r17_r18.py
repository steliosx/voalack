"""Independent assessment of PR9 review comments 4165463607 and 4165463610.

Synthetic fixtures; run only inside smolvm against the exact reviewed wheels.
"""
import pytest
from alerta_ack_core import INTENT_V2, canonical_json, mac_hex
from test_envelope import CTX, KEY, KEYS, envelope
from voalack import envelope as v2


def require_rejection(env, operation, reason):
    with pytest.raises(v2.EnvelopeError, match=reason):
        if operation == "sign":
            v2.sign(env, CTX, KEYS)
        else:
            data = canonical_json(env, 16384)
            mac = mac_hex(INTENT_V2, env, "lab-k1", KEY)
            v2.verify(data, mac, CTX, KEYS)


@pytest.mark.parametrize("operation", ["sign", "verify"])
@pytest.mark.parametrize("user_id", ["u" * 129, "\u00e9" * 65], ids=["129-ascii-bytes", "130-utf8-bytes"])
def test_actor_logical_id_over_128_bytes_is_refused(operation, user_id):
    env = envelope()
    env["actor"]["user_id"] = user_id
    require_rejection(env, operation, "user_id_invalid")


@pytest.mark.parametrize("user_id", ["u" * 128, "\u00e9" * 64], ids=["128-ascii-bytes", "128-utf8-bytes"])
def test_actor_id_boundary_and_distinct_256_byte_login_round_trip(user_id):
    env = envelope()
    env["actor"]["user_id"] = user_id
    env["actor"]["login"] = "l" * 256
    env["message"] = v2.build_message(env["action_id"], env["actor"]["login"],
                                     env["issued_at"], env["alert_id"], "synthetic ack")
    signed = v2.sign(env, CTX, KEYS)
    assert v2.verify(signed.canonical, signed.mac, CTX, KEYS) == env


@pytest.mark.parametrize("operation", ["sign", "verify"])
@pytest.mark.parametrize("suffix", ["a  b", "a b ", " a b", "a\u00a0b"],
                         ids=["repeated-space", "trailing-space", "leading-space", "nonbreaking-space"])
def test_noncanonical_note_suffix_is_refused_without_rewriting(operation, suffix):
    env = envelope()
    prefix = env["message"].split("note=", 1)[0] + "note="
    env["message"] = prefix + suffix
    require_rejection(env, operation, "message_invalid")
