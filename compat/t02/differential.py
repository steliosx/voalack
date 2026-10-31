"""Differential check: original Zabalack crypto (494768d) vs. the core-backed compatibility patch.

Runs in the VM with the patched `zabalack` installed and the original crypto loaded as
package `zabalack_orig` (a copy of the same source tree with the original crypto.py).
"""
import os
import random
import secrets
import string
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import zabalack.crypto as new
import zabalack_orig.crypto as old

if os.environ.get("VOALACK_DIFF_FAULT") == "1":
    # Test-only fault: make the patched signer disagree, to prove this check fails.
    _sign = new.sign_intent
    new.sign_intent = lambda intent, kid, key: _sign(intent, kid, key)[:-3] + "00]"

rng = random.Random(20261001)
ALPHABET = string.ascii_letters + string.digits + " -_.ÄéüßøЖ中✓"


def text(n):
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, n))).strip() or "x"


checked = 0
for _ in range(500):
    key = secrets.token_bytes(rng.choice([32, 48, 64, 128]))
    kid = rng.choice(["k1", "lab-key", "rot.2026_10"])
    now = datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(seconds=rng.randint(0, 10**7), microseconds=rng.randint(0, 999999))
    source = dict(zabbix_instance=rng.choice(["lab-zbx", "zbx-a", "zbx-b"]),
                  zabbix_event_id=str(rng.randint(1, 10**12)), zabbix_trigger_id=str(rng.randint(1, 10**9)))
    customers = sorted({text(20) for _ in range(rng.randint(1, 5))})
    actor = dict(login=text(60), customers=customers, admin=rng.random() < 0.2, auth_type="user")
    args = (str(uuid4()), customers[0], source, actor, str(rng.randint(1, 99)), str(rng.randint(1, 99)), now)
    action_id = str(uuid4())
    intent_old = old.build_intent(*args, action_id=action_id)
    intent_new = new.build_intent(*args, action_id=action_id)
    assert intent_old == intent_new
    assert old.canonical_bytes(intent_old) == new.canonical_bytes(intent_new)
    marker_old = old.sign_intent(intent_old, kid, key)
    marker_new = new.sign_intent(intent_new, kid, key)
    assert marker_old == marker_new, (marker_old, marker_new)
    capture = dict(intent=intent_new, marker=marker_old, alert_id=intent_new["alert_id"],
                   customer=intent_new["customer"], source=source, history_type="ack",
                   history_user=actor["login"], resulting_status="ack",
                   captured_at=new.timestamp(now + timedelta(seconds=1)))
    assert new.verify_capture(capture, {kid: key}) == old.verify_capture(capture, {kid: key})
    tampered = dict(capture, marker=marker_old[:-2] + ("0]" if marker_old[-2] != "0" else "1]"))
    for mod in (old, new):
        try:
            mod.verify_capture(tampered, {kid: key})
            raise AssertionError("tampered MAC accepted")
        except mod.BindingError as exc:
            assert exc.args[0] == "mac_invalid"
    checked += 1


def reason(fn, *a):
    try:
        fn(*a)
    except Exception as exc:  # noqa: BLE001 - comparing exception type and reason
        return type(exc).__name__, exc.args[:1]
    return None


base = old.build_intent(str(uuid4()), "c", dict(zabbix_instance="z", zabbix_event_id="1", zabbix_trigger_id="2"),
                        dict(login="u", customers=["c"], admin=False, auth_type="user"), "1", "1",
                        datetime(2026, 10, 1, tzinfo=timezone.utc))
cases = {
    "oversized_login": dict(base, actor=dict(base["actor"], login="a" * 300)),
    "lone_surrogate": dict(base, customer="\ud800"),
    "bad_version": dict(base, version=2),
}
parity = {}
for name, intent in cases.items():
    a, b = reason(old.canonical_bytes, intent), reason(new.canonical_bytes, intent)
    assert a == b, (name, a, b)
    parity[name] = a
for kid, key in [("bad kid", bytes(32)), ("k1", bytes(31)), ("k1", bytes(129))]:
    a, b = reason(old.sign_intent, base, kid, key), reason(new.sign_intent, base, kid, key)
    assert a == b, (kid, len(key), a, b)
    parity[f"sign {kid!r} {len(key)}B"] = a

# Verification-key boundary: the original accepts any byte key of at least 32 bytes.
vk_intent = old.build_intent(str(uuid4()), "c", dict(zabbix_instance="z", zabbix_event_id="1", zabbix_trigger_id="2"),
                             dict(login="u", customers=["c"], admin=False, auth_type="user"), "1", "1",
                             datetime(2026, 10, 1, tzinfo=timezone.utc))
import hashlib, hmac as _hmac
for size in (32, 128, 129, 200, 1024):
    vkey = secrets.token_bytes(size)
    vmac = _hmac.new(vkey, old.canonical_bytes(vk_intent), hashlib.sha256).hexdigest()
    vmarker = f'[zabalack:v1 action={vk_intent["action_id"]} kid=k1 mac={vmac}]'
    cap = dict(intent=vk_intent, marker=vmarker, alert_id=vk_intent["alert_id"], customer="c",
               source=vk_intent["source"], history_type="ack", history_user="u", resulting_status="ack",
               captured_at=old.timestamp(datetime(2026, 10, 1, 0, 0, 1, tzinfo=timezone.utc)))
    bad = dict(cap, marker=vmarker[:-2] + ("0]" if vmarker[-2] != "0" else "1]"))
    for label, capture in (("valid", cap), ("tampered", bad)):
        a, b = reason(old.verify_capture, capture, {"k1": vkey}), reason(new.verify_capture, capture, {"k1": vkey})
        assert a == b, (size, label, a, b)
        parity[f"verify {size}B key {label}"] = a or "accepted"
for label, keys in (("31B key", {"k1": bytes(31)}), ("missing key", {}), ("str key", {"k1": "x" * 40})):
    a, b = reason(old.verify_capture, cap, keys), reason(new.verify_capture, cap, keys)
    assert a == b, (label, a, b)
    parity[f"verify {label}"] = a

print(f"differential: {checked} random intents identical (build, canonical bytes, marker, verify, tamper)")
for name, result in parity.items():
    print(f"error parity: {name}: {result}")
sys.exit(0)
