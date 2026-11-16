"""Audit 2026-11-08 finding 6: a ONE session that is no longer accepted is not reused forever.

The owner logged in once and kept the session. After a ONE restart or a session expiry every later
preflight was answered 401 and aborted as preflight_unavailable, so each acknowledgement used up its
three attempts and ended BLOCKED. Now any 401 reply makes the owner forget the session: the next
operation logs in again (at most once) and registers the new session before using it. The reply
keeps its own classification: a preflight answered 401 is still an abort without dispatch that
counts toward the budget, and an ACK answered 401 stays uncertain and is never resent.

Labels: [fake] the loopback fake's opt-in session modes (``script["session"]``); [scripted] a Python
substitution of one reply status. Counts: logins and reads at the provider and in the transport,
requests the provider answered 401, ACK connects and writes, provider receipts and effects.
"""
import hashlib
import json

import pytest

from conftest import new_alert, sql
from test_t04_s2_sender import _attempt, _effect, _guards, _owner, fake, instance  # noqa: F401
from test_t04_s3a_transport import _effect_budget, _phase
from test_t04_s3b_settlement import _sessions, _uncertain
from test_t05b_s2_observe import _enable


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _logins(owner, fake):
    return fake.counts["logins"], owner.transport.counts["logins"]


def _targets(fake):
    return [json.loads(body)["target"]["id"] for body in fake.receipts]


def test_after_a_one_restart_the_next_try_logs_in_again_and_delivers_once(client, app, instance, fake):
    first = _effect(client, app, instance, occurrence_ref="lab-a6-first")
    second = _effect(client, app, instance, target_id="4712", occurrence_ref="lab-a6-second")
    owner = _owner(instance, fake)
    assert owner.apply_once(first)["outcome"] == "confirmed"
    old = owner.token
    assert _logins(owner, fake) == (1, 1)
    fake.script["session"] = "expire_once"                               # [fake] ONE restarts: the session is gone
    refused = owner.apply_once(second)
    assert (refused["outcome"], refused["reason"]) == ("refused", "preflight_unavailable"), refused
    assert owner.token is None and owner.stopped is None                 # forgotten; the owner keeps running
    assert _attempt(refused["attempt_id"]) == ("aborted_before_dispatch", "revoked")
    assert _effect_budget(second)[:2] == ("QUEUED", 1) and _guards(instance) == []
    assert [d["status"] for (d,) in sql("SELECT detail FROM voalack.attempt_evidence WHERE attempt_id = %s "
                                        "AND kind = 'preflight_unavailable'", (refused["attempt_id"],))] == [401]
    assert _logins(owner, fake) == (1, 1) and fake.unauthorised == {"reads": 1, "acks": 0}

    delivered = owner.apply_once(second)                                 # the next try logs in again
    assert delivered["outcome"] == "confirmed", delivered
    assert _logins(owner, fake) == (2, 2)                                # exactly one login more
    assert owner.token not in (None, old)
    assert _sessions(instance, owner) == [_digest(old), _digest(owner.token)]   # each registered before use
    assert _effect_budget(second)[:2] == ("REMOTE_CONFIRMED", 2)
    assert sql("SELECT state FROM voalack.attempts WHERE effect_id = %s ORDER BY started_at", (second,)) == [
        ("aborted_before_dispatch",), ("confirmed",)]
    assert _targets(fake) == ["4711", "4712"]                             # one ACK per effect, none repeated
    assert _phase(owner, fake) == {"dispatch": 2, "connects": 2, "connect_failures": 0, "writes": 2, "receipts": 2,
                                   "effects": 2}
    assert (fake.counts["reads"], owner.transport.counts["reads"]) == (4, 5)    # the 401 read never executed
    assert fake.unauthorised == {"reads": 1, "acks": 0}


def test_a_persistent_401_still_blocks_after_three_tries(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    fake.script["session"] = "expire_always"                             # [fake] no session outlives its first use
    owner = _owner(instance, fake)
    for count in (1, 2, 3):
        result = owner.apply_once(effect_id)
        assert (result["outcome"], result["reason"]) == ("refused", "preflight_unavailable"), result
        assert owner.token is None and _logins(owner, fake) == (count, count)   # one fresh login per try, no more
        assert _effect_budget(effect_id)[:2] == (("QUEUED", count) if count < 3 else ("BLOCKED", 3))
    assert owner.apply_once(effect_id)["reason"] == "effect_not_queued"
    assert _logins(owner, fake) == (3, 3)                                # a refused start never logs in
    assert fake.unauthorised == {"reads": 3, "acks": 0} and fake.counts["reads"] == 0
    assert len(_sessions(instance, owner)) == 3 and owner.stopped is None
    assert _phase(owner, fake) == {"dispatch": 0, "connects": 0, "connect_failures": 0, "writes": 0, "receipts": 0,
                                   "effects": 0}


@pytest.mark.parametrize("how", ["expired", "scripted"])
def test_an_ack_answered_401_stays_uncertain_and_is_never_resent(client, app, instance, fake, how):
    """expired: [fake] the ACK's session expired after the preflight; the provider never executed it.
    scripted: [scripted] the provider applied the ACK, but the reply's status is replaced by 401."""
    effect_id = _effect(client, app, instance, occurrence_ref="lab-a6-ack")
    other = _effect(client, app, instance, target_id="4712", occurrence_ref="lab-a6-other")
    owner = _owner(instance, fake)
    if how == "expired":
        def expire(_):
            owner.hooks.pop("before_send")
            fake.script["session"] = "expire_once"
        owner.hooks["before_send"] = expire
    else:
        call = owner.transport.ack

        def status_401(*args):
            owner.transport.ack = call                                    # the next ACK is unchanged
            return 401, call(*args)[1]
        owner.transport.ack = status_401
    result = owner.apply_with_retry(effect_id)
    assert result["outcome"] == "uncertain" and "retry" not in result, result
    assert owner.token is None and owner.stopped is None
    assert _attempt(result["attempt_id"]) == ("uncertain", "consumed") and _guards(instance) == [("4711", "uncertain")]
    assert sql("SELECT detail FROM voalack.attempt_evidence WHERE attempt_id = %s AND kind = 'result'",
               (result["attempt_id"],))[0][0]["status"] == 401
    applied = 1 if how == "scripted" else 0
    assert (fake.counts["receipts"], fake.counts["effects"]) == (applied, applied)
    assert fake.unauthorised == {"reads": 1 - applied, "acks": 1 - applied}   # expired: the read-back too
    again = owner.apply_once(effect_id)
    assert (again["outcome"], again["reason"]) == ("refused", "effect_not_queued")
    assert sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0] == 1
    assert _logins(owner, fake) == (1, 1)                                # nothing resent, no login for it

    assert owner.apply_once(other)["outcome"] == "confirmed"             # the next send logs in again
    assert _logins(owner, fake) == (2, 2) and len(_sessions(instance, owner)) == 2
    assert _guards(instance) == [("4711", "uncertain")] and _attempt(result["attempt_id"]) == ("uncertain", "consumed")
    assert owner.transport.counts["ack_writes"] == 2 and _targets(fake) == ["4711"] * applied + ["4712"]


@pytest.mark.parametrize("status", [401, 403, 500])
def test_only_a_401_reply_forgets_the_session(client, app, instance, fake, status):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    call = owner.transport.read_alarm
    owner.transport.read_alarm = lambda *args: (status, call(*args)[1])   # [scripted] status, real payload
    for count in (1, 2):
        assert owner.apply_once(effect_id)["reason"] == "preflight_unavailable"
        assert _effect_budget(effect_id)[:2] == ("QUEUED", count)
    logins = 2 if status == 401 else 1                                   # 403 and 5xx keep the session
    assert (owner.token is None) == (status == 401)
    assert _logins(owner, fake) == (logins, logins) and len(_sessions(instance, owner)) == logins
    assert _phase(owner, fake)["connects"] == 0 and fake.counts["receipts"] == 0


def test_a_reconciliation_read_answered_401_is_evidence_only_and_the_next_read_logs_in(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)   # the fake applied the ACK
    fake.script["session"] = "expire_once"                               # [fake]
    logins = _logins(owner, fake)
    first = owner.reconcile(attempt_id)
    assert (first["outcome"], first["classification"]) == ("recorded", "evidence_only"), first
    assert owner.token is None and owner.stopped is None and _logins(owner, fake) == logins
    second = owner.reconcile(attempt_id)
    assert (second["outcome"], second["classification"]) == ("settled", "attributable"), second
    assert _logins(owner, fake) == (logins[0] + 1, logins[1] + 1) and len(_sessions(instance, owner)) == 2
    assert owner.transport.counts["ack_writes"] == 1 and fake.counts["receipts"] == 1   # reads only


def test_an_observation_read_answered_401_forgets_the_session(client, app, instance, fake):
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    first = owner.observe(alert_id)
    fake.script["session"] = "expire_once"                               # [fake]
    second = owner.observe(alert_id)
    assert owner.token is None and owner.stopped is None and _logins(owner, fake) == (1, 1)
    third = owner.observe(alert_id)
    assert [(r["outcome"], r["classification"]) for r in (first, second, third)] == [
        ("recorded", "not_acked"), ("recorded", "unreadable"), ("recorded", "not_acked")]
    assert _logins(owner, fake) == (2, 2) and len(_sessions(instance, owner)) == 2
    assert fake.unauthorised == {"reads": 1, "acks": 0}
    assert owner.transport.counts["ack_writes"] == 0 and fake.counts["receipts"] == 0
