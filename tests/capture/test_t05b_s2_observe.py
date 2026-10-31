"""T05b S2: OwnerSession.observe, the ledger-only observer's provider path (design r2 + r3 + r3a).

[get] a real fake-provider GET counted by the fake; [inject] synthetic fake state set by the test. Every
witness states its transport baselines and asserts that no ACK is ever sent by an observation.
"""
import json

import pytest

from conftest import new_alert, sql
from test_t04_s2_sender import _effect, _owner, fake, instance  # noqa: F401
from test_t04_s3b_settlement import _successor
from test_t05a_reverse_state import _alert, _display, _ledger
from voalack import sender


def _enable(instance, on=True):
    sql("UPDATE voalack.instance_config SET observer_enabled = %s WHERE instance_id = %s", (on, instance), fetch=False)


def _counts(owner, fake):
    return {"reads": fake.counts["reads"], "logins": fake.counts["logins"], "ack_writes": owner.transport.counts["ack_writes"],
            "receipts": fake.counts["receipts"], "effects": fake.counts["effects"]}


def _stored(alert_id):
    return sql("SELECT classification, summary FROM voalack.source_observations WHERE alert_id = %s "
               "ORDER BY reservation_seq", (alert_id,))


def test_flag_off_uses_no_credential_or_network(client, app, instance, fake):
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    owner.token = None                                   # any read would need a fresh login
    before = _counts(owner, fake)
    result = owner.observe(alert_id)
    assert (result["outcome"], result["reason"]) == ("refused", "observer_disabled"), result
    assert _counts(owner, fake) == before                # zero reads, zero logins, zero ACKs
    assert owner.stopped is None


def test_one_get_per_accepted_reservation_and_never_an_ack(client, app, instance, fake):
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    before, ledger, alert = _counts(owner, fake), _ledger(), _alert(alert_id)
    first = owner.observe(alert_id)
    assert (first["outcome"], first["result"], first["classification"]) == ("recorded", "stored", "not_acked"), first
    fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True,
                           "comment": "acknowledged in ONE"}                    # [inject]
    second = owner.observe(alert_id)
    third = owner.observe(alert_id)
    assert [r["result"] for r in (first, second, third)] == ["stored", "stored", "unchanged"]
    after = _counts(owner, fake)
    assert after["reads"] == before["reads"] + 3 and after["ack_writes"] == before["ack_writes"] == 0
    assert (after["receipts"], after["effects"]) == (before["receipts"], before["effects"])
    assert _ledger() == ledger and _alert(alert_id) == alert                    # nothing outbound, Alerta unchanged
    stored = _stored(alert_id)
    assert [c for c, _ in stored] == ["not_acked", "acked_unattributed"]
    assert "acknowledged in ONE" not in json.dumps([s for _, s in stored])      # no raw comment text


def test_summary_is_typed_and_never_carries_text():
    s = sender.observation_summary(200, {"target_id": "4711", "kind": "triggered_alarm", "acked": True,
                                         "comment": "[AlertaAck:0f0f0f0f-0000-4000-8000-000000000000] x by alice",
                                         "acked_by_operation": "a" * 64, "operation_status": "completed"}, None)
    assert s["comment"]["state"] == "string" and set(s["comment"]) == {"state", "sha256"}
    assert s["marker"] == {"state": "valid", "action_id": "0f0f0f0f-0000-4000-8000-000000000000"}
    assert s["operation"] == {"state": "valid", "sha256": "a" * 64}
    assert "alice" not in json.dumps(s)
    assert sender.observation_summary(None, None, "login")["acked"] == {"state": "absent"}
    assert sender.observation_summary(200, {"acked": "yes", "target_id": "04711"}, None)["acked"] == {"state": "invalid"}


MARKED = "[AlertaAck:0f0f0f0f-0000-4000-8000-000000000000]"


@pytest.mark.parametrize("comment, expected", [
    ("missing", ("absent", "absent")),
    (None, ("absent", "absent")),
    (7, ("invalid", "absent")),
    ("", ("string", "absent")),
    ("\ud800", ("invalid", "absent")),                                   # lone surrogate: not valid Unicode
    (MARKED + " by \ud800", ("invalid", "absent")),                      # even after a valid marker prefix
], ids=["missing", "null", "nonstring", "empty", "surrogate", "marker_surrogate"])
def test_summary_comment_states_are_total_and_never_carry_text(comment, expected):
    alarm = {"target_id": "4711", "kind": "triggered_alarm", "acked": True}
    if comment != "missing":
        alarm["comment"] = comment
    s = sender.observation_summary(200, alarm, None)                     # never raises
    assert (s["comment"]["state"], s["marker"]["state"]) == expected, s
    assert set(s["comment"]) == ({"state", "sha256"} if expected[0] == "string" else {"state"})
    json.dumps(s, ensure_ascii=False).encode("utf-8")                   # the summary itself is valid Unicode


def test_a_non_unicode_comment_from_the_provider_is_recorded_as_invalid(client, app, instance, fake):
    """[get] the provider returns an escaped lone surrogate after a valid marker prefix: one GET, a defined
    completion classified invalid, no comment text or digest of it, nothing outbound."""
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True,
                           "comment": MARKED + " by \ud800"}                                     # [inject]
    before, ledger, alert = _counts(owner, fake), _ledger(), _alert(alert_id)
    result = owner.observe(alert_id)
    assert (result["outcome"], result["result"], result["classification"]) == ("recorded", "stored", "invalid"), result
    after = _counts(owner, fake)
    assert after["reads"] == before["reads"] + 1 and after["ack_writes"] == before["ack_writes"]
    assert _ledger() == ledger and _alert(alert_id) == alert
    (classification, summary), = _stored(alert_id)
    assert summary["comment"] == {"state": "invalid"} and summary["marker"] == {"state": "absent"}
    assert sql("SELECT count(*) FROM voalack.observation_completions c JOIN voalack.observation_reads r "
               "USING (obs_id) WHERE r.alert_id = %s", (alert_id,))[0][0] == 1


def test_an_unresolved_holder_refuses_before_any_read(client, app, instance, fake):
    _enable(instance)
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    fake.script["ack"] = "close_after_body"
    assert owner.apply_once(effect_id)["outcome"] == "uncertain"
    fake.script["ack"] = "success"
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (effect_id,))[0][0]
    before = _counts(owner, fake)
    result = owner.observe(alert_id)
    assert (result["outcome"], result["reason"]) == ("refused", "target_held"), result
    assert _counts(owner, fake) == before


def test_a_flag_cycle_under_a_live_owner_stops_it(client, app, instance, fake):
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    _enable(instance, False)
    _enable(instance, True)                              # back on: only the revision bump fences the owner
    before = _counts(owner, fake)
    result = owner.observe(alert_id)
    # the owner's own fence sees the bumped revision before it reserves anything (earlier than the SQL refusal)
    assert (result["outcome"], result["reason"]) == ("held", "config_changed"), result
    assert owner.stopped == "config_changed" and _counts(owner, fake) == before
    assert sql("SELECT count(*) FROM voalack.observation_reads WHERE alert_id = %s", (alert_id,))[0][0] == 0
    assert owner.observe(alert_id)["outcome"] == "held"  # the local stop persists


def test_a_change_after_the_reservation_stops_the_owner_before_login_and_read(client, app, instance, fake):
    """The fence between the reservation and the provider: a configuration change committed after an accepted
    reservation stops the owner before any login or GET; the reservation stays without a completion."""
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    owner.token = None                                   # a read would need a fresh login
    owner.hooks["after_observation_reservation"] = lambda _: _enable(instance, False)
    before = _counts(owner, fake)
    result = owner.observe(alert_id)
    assert _counts(owner, fake) == before, ("login or GET after a committed change", _counts(owner, fake), before)
    assert (result["reservation"], result["outcome"], result["reason"]) == ("reserved", "held", "config_changed"), result
    assert owner.stopped == "config_changed"
    assert sql("SELECT count(*) FROM voalack.observation_reads WHERE alert_id = %s", (alert_id,))[0][0] == 1
    assert sql("SELECT count(*) FROM voalack.observation_completions c JOIN voalack.observation_reads r "
               "USING (obs_id) WHERE r.alert_id = %s", (alert_id,))[0][0] == 0


def test_a_flag_change_during_the_read_is_refused_at_record(client, app, instance, fake):
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    owner.hooks["before_observation_record"] = lambda _: _enable(instance, False)
    result = owner.observe(alert_id)
    assert (result["outcome"], result["reason"]) == ("held", "refused:config_changed"), result
    assert owner.stopped == "config_changed"
    assert _stored(alert_id) == []


def test_a_competing_binding_during_the_read_is_ambiguous(client, app, instance, fake):
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    owner.hooks["before_observation_record"] = lambda _: new_alert(client, instance_id=instance)
    result = owner.observe(alert_id)
    assert (result["outcome"], result["result"]) == ("recorded", "refused:ambiguous_target"), result
    assert _stored(alert_id) == [] and owner.stopped is None


def test_a_lab_holder_committed_during_the_read_refuses_the_record(client, app, instance, fake):
    """C1 [lab]: a dispatched attempt on the key committed between reservation and record (S3b holder
    fixture) refuses the record at the admission statement; nothing is stored."""
    from test_t04_s3b_settlement import _lab_holder
    _enable(instance)
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    attempt_id = sql("SELECT attempt_id::text FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (effect_id,))[0][0]
    owner.hooks["before_observation_record"] = lambda _: _lab_holder(attempt_id)
    result = owner.observe(alert_id)
    assert (result["outcome"], result["result"]) == ("recorded", "refused:target_held"), result
    assert _stored(alert_id) == []


def test_database_loss_before_record_stops_the_owner(client, app, instance, fake):
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)

    def lose(_):
        owner._conn.close()
        owner.dsn = "postgres://nobody:nothing@127.0.0.1:1/none"     # [lab] the database is unreachable
    owner.hooks["before_observation_record"] = lose
    result = owner.observe(alert_id)
    assert result["outcome"] == "held", result
    assert owner.stopped is not None
    reads = fake.counts["reads"]
    assert owner.observe(alert_id)["outcome"] == "held" and fake.counts["reads"] == reads   # no fresh read


def test_reading_back_our_own_ack_is_matched_and_echoes_nothing(client, app, instance, fake):
    """E1 for the observer: after a confirmed ACK on the key, an observation of that exact state is
    classified as our matching completed operation; no intent, capture, effect, attempt, note or ACK."""
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (effect_id,))[0][0]
    action = sql("SELECT action_id::text FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0][0]
    _enable(instance)                                    # fences the sending owner (revision bump)
    observer = _successor(instance, fake, owner, quiesce=False)
    ledger, alert, display = _ledger(), _alert(alert_id), _display(action)
    acks = fake.counts["receipts"]
    result = observer.observe(alert_id)
    assert (result["outcome"], result["classification"]) == \
        ("recorded", "acked_with_matching_voalack_operation"), result
    assert fake.counts["receipts"] == acks and observer.transport.counts["ack_writes"] == 0
    assert _ledger() == ledger and _alert(alert_id) == alert and _display(action) == display


def test_concurrent_identical_records_on_one_chain_store_once(client, app, instance, fake):
    """[native] B2 chain lock: session A records inside an open transaction (holding the chain row); session B
    records the same state for a later reservation and must wait (its own backend is seen blocked by A); after A
    commits, B sees A's stored state and returns unchanged. Without the chain lock B would not see A's
    uncommitted row and would store a second row."""
    import datetime
    import psycopg2
    import psycopg2.extras
    from conftest import SENDER_DSN
    from test_t05b_s1_observer import RECORD, _begin, _finish, _native_worker, _waiting_on, summary
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    first, _ = _begin(owner, alert_id)
    second, _ = _begin(owner, alert_id)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    a = psycopg2.connect(SENDER_DSN)
    cur = a.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    out = {}
    worker = _native_worker(RECORD, (second, instance, owner.generation, owner.incarnation, json.dumps(summary()),
                                     now, now), out)
    try:
        cur.execute(RECORD, (first, instance, owner.generation, owner.incarnation, json.dumps(summary()), now, now))
        assert cur.fetchone()["r_result"] == "stored"                 # not yet committed: A holds the chain row
        worker.start()
        waiter = _waiting_on(cur)
        assert waiter is not None and waiter == out.get("pid"), ("B never waited on A's chain lock", waiter, out)
        assert worker.is_alive()
        a.commit()
    finally:
        _finish(a, worker, out)
    assert out["row"]["r_result"] == "unchanged", out
    assert len(_stored(alert_id)) == 1


@pytest.mark.parametrize("drift, restore, failure", [
    ("DROP TRIGGER instance_config_observer_bump ON voalack.instance_config",
     "CREATE TRIGGER instance_config_observer_bump BEFORE UPDATE ON voalack.instance_config "
     "FOR EACH ROW EXECUTE FUNCTION voalack._observer_flag_bump()", "before_update_drift"),
    ("ALTER TABLE voalack.observation_reads DROP CONSTRAINT observation_reads_reservation_seq_key",
     "ALTER TABLE voalack.observation_reads ADD CONSTRAINT observation_reads_reservation_seq_key "
     "UNIQUE (reservation_seq)", "uniqueness_drift"),
    ("REVOKE EXECUTE ON FUNCTION voalack.begin_observation(uuid, text, text, bigint, uuid) FROM voalack_sender",
     "GRANT EXECUTE ON FUNCTION voalack.begin_observation(uuid, text, text, bigint, uuid) TO voalack_sender",
     "execute_drift"),
], ids=["flag_fence", "uniqueness", "execute"])
def test_a_drifted_observer_installation_is_refused_before_login(client, app, instance, fake, drift, restore, failure):
    """A partial or drifted observer installation fails sender readiness at acquisition: no owner, so no
    login, read or reservation is possible; readiness returns once the installation is restored."""
    from test_t04_s2_sender import _sender_ready_error
    from voalack import verifier
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    logins, reads = fake.counts["logins"], fake.counts["reads"]
    sql(drift, fetch=False)
    try:
        error = _sender_ready_error()
        with pytest.raises(verifier.NotReady):
            _owner(instance, fake)
    finally:
        sql(restore, fetch=False)
    assert error is not None and failure in error, error
    assert (fake.counts["logins"], fake.counts["reads"]) == (logins, reads)
    assert sql("SELECT count(*) FROM voalack.session_owners WHERE instance_id = %s AND state = 'active'",
               (instance,))[0][0] == 0
    assert sql("SELECT count(*) FROM voalack.observation_reads WHERE alert_id = %s", (alert_id,))[0][0] == 0
    assert _sender_ready_error() is None
