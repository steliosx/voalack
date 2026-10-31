"""T05b S1: the ledger-only source-state observer, SQL layer (design r2 + r3 + r3a).

Direct-SQL witnesses through the sender role ([sql]); no provider read happens in S1 (the network path is
S2). Every summary is a constructed typed summary, never raw provider text.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.errors
import pytest

from conftest import APP_DSN, DSN, VERIFIER_DSN, bind, new_alert, sql
from test_t04_s2_sender import _call, _effect, _owner, fake, instance  # noqa: F401
from test_t04_s3a_transport import _refuse_ack_connects
from test_t04_s3b_settlement import SETTLER_DSN, _successor, _uncertain
from test_t04_s4_projection import PROJECTOR_DSN


def _enable(instance, on=True):
    sql("UPDATE voalack.instance_config SET observer_enabled = %s WHERE instance_id = %s", (on, instance), fetch=False)


def _revision(instance):
    return sql("SELECT config_revision FROM voalack.instance_config WHERE instance_id = %s", (instance,))[0][0]


def _begin(owner, alert_id, obs=None):
    obs = obs or str(uuid.uuid4())
    row = _call("SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)",
                (obs, alert_id, owner.instance_id, owner.generation, owner.incarnation))
    return obs, row


def _record(owner, obs, summary, started="now", completed="now"):
    now = datetime.now(timezone.utc)
    started = now if started == "now" else started
    completed = now + timedelta(microseconds=1) if completed == "now" else completed
    # ISO text with microseconds (Alerta's process-wide datetime adapter sends milliseconds only)
    iso = lambda t: t.isoformat() if t is not None else None   # noqa: E731
    return _call(RECORD, (obs, owner.instance_id, owner.generation, owner.incarnation,
                          None if summary is None else json.dumps(summary), iso(started), iso(completed)))


RECORD = "SELECT * FROM voalack.record_observation(%s, %s, %s, %s, %s::jsonb, %s::timestamptz, %s::timestamptz)"
BEGIN = "SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)"


def summary(**over):
    """A typed summary of a readable, unacknowledged alarm on the default bound target."""
    s = {"v": 1, "http_status": 200, "read_error": None,
         "acked": {"state": "false"}, "comment": {"state": "absent"}, "operation": {"state": "absent"},
         "operation_status": {"state": "absent"}, "children": {"state": "absent"}, "marker": {"state": "absent"},
         "response_target_kind": {"state": "string", "value": "triggered_alarm"},
         "response_target_id": {"state": "string", "value": "4711"}}
    s.update(over)
    return s


ACKED = {"acked": {"state": "true"}}


def _bound(client, instance, fake, enable=True):
    """A bound alert on the instance, with the observer enabled before the owner is acquired."""
    if enable:
        _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    return alert_id, _owner(instance, fake)


def _rows(table, alert_id):
    return sql(f"SELECT count(*) FROM voalack.{table} t WHERE t.alert_id = %s", (alert_id,))[0][0]


# --- enablement: default off; a flag change bumps the revision and fences old owners ---------------

def test_observer_is_off_by_default_and_refuses(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake, enable=False)
    assert sql("SELECT observer_enabled FROM voalack.instance_config WHERE instance_id = %s", (instance,))[0][0] is False
    obs, row = _begin(owner, alert_id)
    assert (row["outcome"], row["r_target_id"]) == ("observer_disabled", None)
    assert sql("SELECT count(*) FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0][0] == 0


@pytest.mark.parametrize("cycle", ["on", "off_on"])
def test_flag_change_bumps_the_revision_and_fences_the_old_owner(client, app, instance, fake, cycle):
    alert_id, owner = _bound(client, instance, fake)
    before = _revision(instance)
    if cycle == "on":                                   # an unrelated column write does not bump
        sql("UPDATE voalack.instance_config SET credential_ref = credential_ref WHERE instance_id = %s",
            (instance,), fetch=False)
        assert _revision(instance) == before
        _enable(instance, True)                         # no change: no bump
        assert _revision(instance) == before
        return
    _enable(instance, False)
    _enable(instance, True)                             # off then on, with no other change
    assert _revision(instance) == before + 2
    obs, row = _begin(owner, alert_id)                  # the owner acquired before the cycle
    assert row["outcome"] == "config_changed", row


def test_an_explicit_revision_never_lowers_the_bump(client, app, instance, fake):
    _bound(client, instance, fake)
    before = _revision(instance)
    sql("UPDATE voalack.instance_config SET observer_enabled = false, config_revision = 1 WHERE instance_id = %s",
        (instance,), fetch=False)
    assert _revision(instance) == before + 1


# --- reservation refusals and resolution (B1, B3, C1) ------------------------------------------------

def test_reservation_resolves_the_bound_target_and_freezes_the_reader(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, row = _begin(owner, alert_id)
    assert (row["outcome"], row["r_target_kind"], row["r_target_id"]) == ("reserved", "triggered_alarm", "4711")
    r = sql("SELECT instance_id, reader_generation, reader_incarnation::text, config_revision, eligible "
            "FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0]
    assert r == (instance, owner.generation, owner.incarnation, _revision(instance), [])
    again = _begin(owner, alert_id, obs)[1]
    assert (again["outcome"], again["r_target_id"]) == ("already_reserved", None)   # no second grant


def test_unbound_inactive_and_foreign_targets_are_refused(client, app, instance, fake):
    _enable(instance)
    owner = _owner(instance, fake)
    unbound = new_alert(client, bound=False)
    assert _begin(owner, unbound)[1]["outcome"] == "no_binding"
    foreign = new_alert(client, instance_id="lab-one-elsewhere")
    assert _begin(owner, foreign)[1]["outcome"] == "wrong_instance"
    inactive = new_alert(client, instance_id=instance)
    sql("UPDATE voalack.bindings SET active = false WHERE alert_id = %s", (inactive,), fetch=False)
    assert _begin(owner, inactive)[1]["outcome"] == "no_binding"


def test_a_second_active_binding_on_the_key_is_ambiguous(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    new_alert(client, instance_id=instance)             # same instance, same target 4711
    assert _begin(owner, alert_id)[1]["outcome"] == "ambiguous_target"


def test_an_unresolved_holder_refuses_without_a_reservation(client, app, instance, fake):
    _enable(instance)
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (effect_id,))[0][0]
    # the owner acquired before enabling is fenced; a fresh owner sees the holder
    obs, row = _begin(owner, alert_id)
    assert row["outcome"] in ("config_changed", "target_held"), row
    assert sql("SELECT count(*) FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0][0] == 0


# --- classification precedence (C2), exact digests, validation (C3, r3a) ---------------------------

@pytest.mark.parametrize("over, expected", [
    ({}, "not_acked"),
    (ACKED, "acked_unattributed"),
    ({**ACKED, "operation": {"state": "valid", "sha256": "f" * 64}}, "acked_other"),
    ({**ACKED, "comment": {"state": "string", "sha256": "0" * 64},
      "marker": {"state": "valid", "action_id": str(uuid.uuid4())}}, "acked_unattributed"),
    ({"read_error": "transport", "http_status": None}, "unreadable"),
    ({"http_status": 500}, "unreadable"),
    ({"response_target_id": {"state": "string", "value": "4712"}}, "unreadable"),
    ({"response_target_kind": {"state": "string", "value": "grouped_alarm"}}, "unreadable"),
    ({"response_target_id": {"state": "absent"}}, "unreadable"),
    ({"response_target_kind": {"state": "invalid"}}, "unreadable"),
    ({"children": {"state": "present"}, **ACKED}, "unreadable"),
    ({"acked": {"state": "absent"}}, "invalid"),
    ({"acked": {"state": "invalid"}}, "invalid"),
    ({**ACKED, "comment": {"state": "invalid"}}, "invalid"),
    ({**ACKED, "operation": {"state": "malformed"}}, "invalid"),
    ({**ACKED, "comment": {"state": "string", "sha256": "0" * 64}, "marker": {"state": "malformed"}}, "invalid"),
    ({"operation": {"state": "valid", "sha256": "f" * 64}}, "contradictory"),
    ({"operation_status": {"state": "completed"}}, "contradictory"),
    ({"http_status": 500, "acked": {"state": "invalid"}}, "unreadable"),          # precedence: step 1 first
])
def test_classification_precedence(client, app, instance, fake, over, expected):
    alert_id, owner = _bound(client, instance, fake)
    obs, row = _begin(owner, alert_id)
    assert row["outcome"] == "reserved"
    started = None if over.get("read_error") == "login" else "now"
    rec = _record(owner, obs, summary(**over), started=started, completed=started)
    assert (rec["outcome"], rec["r_result"], rec["r_classification"]) == ("recorded", "stored", expected), rec


def _confirmed_on_key(client, app, instance, fake):
    """A confirmed attempt on 4711, then a different alert bound to the same key for observation."""
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    attempt = sql("SELECT attempt_id::text, action_id::text, request_sha256, "
                  "encode(sha256(convert_to(convert_from(request_bytes, 'UTF8')::jsonb->>'comment', 'UTF8')), 'hex') "
                  "FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0]
    first = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                "WHERE e.effect_id = %s", (effect_id,))[0][0]
    _enable(instance)                                    # fences the sending owner (revision bump)
    return first, _successor(instance, fake, owner, quiesce=False), attempt


@pytest.mark.parametrize("case, expected", [
    ("match", "acked_with_matching_voalack_operation"),
    ("other_comment", "acked_known_request_hash"),
    ("not_completed", "acked_known_request_hash"),
    ("marker_only", "acked_marker_unverified"),
])
def test_eligible_tuples_bind_operation_comment_and_marker(client, app, instance, fake, case, expected):
    alert_id, owner, (attempt_id, action_id, request_sha, comment_sha) = _confirmed_on_key(client, app, instance, fake)
    obs, row = _begin(owner, alert_id)
    assert row["outcome"] == "reserved", row
    eligible = sql("SELECT eligible FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0][0]
    assert eligible == [{"attempt_id": attempt_id, "action_id": action_id, "request_sha256": request_sha,
                         "comment_sha256": comment_sha}]
    s = {**ACKED, "comment": {"state": "string", "sha256": comment_sha},
         "operation": {"state": "valid", "sha256": request_sha}, "operation_status": {"state": "completed"}}
    if case == "other_comment":
        s["comment"] = {"state": "string", "sha256": "0" * 64}
    elif case == "not_completed":
        s["operation_status"] = {"state": "other"}
    elif case == "marker_only":
        s = {**ACKED, "comment": {"state": "string", "sha256": "0" * 64},
             "marker": {"state": "valid", "action_id": action_id}}
    rec = _record(owner, obs, summary(**s))
    assert rec["r_classification"] == expected, rec


def test_never_sent_attempts_are_not_eligible(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    hooks = _refuse_ack_connects(owner, 1)                # a proven not-sent attempt (S3a)
    owner.hooks.update(before_send=hooks["before_send"])
    assert owner.apply_once(effect_id)["outcome"] == "not_sent"
    hooks["restore"]()
    states = sql("SELECT state FROM voalack.attempts WHERE effect_id = %s", (effect_id,))
    assert states == [("not_sent",)]
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (effect_id,))[0][0]
    _enable(instance)
    observer = _successor(instance, fake, owner, quiesce=False)
    obs, row = _begin(observer, alert_id)
    if row["outcome"] == "reserved":
        assert sql("SELECT eligible FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0][0] == [], states
    else:
        assert row["outcome"] == "target_held", (row, states)


@pytest.mark.parametrize("bad", ["unknown_key", "missing_key", "match_key", "raw_comment", "value_on_absent",
                                 "bad_hex", "bad_kind", "bad_id", "string_status", "version"])
def test_malformed_summaries_are_rejected_with_digest_only_evidence(client, app, instance, fake, bad):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    s = summary()
    if bad == "unknown_key":
        s["extra"] = "x"
    elif bad == "missing_key":
        s.pop("marker")
    elif bad == "match_key":
        s["response_target_id"] = {"state": "string", "value": "4711", "match": True}
    elif bad == "raw_comment":
        s["comment"] = {"state": "string", "sha256": "a" * 64, "text": "operator words"}
    elif bad == "value_on_absent":
        s["operation"] = {"state": "absent", "sha256": "a" * 64}
    elif bad == "bad_hex":
        s["operation"] = {"state": "valid", "sha256": "A" * 64}
    elif bad == "bad_kind":
        s["response_target_kind"] = {"state": "string", "value": "Triggered Alarm!"}
    elif bad == "bad_id":
        s["response_target_id"] = {"state": "string", "value": "04711"}
    elif bad == "string_status":
        s["http_status"] = "200"
    else:
        s["v"] = 2
    rec = _record(owner, obs, s)
    assert rec["outcome"] == "bad_summary", rec
    ev = sql("SELECT kind, reason, input_octets, input_sha256 IS NOT NULL FROM voalack.observation_evidence "
             "WHERE obs_id = %s", (obs,))
    assert len(ev) == 1 and ev[0][0] == "bad_summary" and ev[0][3] is True
    assert "operator words" not in json.dumps(sql("SELECT row_to_json(e) FROM voalack.observation_evidence e "
                                                  "WHERE obs_id = %s", (obs,)))
    assert sql("SELECT count(*) FROM voalack.observation_completions WHERE obs_id = %s", (obs,))[0][0] == 0


def test_oversize_input_keeps_only_its_length(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    s = summary()
    s["padding"] = "p" * 5000
    rec = _record(owner, obs, s)
    assert rec["outcome"] == "bad_summary"
    assert sql("SELECT reason, input_sha256, input_octets > 4096 FROM voalack.observation_evidence WHERE obs_id = %s",
               (obs,)) == [("oversize", None, True)]


@pytest.mark.parametrize("times", ["login_with_times", "read_without_times", "before_reservation", "reversed",
                                   "future"])
def test_client_times_are_bound_to_the_reservation_window(client, app, instance, fake, times):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    now = datetime.now(timezone.utc)
    s, started, completed = summary(), now, now
    if times == "login_with_times":
        s = summary(read_error="login", http_status=None)
    elif times == "read_without_times":
        started = completed = None
    elif times == "before_reservation":
        started = now - timedelta(hours=1)
    elif times == "reversed":
        started, completed = now, now - timedelta(seconds=1)
    else:
        completed = now + timedelta(hours=1)
    rec = _record(owner, obs, s, started=started, completed=completed)
    assert rec["outcome"] == "bad_summary", rec
    assert sql("SELECT reason FROM voalack.observation_evidence WHERE obs_id = %s", (obs,)) == [("client_times",)]


# --- replay identity, deduplication and order (C3, B2) ------------------------------------------------

def test_replay_identity_includes_the_client_times(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    now = datetime.now(timezone.utc)
    first = _record(owner, obs, summary(), started=now, completed=now)
    assert (first["outcome"], first["r_result"]) == ("recorded", "stored")
    same = _record(owner, obs, summary(), started=now, completed=now)
    assert same == first                                                    # identical: the original result
    shifted = _record(owner, obs, summary(), started=now, completed=now + timedelta(microseconds=5))
    assert (shifted["outcome"], shifted["r_result"]) == ("already_recorded", "stored")
    other = _record(owner, obs, summary(**ACKED), started=now, completed=now)
    assert (other["outcome"], other["r_classification"]) == ("already_recorded", "not_acked")
    assert sql("SELECT count(*) FROM voalack.observation_evidence WHERE obs_id = %s "
               "AND kind = 'conflicting_observation'", (obs,))[0][0] == 2           # one row per conflicting call
    bad = _record(owner, obs, {**summary(), "extra": 1}, started=now, completed=now)
    assert (bad["outcome"], bad["r_result"]) == ("already_recorded", "stored")      # malformed replay
    assert sql("SELECT count(*) FROM voalack.observation_completions WHERE obs_id = %s", (obs,))[0][0] == 1
    assert sql("SELECT count(*) FROM voalack.source_observations WHERE obs_id = %s", (obs,))[0][0] == 1


def test_a_to_a_stores_once_and_a_b_a_stores_three(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    results = []
    for s in (summary(), summary(), summary(**ACKED), summary()):
        obs, row = _begin(owner, alert_id)
        assert row["outcome"] == "reserved"
        results.append(_record(owner, obs, s)["r_result"])
    assert results == ["stored", "unchanged", "stored", "stored"]
    chain = sql("SELECT classification, previous_obs_id IS NOT NULL FROM voalack.source_observations "
                "WHERE alert_id = %s ORDER BY reservation_seq", (alert_id,))
    assert chain == [("not_acked", False), ("acked_unattributed", True), ("not_acked", True)]


def test_a_delayed_older_record_is_superseded(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    older, _ = _begin(owner, alert_id)
    newer, _ = _begin(owner, alert_id)
    assert _record(owner, newer, summary())["r_result"] == "stored"
    late = _record(owner, older, summary(**ACKED))
    assert (late["outcome"], late["r_result"]) == ("recorded", "superseded")
    assert _rows("source_observations", alert_id) == 1


def test_abandoned_reservation_cannot_be_recorded_by_another_reader(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    other = _successor(instance, fake, owner, quiesce=False)
    rec = _call("SELECT * FROM voalack.record_observation(%s, %s, %s, %s, %s::jsonb, now(), now())",
                (obs, instance, other.generation, other.incarnation, json.dumps(summary())))
    assert rec["outcome"] == "not_reader"
    assert sql("SELECT count(*) FROM voalack.observation_completions WHERE obs_id = %s", (obs,))[0][0] == 0


def test_a_flag_change_between_reservation_and_record_refuses(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    _enable(instance, False)
    rec = _record(owner, obs, summary())
    assert (rec["outcome"], rec["r_result"]) == ("recorded", "refused:config_changed")
    assert _rows("source_observations", alert_id) == 0


def test_a_competing_binding_committed_before_record_is_ambiguous(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    new_alert(client, instance_id=instance)
    rec = _record(owner, obs, summary())
    assert rec["r_result"] == "refused:ambiguous_target"


# --- privileges -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("dsn", [APP_DSN, VERIFIER_DSN, SETTLER_DSN, PROJECTOR_DSN],
                         ids=["app", "verifier", "settler", "projector"])
def test_other_runtime_roles_cannot_use_the_observer(app, dsn):
    with psycopg2.connect(dsn) as conn:
        cur = conn.cursor()
        for stmt in ("SELECT * FROM voalack.begin_observation(gen_random_uuid(), 'x', 'x', 1, gen_random_uuid())",
                     "SELECT count(*) FROM voalack.source_observations",
                     "SELECT voalack.observation_status('x')"):
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute(stmt)
            conn.rollback()


def test_the_sender_cannot_read_or_write_observation_tables_directly(app):
    from conftest import SENDER_DSN
    with psycopg2.connect(SENDER_DSN) as conn:
        cur = conn.cursor()
        for stmt in ("SELECT count(*) FROM voalack.source_observations",
                     "SELECT count(*) FROM voalack.observation_evidence",
                     "INSERT INTO voalack.observation_evidence (obs_id, kind) VALUES (gen_random_uuid(), 'refused')"):
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute(stmt)
            conn.rollback()


def test_observation_records_are_immutable(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    _record(owner, obs, summary())
    for table in ("observation_reads", "observation_completions", "source_observations", "observation_chains"):
        with pytest.raises(psycopg2.Error):
            sql(f"UPDATE voalack.{table} SET alert_id = alert_id" if table != "observation_completions"
                else "UPDATE voalack.observation_completions SET result = result", fetch=False)


# --- separation from S1 and the admission snapshot ------------------------------------------------------

OBSERVER_FUNCTIONS = {"begin_observation", "record_observation", "observation_status", "_observation_refusal",
                      "_observation_class", "_observation_invalid", "_observation_lines"}


def test_only_observer_functions_read_observation_tables(app):
    """No settlement, recovery, capture, intent, event or projection function body names an observation
    relation; observations confer no authority anywhere else."""
    rows = sql("SELECT n.nspname, p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
               "WHERE n.nspname IN ('voalack', 'voalack_publication') "
               "AND p.prosrc ~ '(observation_reads|observation_completions|source_observations|observation_evidence|observation_chains)'")
    assert {r[1] for r in rows} <= OBSERVER_FUNCTIONS, rows
    deps = sql("SELECT DISTINCT c.relname FROM pg_depend d JOIN pg_class c ON c.oid = d.refobjid "
               "JOIN pg_class o ON o.oid = d.objid WHERE c.relname IN ('observation_reads', 'observation_completions', "
               "'source_observations', 'observation_evidence', 'observation_chains') AND o.relkind IN ('v', 'm')")
    assert deps == []                                                       # no view exposes them


def test_a_holder_committed_before_the_admission_snapshot_refuses(client, app, instance, fake):
    """[sql] C1/r3a: a dispatched attempt on the key committed between reservation and record is refused at
    the record's single admission statement; nothing is stored."""
    from test_t04_s3b_settlement import _lab_holder
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    attempt_id = sql("SELECT attempt_id::text FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (effect_id,))[0][0]
    _enable(instance)
    observer = _successor(instance, fake, owner, quiesce=False)
    obs, row = _begin(observer, alert_id)
    assert row["outcome"] == "reserved", row
    _lab_holder(attempt_id)                                                 # committed before the record
    rec = _record(observer, obs, summary())
    assert (rec["outcome"], rec["r_result"]) == ("recorded", "refused:target_held"), rec
    assert _rows("source_observations", alert_id) == 0


def test_attempts_on_another_target_are_never_eligible(client, app, instance, fake):
    """[sql] eligibility is bound to the exact physical key: a confirmed attempt on 4712 is not a tuple of an
    observation of 4711."""
    effect_id = _effect(client, app, instance, target_id="4712")
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    _enable(instance)
    observer = _successor(instance, fake, owner, quiesce=False)
    alert_id = new_alert(client, instance_id=instance)                       # bound to 4711
    obs, row = _begin(observer, alert_id)
    assert row["outcome"] == "reserved", row
    assert sql("SELECT eligible FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0][0] == []


def test_client_times_are_stored_exactly_as_reported(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    now = datetime.now(timezone.utc)
    started, completed = now, now + timedelta(microseconds=7)
    _record(owner, obs, summary(), started=started, completed=completed)
    got = sql("SELECT client_read_started_at, client_read_completed_at, recorded_at > client_read_completed_at "
              "FROM voalack.observation_completions WHERE obs_id = %s", (obs,))[0]
    assert (got[0], got[1]) == (started, completed) and got[2] is True


def _waiting_on(holder_cursor, seconds=5.0):
    """[native] The pid of a backend that pg_stat_activity shows in a Lock wait inside an observer function, with
    the holder's backend among its pg_blocking_pids; None if no such wait is seen within ``seconds``. Row locks
    are waited on as the holder's transaction id, so the relation is not identified here: the caller's setup fixes
    the one row the holder has locked, and the caller compares the returned pid with its worker's own backend."""
    import time as _time
    holder_cursor.execute("SELECT pg_backend_pid()")
    row = holder_cursor.fetchone()
    holder = row[0] if isinstance(row, tuple) else next(iter(row.values()))
    limit = _time.monotonic() + seconds
    while _time.monotonic() < limit:
        rows = sql("SELECT a.pid FROM pg_stat_activity a WHERE a.wait_event_type = 'Lock' "
                   "AND %s = ANY(pg_blocking_pids(a.pid)) AND a.query ~ %s",
                   (holder, "begin_observation|record_observation"))
        if rows:
            return rows[0][0]
        _time.sleep(0.05)
    return None


def _native_worker(statement, args, out):
    """A thread that runs ``statement`` on its own sender connection and records its backend pid, its result or
    its exception (class, SQLSTATE and constraint name), so an error is a reported result, never a missing key."""
    import threading
    import psycopg2.extras
    from conftest import SENDER_DSN

    def run():
        try:
            with psycopg2.connect(SENDER_DSN) as conn:
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute("SELECT pg_backend_pid() AS pid")
                out["pid"] = cur.fetchone()["pid"]
                cur.execute(statement, args)
                out["row"] = cur.fetchone()
        except Exception as exc:                                            # reported, asserted by the caller
            diag = getattr(exc, "diag", None)
            out["error"] = (f"{type(exc).__name__} sqlstate={getattr(exc, 'pgcode', None)} "
                            f"constraint={getattr(diag, 'constraint_name', None)}: {str(exc).splitlines()[0] if str(exc) else ''}")
    return threading.Thread(target=run)


def _finish(holder_conn, worker, out):
    """Release the holder (commit if it is still open and healthy, else close) and join the worker, so a failed
    wait assertion never leaves a blocked backend or a live thread behind."""
    try:
        if not holder_conn.closed:
            holder_conn.close()
    finally:
        if worker.ident is not None:
            worker.join(10)
    assert not worker.is_alive(), "the worker never finished"
    assert "error" not in out, out["error"]


def _record_after_forced_wait(owner, obs, change, alert_id):
    """[native] r3a §2 oracle: an administrator transaction holds the chain row FOR UPDATE; the record (a worker
    with its own backend) waits on it after its earlier locks; the competing change commits during that wait; the
    lock is released; the record's single admission statement then takes its snapshot after the wait and must see
    the change. The oracle is the observed wait of that exact backend, not elapsed time."""
    admin = psycopg2.connect(DSN)
    cur = admin.cursor()
    out = {}
    worker = _native_worker(RECORD, (obs, owner.instance_id, owner.generation, owner.incarnation,
                                     json.dumps(summary()), datetime.now(timezone.utc).isoformat(),
                                     (datetime.now(timezone.utc) + timedelta(microseconds=1)).isoformat()), out)
    try:
        cur.execute("SELECT 1 FROM voalack.observation_chains c JOIN voalack.observation_reads r "
                    "ON (c.instance_id, c.target_kind, c.target_id, c.alert_id, c.binding_id, c.binding_revision) "
                    "= (r.instance_id, r.target_kind, r.target_id, r.alert_id, r.binding_id, r.binding_revision) "
                    "WHERE r.obs_id = %s FOR UPDATE OF c", (obs,))
        assert cur.rowcount == 1
        worker.start()
        waiter = _waiting_on(cur)
        assert waiter is not None and waiter == out.get("pid"), ("the record never waited on the held chain row",
                                                                waiter, out)
        assert worker.is_alive()
        change()                                                            # committed during the wait
        admin.commit()                                                      # release
    finally:
        _finish(admin, worker, out)
    return out["row"]


def test_admission_snapshot_follows_a_forced_lock_wait_for_a_holder(client, app, instance, fake):
    from test_t04_s3b_settlement import _lab_holder
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    attempt_id = sql("SELECT attempt_id::text FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (effect_id,))[0][0]
    _enable(instance)
    observer = _successor(instance, fake, owner, quiesce=False)
    obs, row = _begin(observer, alert_id)
    assert row["outcome"] == "reserved"
    rec = _record_after_forced_wait(observer, obs, lambda: _lab_holder(attempt_id), alert_id)
    assert (rec["outcome"], rec["r_result"]) == ("recorded", "refused:target_held"), rec
    assert _rows("source_observations", alert_id) == 0


def test_admission_snapshot_follows_a_forced_lock_wait_for_a_competing_binding(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, row = _begin(owner, alert_id)
    assert row["outcome"] == "reserved"
    rec = _record_after_forced_wait(owner, obs, lambda: new_alert(client, instance_id=instance), alert_id)
    assert (rec["outcome"], rec["r_result"]) == ("recorded", "refused:ambiguous_target"), rec
    assert _rows("source_observations", alert_id) == 0



# --- corrections to the S1 checkpoint review: NULL-safe validation, combinations, global id, readiness --------

TYPED = ["acked", "comment", "operation", "operation_status", "children", "marker", "response_target_kind",
         "response_target_id"]


@pytest.mark.parametrize("field", TYPED)
@pytest.mark.parametrize("shape", ["empty", "missing_state", "null_state"])
def test_empty_or_stateless_typed_fields_are_rejected(client, app, instance, fake, field, shape):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    s = summary()
    s[field] = {"empty": {}, "missing_state": {"value": "x"}, "null_state": {"state": None}}[shape]
    rec = _record(owner, obs, s)
    assert rec["outcome"] == "bad_summary", rec
    assert sql("SELECT kind, reason FROM voalack.observation_evidence WHERE obs_id = %s", (obs,)) == \
        [("bad_summary", field)]
    assert sql("SELECT count(*) FROM voalack.observation_completions WHERE obs_id = %s", (obs,))[0][0] == 0
    assert _rows("source_observations", alert_id) == 0


def test_an_empty_field_on_replay_returns_the_original_result(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    first = _record(owner, obs, summary())
    assert first["r_result"] == "stored"
    bad = _record(owner, obs, {**summary(), "acked": {}})
    assert (bad["outcome"], bad["r_result"], bad["r_classification"]) == ("already_recorded", "stored", "not_acked")
    assert sql("SELECT kind, reason FROM voalack.observation_evidence WHERE obs_id = %s", (obs,)) == \
        [("bad_summary", "acked")]


@pytest.mark.parametrize("marker", ["valid", "malformed"])
@pytest.mark.parametrize("comment", ["absent", "invalid"])
def test_a_marker_needs_a_string_comment(client, app, instance, fake, marker, comment):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    m = {"state": "valid", "action_id": str(uuid.uuid4())} if marker == "valid" else {"state": "malformed"}
    rec = _record(owner, obs, summary(**ACKED, comment={"state": comment}, marker=m))
    assert rec["outcome"] == "bad_summary", rec
    assert sql("SELECT reason FROM voalack.observation_evidence WHERE obs_id = %s", (obs,)) == [("combination",)]


def test_concurrent_begins_of_one_observation_id_both_commit_a_result(client, app, instance, fake):
    """[native] the observation id is global: a second begin of the same id on the same chain waits (on the
    chain row the first holds), then meets the first's committed primary key and gets the committed
    already_reserved refusal with no target, never an error; exactly one reservation exists."""
    import psycopg2.extras
    from conftest import SENDER_DSN
    alert_id, owner = _bound(client, instance, fake)
    obs = str(uuid.uuid4())
    args = (obs, alert_id, owner.instance_id, owner.generation, owner.incarnation)
    a = psycopg2.connect(SENDER_DSN)
    cur = a.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    out = {}
    worker = _native_worker(BEGIN, args, out)
    try:
        cur.execute(BEGIN, args)
        assert cur.fetchone()["outcome"] == "reserved"                 # uncommitted
        worker.start()
        waiter = _waiting_on(cur)
        assert waiter is not None and waiter == out.get("pid"), ("the second begin never waited", waiter, out)
        assert worker.is_alive()
        a.commit()
    finally:
        _finish(a, worker, out)
    assert (out["row"]["outcome"], out["row"]["r_target_kind"], out["row"]["r_target_id"]) == \
        ("already_reserved", None, None), out
    assert sql("SELECT count(*) FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0][0] == 1


def test_reservations_freeze_the_owners_epoch_and_head(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    assert sql("SELECT r.acquired_epoch = o.acquired_epoch AND r.acquired_head_sha256 = o.acquired_head_sha256 "
               "FROM voalack.observation_reads r JOIN voalack.session_owners o USING (instance_id) "
               "WHERE r.obs_id = %s", (obs,)) == [(True,)]


def test_status_reports_the_latest_state_per_chain(client, app, instance, fake):
    alert_id, owner = _bound(client, instance, fake)
    for s in (summary(), summary(**ACKED)):
        obs, _ = _begin(owner, alert_id)
        _record(owner, obs, s)
    status = sql("SELECT voalack.observation_status(%s)", (alert_id,))[0][0]
    assert [c["classification"] for c in status["chains"]] == ["acked_unattributed"]
    assert status["completions"] == {"stored": 2}


@pytest.mark.parametrize("drift", ["disabled", "dropped", "insert_too"])
def test_sender_readiness_requires_the_observer_flag_fence(app, drift):
    from conftest import SENDER_DSN
    from voalack import sender, verifier
    setup = {"disabled": "ALTER TABLE voalack.instance_config DISABLE TRIGGER instance_config_observer_bump",
             "dropped": "DROP TRIGGER instance_config_observer_bump ON voalack.instance_config",
             "insert_too": "DROP TRIGGER instance_config_observer_bump ON voalack.instance_config; "
                           "CREATE TRIGGER instance_config_observer_bump BEFORE INSERT OR UPDATE ON "
                           "voalack.instance_config FOR EACH ROW EXECUTE FUNCTION voalack._observer_flag_bump()"}[drift]
    restore = ("DROP TRIGGER IF EXISTS instance_config_observer_bump ON voalack.instance_config; "
               "CREATE TRIGGER instance_config_observer_bump BEFORE UPDATE ON voalack.instance_config "
               "FOR EACH ROW EXECUTE FUNCTION voalack._observer_flag_bump()")
    with psycopg2.connect(SENDER_DSN) as conn:
        verifier.check_ready(conn, sender.SENDER)                       # as installed
    sql(setup, fetch=False)
    try:
        with psycopg2.connect(SENDER_DSN) as conn:
            with pytest.raises(verifier.NotReady, match="before_update_drift"):
                verifier.check_ready(conn, sender.SENDER)
    finally:
        sql(restore, fetch=False)
    with psycopg2.connect(SENDER_DSN) as conn:
        verifier.check_ready(conn, sender.SENDER)                       # restored


def test_sender_readiness_requires_the_observer_uniqueness(app):
    from conftest import SENDER_DSN
    from voalack import sender, verifier
    sql("ALTER TABLE voalack.observation_reads DROP CONSTRAINT observation_reads_reservation_seq_key", fetch=False)
    try:
        with psycopg2.connect(SENDER_DSN) as conn:
            with pytest.raises(verifier.NotReady, match="uniqueness_drift"):
                verifier.check_ready(conn, sender.SENDER)
    finally:
        sql("ALTER TABLE voalack.observation_reads ADD CONSTRAINT observation_reads_reservation_seq_key "
            "UNIQUE (reservation_seq)", fetch=False)


def test_one_observation_id_on_two_chains_reserves_once(client, app, instance, fake):
    """[native] the global id conflict, not a chain lock: A reserves id X on alert 1 and holds its transaction; B
    begins X on alert 2 (another chain, another key), blocks on A's uncommitted primary key, and after A commits
    gets the committed already_reserved with no target, never an error; exactly one reservation row exists for X."""
    import psycopg2.extras
    from conftest import SENDER_DSN
    _enable(instance)
    one = new_alert(client, instance_id=instance, target_id="4711")
    two = new_alert(client, instance_id=instance, target_id="4712")
    owner = _owner(instance, fake)
    obs = str(uuid.uuid4())
    a = psycopg2.connect(SENDER_DSN)
    cur = a.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    out = {}
    worker = _native_worker(BEGIN, (obs, two, instance, owner.generation, owner.incarnation), out)
    try:
        cur.execute(BEGIN, (obs, one, instance, owner.generation, owner.incarnation))
        assert cur.fetchone()["r_target_id"] == "4711"
        worker.start()
        waiter = _waiting_on(cur)
        assert waiter is not None and waiter == out.get("pid"), ("the second begin never waited on the id",
                                                                waiter, out)
        assert worker.is_alive()
        a.commit()
    finally:
        _finish(a, worker, out)
    assert (out["row"]["outcome"], out["row"]["r_target_kind"], out["row"]["r_target_id"]) == \
        ("already_reserved", None, None), out
    assert sql("SELECT alert_id FROM voalack.observation_reads WHERE obs_id = %s", (obs,)) == [(one,)]


def test_a_changed_acquisition_pin_refuses_the_record(client, app, instance, fake):
    """r2 B1, aggregate fencing witness: a changed acquisition pin on the owner row (here by the lab administrator)
    refuses the record as owner_fenced and stores nothing. It may be refused by _owner_fenced before the saved-pin
    comparison; the distinct saved-versus-current comparison (reachable only across a restore) is an S3 witness."""
    alert_id, owner = _bound(client, instance, fake)
    obs, _ = _begin(owner, alert_id)
    sql("UPDATE voalack.session_owners SET acquired_head_sha256 = %s WHERE instance_id = %s", ("f" * 64, instance),
        fetch=False)
    rec = _record(owner, obs, summary())
    assert (rec["outcome"], rec["r_result"]) == ("recorded", "refused:owner_fenced"), rec
    assert _rows("source_observations", alert_id) == 0
