"""T04 S3b: read-only reconciliation of uncertain attempts, guarded settlement and the settler role.

Labels: [native] real PostgreSQL transactions, row locks, roles and constraints; [fake] fake ONE
provider behaviour (synthetic contract fake-one/v1, S3b additions frozen in fake_one.py); [lab]
administrator-attested containment and quiescence (the database checks presence, coverage, binding
and ordering, not the facts) and lab-constructed rows; [scripted] Python hooks. Every reconciliation
case asserts zero ACK connects and writes for the reading owner.
"""
import hashlib
import json
import os
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone

import psycopg2
import psycopg2.errors
import psycopg2.extras
import pytest

from conftest import APP_DSN, DSN, SENDER_DSN, VERIFIER_DSN, sql
from test_t04_s2_sender import _call, _contain, _effect, _guards, _owner, fake, instance  # noqa: F401
from test_t04_s3a_transport import _phase
from voalack import schema, sender, settler, verifier
from voalack.sender import UnknownCommit

SETTLER_DSN = os.environ.get("VOALACK_LAB_SETTLER_DSN", "postgres://lab_settler:lab-only-settler@localhost/alerta")
S3A_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "schema_s3a_e471642.sql")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _uncertain(client, app, instance, fake, owner=None, mode="close_after_body", **kwargs):
    """One effect whose single attempt is uncertain. close_after_body: the fake applied it;
    close_before_body: the fake never processed it (no receipt)."""
    effect_id = _effect(client, app, instance, **kwargs)
    owner = owner or _owner(instance, fake)
    fake.script["ack"] = mode
    result = owner.apply_once(effect_id)
    fake.script["ack"] = "success"
    assert result["outcome"] == "uncertain", result
    return effect_id, result["attempt_id"], owner


def _effect_row(effect_id):
    return sql("SELECT state, in_flight_attempt IS NOT NULL FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0]


def _settlements(attempt_id):
    return sql("SELECT outcome, path, effect_state, decided_by FROM voalack.settlements WHERE attempt_id = %s",
               (attempt_id,))


def _reconciliation(rid):
    return sql("SELECT classification, original_generation, original_incarnation::text, reader_generation, "
               "reader_incarnation::text, target_id, read_started_at IS NOT NULL FROM voalack.reconciliations "
               "WHERE reconciliation_id = %s", (rid,))[0]


def _comment(attempt_id):
    return sql("SELECT convert_from(request_bytes, 'UTF8')::jsonb->>'comment' FROM voalack.attempts "
               "WHERE attempt_id = %s", (attempt_id,))[0][0]


def _lab(fake, method, path):
    request = urllib.request.Request(fake.url + path, method=method, data=b"{}" if method == "POST" else None,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read() or b"null")


def _sessions(instance, owner):
    return [r[0] for r in sql("SELECT session_ref FROM voalack.provider_sessions WHERE instance_id = %s "
                              "AND owner_generation = %s AND incarnation = %s ORDER BY opened_at",
                              (instance, owner.generation, owner.incarnation))]


def _quiescence_evidence(fake, refs):
    """[lab] The administrator revokes every registered session of the holder, then observes each
    session's executing count at the provider (exact session scope)."""
    sessions = []
    for ref in refs:
        status, _ = _lab(fake, "POST", f"/lab/sessions/{ref}/revoke")
        revoke = {"status": status, "observed_at": _now()}
        time.sleep(0.002)
        status, seen = _lab(fake, "GET", f"/lab/sessions/{ref}/executing")
        sessions.append({"session_ref": ref, "revoke": revoke,
                         "executing": {"status": status, "session_ref": seen["session_ref"], "scope": seen["scope"],
                                       "executing": seen["executing"], "live": seen["live"],
                                       "observed_at": _now()}})
    return {"process": {"label": "lab OwnerSession (same OS process)", "exit_observed_at": _now()},
            "sessions": sessions, "basis": "lab: fake provider session view"}


def _record_quiescence(instance, owner, evidence):
    return sql("SELECT voalack.record_quiescence(%s, %s, %s, %s::jsonb)",
               (instance, owner.generation, owner.incarnation, json.dumps(evidence)))[0][0]


def _quiesce(instance, owner, fake):
    return _record_quiescence(instance, owner, _quiescence_evidence(fake, _sessions(instance, owner)))


def _successor(instance, fake, original, quiesce=True):
    """Stop and contain the original; optionally record its quiescence; acquire a successor."""
    original.stop("lab: original stopped")
    _contain(instance, original.generation)
    if quiesce:
        _quiesce(instance, original, fake)
    return _owner(instance, fake, owner_id="lab-successor")


def _no_ack_traffic(owner):
    return (owner.transport.phase_counts["ack_connects"], owner.transport.counts["ack_writes"]) == (0, 0)


def _wait_effects(fake, n, seconds=5):
    limit = time.monotonic() + seconds
    while fake.counts["effects"] < n and time.monotonic() < limit:
        time.sleep(0.02)
    return fake.counts["effects"] >= n


# --- sessions (B1) ----------------------------------------------------------------------------------

def test_every_session_is_registered_by_digest_before_use(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    refs = _sessions(instance, owner)
    assert refs == [hashlib.sha256(owner.token.encode()).hexdigest()]
    assert owner.token not in json.dumps(sql("SELECT row_to_json(p) FROM voalack.provider_sessions p"))
    owner.revoke()
    owner.login()
    assert len(_sessions(instance, owner)) == 2                         # a new session is registered too
    assert _call("SELECT voalack.register_session(%s, %s, %s, %s) AS o",
                 ("a" * 64, instance, owner.generation + 1, owner.incarnation))["o"] == "owner_fenced"


# --- reconciliation by the original live owner (A3, B2, B3) ---------------------------------------

def test_late_completion_is_reconciled_then_settled_by_attribution(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    owner.transport.timeout = 0.5
    fake.script["delay"] = 1.5                                   # [fake] the ACK completes later
    result = owner.apply_once(effect_id)
    assert result["outcome"] == "uncertain", result
    early = owner.reconcile(result["attempt_id"])                # read while the request still executes
    assert (early["outcome"], early["classification"]) == ("recorded", "not_acked"), early
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    assert _wait_effects(fake, 1)
    late = owner.reconcile(result["attempt_id"])
    assert (late["outcome"], late["classification"], late["settlement"]) == ("settled", "attributable", "settled")
    assert _effect_row(effect_id) == ("REMOTE_CONFIRMED", False) and _guards(instance) == []
    assert _settlements(result["attempt_id"]) == [("confirmed_attributed", "automatic", "REMOTE_CONFIRMED",
                                                   "lab_sender")]
    assert sql("SELECT state FROM voalack.attempts WHERE attempt_id = %s", (result["attempt_id"],)) == [("uncertain",)]
    assert owner.transport.counts["ack_writes"] == owner.transport.phase_counts["ack_connects"] == 1
    assert fake.counts["receipts"] == fake.counts["effects"] == 1 and fake.read_targets[-2:] == ["4711", "4711"]
    assert _reconciliation(late["reconciliation_id"])[6] is True          # adapter read timing recorded


def test_attribution_relies_on_the_completed_publication_not_on_request_exit(client, app, instance, fake):
    """[fake] The alarm is published (completed) while the request still holds its executing slot."""
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    owner.transport.timeout = 0.3
    fake.script["post_publish_delay"] = 1.5
    result = owner.apply_once(effect_id)
    assert result["outcome"] == "uncertain"
    assert _wait_effects(fake, 1)
    assert fake.executing == 1                                   # the request has not finished
    done = owner.reconcile(result["attempt_id"])
    assert (done["classification"], done["outcome"]) == ("attributable", "settled"), done
    published = dict(fake.alarms["4711"])
    limit = time.monotonic() + 5
    while fake.executing and time.monotonic() < limit:
        time.sleep(0.02)
    assert fake.alarms["4711"] == published and fake.counts["effects"] == 1   # no later mutation


@pytest.mark.parametrize("read, alarm, expected", [
    ("normal", None, "attributable"),
    ("error", None, "evidence_only"),                 # a matching body on 500 is evidence only
    ("wrong_target", None, "evidence_only"),
    ("ambiguous", None, "evidence_only"),
    ("grouped", None, "evidence_only"),
    ("no_kind", None, "evidence_only"),
    ("no_completion", None, "evidence_only"),         # our operation without the completion marker
    ("comment", None, "evidence_only"),               # our operation id, another comment
    ("normal", "other_operation", "acked_by_other"),  # a valid different operation identity
    ("normal", "malformed_operation", "evidence_only"),
    ("normal", "empty_operation", "evidence_only"),
    ("normal", "unattributed", "acked_unattributed"),
    ("normal", "null_operation", "acked_unattributed"),
    ("normal", "unattributed_other_comment", "evidence_only"),
    ("normal", "not_acked", "not_acked"),
    ("normal", "not_acked_with_operation", "evidence_only"),
])
def test_classification_is_strict_and_only_attribution_settles_automatically(client, app, instance, fake,
                                                                             read, alarm, expected):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    if read == "comment":
        fake.script["read_back"] = "mismatch"
    else:
        fake.script["read"] = read
    base = {"target_id": "4711", "kind": "triggered_alarm", "acked": True}
    variants = {
        "other_operation": {"acked_by_operation": "f" * 64, "comment": "someone else"},
        "malformed_operation": {"acked_by_operation": "someone-else", "comment": _comment(attempt_id)},
        "empty_operation": {"acked_by_operation": "", "comment": _comment(attempt_id)},
        "unattributed": {"comment": _comment(attempt_id)},
        "null_operation": {"acked_by_operation": None, "comment": _comment(attempt_id)},
        "unattributed_other_comment": {"comment": "another comment"},
        "not_acked": {"acked": False},
        "not_acked_with_operation": {"acked": False, "acked_by_operation": "f" * 64},
    }
    if alarm is not None:
        fake.alarms["4711"] = {**base, **variants[alarm]}
    before = _phase(owner, fake)
    result = owner.reconcile(attempt_id)
    assert result["classification"] == expected, result
    assert _phase(owner, fake) == before                         # no ACK connect, write or receipt
    if expected == "attributable":
        assert result["outcome"] == "settled" and _effect_row(effect_id) == ("REMOTE_CONFIRMED", False)
    else:
        assert result["outcome"] == "recorded" and _effect_row(effect_id) == ("UNCERTAIN", True)
        assert _guards(instance) == [("4711", "uncertain")] and _settlements(attempt_id) == []


def _reserve(owner, attempt_id, read_id=None):
    read_id = read_id or str(uuid.uuid4())
    row = _call("SELECT * FROM voalack.begin_reconciliation(%s, %s, %s, %s, %s)",
                (read_id, attempt_id, owner.instance_id, owner.generation, owner.incarnation))
    return read_id, row


def _record(owner, read_id, observation):
    return _call("SELECT * FROM voalack.record_reconciliation(%s, %s, %s, %s, %s::jsonb)",
                 (read_id, owner.instance_id, owner.generation, owner.incarnation, json.dumps(observation)))


@pytest.mark.parametrize("change", ["status_text", "acked_text", "read_before_reservation", "no_read_time",
                                    "operation_number"])
def test_classification_refuses_coerced_or_mistimed_observations(client, app, instance, fake, change):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    read_id, row = _reserve(owner, attempt_id)
    assert row["outcome"] == "reserved"
    alarm = dict(fake.alarms["4711"])
    observation = {"kind": "reconciliation_read", "status": 200, "alarm": alarm, "read_started_at": _now(),
                   "read_completed_at": _now()}
    if change == "status_text":
        observation["status"] = "200"
    elif change == "acked_text":
        alarm["acked"] = "true"
    elif change == "read_before_reservation":
        observation["read_started_at"] = "2000-01-01T00:00:00+00:00"
    elif change == "no_read_time":
        observation.pop("read_started_at")
    else:
        alarm["acked_by_operation"] = 7
    assert _record(owner, read_id, observation)["r_classification"] == "evidence_only"


def test_read_ids_are_idempotent_records_never_fresh_reads(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    read_id, row = _reserve(owner, attempt_id)
    assert row["outcome"] == "reserved"
    assert _reserve(owner, attempt_id, read_id)[1]["outcome"] == "already_reserved"   # no second read
    observation = {"kind": "reconciliation_read", "status": 200, "alarm": dict(fake.alarms["4711"]),
                   "read_started_at": _now(), "read_completed_at": _now()}
    first = _record(owner, read_id, observation)
    assert (first["outcome"], first["r_classification"]) == ("recorded", "attributable")
    assert _record(owner, read_id, observation) == first                              # exact duplicate
    changed = {**observation, "alarm": {**observation["alarm"], "acked": False}}
    conflict = _record(owner, read_id, changed)
    assert (conflict["outcome"], conflict["r_reconciliation_id"], conflict["r_classification"]) == \
        ("already_recorded", first["r_reconciliation_id"], "attributable")          # first record kept
    assert sql("SELECT count(*) FROM voalack.attempt_evidence WHERE attempt_id = %s "
               "AND kind = 'conflicting_reconciliation'", (attempt_id,))[0][0] == 1
    assert sql("SELECT count(*) FROM voalack.reconciliations WHERE read_id = %s", (read_id,))[0][0] == 1


def test_reconciliation_reads_the_attempts_original_target(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    sql("UPDATE voalack.effects SET target_id = '4799' WHERE effect_id = %s", (effect_id,), fetch=False)   # lab drift
    result = owner.reconcile(attempt_id, settle=False)
    assert result["classification"] == "attributable" and fake.read_targets[-1] == "4711"
    assert _reconciliation(result["reconciliation_id"])[5] == "4711"


def test_refused_reservations_use_no_credential_or_network(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    assert owner.reconcile(attempt_id)["outcome"] == "settled"
    reads, logins = fake.counts["reads"], fake.counts["logins"]
    assert owner.reconcile(attempt_id)["reason"] == "not_uncertain"
    assert owner.reconcile(str(uuid.uuid4()))["reason"] == "no_attempt"
    other = f"{instance}-x"
    sql("INSERT INTO voalack.instance_config VALUES (%s, %s, 'fake-one/v1', 1)", (other, f"cred-{other}"), fetch=False)
    stranger = _owner(other, fake, owner_id="lab-stranger")
    assert stranger.reconcile(attempt_id)["reason"] == "wrong_instance"
    assert stranger.stopped is None                              # another owner's attempt: no fence implied
    assert (fake.counts["reads"], fake.counts["logins"]) == (reads, logins)


def test_owner_fenced_at_reservation_stops_the_owner_after_a_native_wait(client, app, instance, fake):
    """Review 886865d6 (P2): an owner transition that the reservation waits for and then observes
    stops the whole owner locally, with no later login, read, ACK or revoke from any entry point."""
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    other = _effect(client, app, instance, target_id="4712")
    admin = psycopg2.connect(DSN)
    admin.cursor().execute("UPDATE voalack.session_owners SET state = 'suspended' WHERE instance_id = %s",
                           (instance,))      # [native] uncommitted: check_owner (MVCC read) still sees active
    timer = threading.Timer(0.6, lambda: (admin.commit(), admin.close()))
    timer.start()
    before = dict(fake.counts)
    started = time.monotonic()
    result = owner.reconcile(attempt_id)     # the reservation's FOR SHARE waits, then sees suspended
    timer.join()
    assert (result["outcome"], result["reservation"]) == ("refused", "owner_fenced"), result
    assert owner.stopped == "owner_fenced" and time.monotonic() - started >= 0.5
    assert owner.reconcile(attempt_id)["outcome"] == "held"
    for call in (lambda: owner.apply_once(other), owner.login, owner.revoke):
        with pytest.raises(sender.OwnerStopped):
            call()                                                    # the local stop persists
    assert fake.counts == before and owner.transport.counts["ack_writes"] == 1   # the original ACK only
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and ("4711", "uncertain") in _guards(instance)
    assert sql("SELECT count(*) FROM voalack.reconciliation_reads WHERE attempt_id = %s", (attempt_id,))[0][0] == 0


@pytest.mark.parametrize("failure", ["login", "read"])
def test_provider_failure_after_reservation_is_recorded_as_evidence_only(client, app, instance, fake, failure):
    """Bot review on 1b24d36 (P2): a login (or read) failure after the reservation committed returns a
    structured result and records the reservation as evidence only; it neither raises nor stops."""
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    if failure == "login":
        owner.token = None                                       # the read needs a fresh session
        fake.script["login"] = "fail"
    else:
        fake.script["read"] = "error"
    reads = fake.counts["reads"]
    result = owner.reconcile(attempt_id)
    assert (result["outcome"], result["classification"]) == ("recorded", "evidence_only"), result
    assert owner.stopped is None and _settlements(attempt_id) == []
    assert fake.counts["reads"] == reads + (0 if failure == "login" else 1)
    observation = sql("SELECT observation FROM voalack.reconciliations WHERE reconciliation_id = %s",
                      (result["reconciliation_id"],))[0][0]
    assert observation["error"].startswith("login_failed:") if failure == "login" else observation["status"] == 500
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    fake.script["login"] = None
    fake.script["read"] = "normal"
    assert owner.reconcile(attempt_id)["outcome"] == "settled"            # a later reservation may succeed


# --- successor identities and holders (A3, B1) -------------------------------------------------------

def test_successor_reconciles_under_original_and_reader_identities(client, app, instance, fake):
    effect_id, attempt_id, original = _uncertain(client, app, instance, fake)
    successor = _successor(instance, fake, original, quiesce=False)
    reads = fake.counts["reads"]
    assert original.reconcile(attempt_id)["outcome"] == "held"  # a stopped original does not resume
    assert fake.counts["reads"] == reads
    result = successor.reconcile(attempt_id)
    assert (result["outcome"], result["classification"]) == ("settled", "attributable"), result
    assert _reconciliation(result["reconciliation_id"])[1:5] == (original.generation, original.incarnation,
                                                                 successor.generation, successor.incarnation)
    assert _no_ack_traffic(successor) and _effect_row(effect_id) == ("REMOTE_CONFIRMED", False)


def _lab_holder(attempt_id, generation=999):
    """[lab] A dispatched attempt on the same physical key by another holder (generation, incarnation)."""
    incarnation = str(uuid.uuid4())
    sql("INSERT INTO voalack.attempts (attempt_id, effect_id, action_id, instance_id, credential_ref, "
        "provider_contract, config_revision, owner_generation, incarnation, target_kind, target_id, request_bytes, "
        "request_sha256, permit_state, state, dispatched_at) "
        "SELECT %s, effect_id, action_id, instance_id, credential_ref, provider_contract, config_revision, %s, %s, "
        "target_kind, target_id, request_bytes, request_sha256, 'consumed', 'dispatched', now() "
        "FROM voalack.attempts WHERE attempt_id = %s", (str(uuid.uuid4()), generation, incarnation, attempt_id),
        fetch=False)
    return generation, incarnation


def test_uncontained_holder_refuses_a_successor_read(client, app, instance, fake):
    effect_id, attempt_id, original = _uncertain(client, app, instance, fake)
    successor = _successor(instance, fake, original, quiesce=False)
    _lab_holder(attempt_id)
    reads = fake.counts["reads"]
    assert successor.reconcile(attempt_id)["reason"] == "holder_not_contained"
    assert fake.counts["reads"] == reads and _effect_row(effect_id) == ("UNCERTAIN", True)


# --- configuration and owner drift, database loss, unknown COMMIT (B2, B4, B5) --------------------

def _drift_after_wait(instance, kind, delay=0.6):
    """[native] An administrator transaction locks the instance configuration (or owner) row, changes
    it and commits after ``delay``; the caller's FOR SHARE waits for it."""
    admin = psycopg2.connect(DSN)
    if kind == "config":
        admin.cursor().execute("UPDATE voalack.instance_config SET config_revision = config_revision + 1 "
                               "WHERE instance_id = %s", (instance,))
    else:
        admin.cursor().execute("UPDATE voalack.session_owners SET state = 'suspended' WHERE instance_id = %s",
                               (instance,))
    timer = threading.Timer(delay, lambda: (admin.commit(), admin.close()))
    timer.start()
    return timer


@pytest.mark.parametrize("kind, expected", [("config", "config_changed"), ("owner", "owner_fenced")])
@pytest.mark.parametrize("stage", ["before_record", "before_settle"])
def test_drift_while_recording_or_settling_keeps_the_guard_and_stops(client, app, instance, fake, stage, kind,
                                                                     expected):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    timers = []
    owner.hooks[stage] = lambda _: timers.append(_drift_after_wait(instance, kind))
    started = time.monotonic()
    result = owner.reconcile(attempt_id)
    waited = time.monotonic() - started
    for timer in timers:
        timer.join()
    assert (result["outcome"], result["reason"]) == ("held", expected), result
    assert waited >= 0.5 and owner.stopped == expected
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    assert _settlements(attempt_id) == []
    reads = fake.counts["reads"]
    assert owner.reconcile(attempt_id)["outcome"] == "held" and fake.counts["reads"] == reads   # stays stopped
    if stage == "before_record":
        assert sql("SELECT count(*) FROM voalack.reconciliations WHERE attempt_id = %s", (attempt_id,))[0][0] == 0
        assert sql("SELECT detail->>'reason' FROM voalack.attempt_evidence WHERE attempt_id = %s "
                   "AND kind = 'late_reconciliation'", (attempt_id,)) == [(expected,)]
    else:
        assert sql("SELECT classification FROM voalack.reconciliations WHERE attempt_id = %s",
                   (attempt_id,)) == [("attributable",)]


def test_drift_after_reservation_stops_before_login_or_read(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    owner.token = None                                           # the read would need a fresh login
    owner.hooks["after_reservation"] = lambda _: sql(
        "UPDATE voalack.instance_config SET config_revision = config_revision + 1 WHERE instance_id = %s",
        (instance,), fetch=False)
    logins, reads = fake.counts["logins"], fake.counts["reads"]
    result = owner.reconcile(attempt_id)
    assert (result["outcome"], result["reason"]) == ("held", "config_changed")
    assert (fake.counts["logins"], fake.counts["reads"]) == (logins, reads)


def test_database_loss_before_recording_stops_without_a_record(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)

    def kill(_):
        sql("SELECT pg_terminate_backend(%s)", (owner._conn.get_backend_pid(),))   # [native] connection lost
    owner.hooks["before_record"] = kill
    result = owner.reconcile(attempt_id)
    assert (result["outcome"], result["reason"]) == ("held", "database_lost") and owner.stopped == "database_lost"
    assert sql("SELECT count(*) FROM voalack.reconciliations WHERE attempt_id = %s", (attempt_id,))[0][0] == 0
    assert _guards(instance) == [("4711", "uncertain")]


def _commit_then_lost(conn):
    conn.commit()
    raise UnknownCommit("lab: settlement committed, acknowledgement lost")


def _rollback_then_lost(conn):
    conn.rollback()
    raise UnknownCommit("lab: settlement rolled back, acknowledgement lost")


@pytest.mark.parametrize("fault, lookup", [(_commit_then_lost, "committed"), (_rollback_then_lost, "absent")])
def test_unknown_automatic_settlement_commit_stops_and_looks_up_the_same_decision(client, app, instance, fake,
                                                                                  fault, lookup):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    owner.hooks["commit:settle"] = fault
    result = owner.reconcile(attempt_id)
    assert (result["outcome"], result["reason"], result["lookup"]) == ("held", "unknown_settlement_commit", lookup)
    assert owner.stopped == "unknown_settlement_commit"
    reads = fake.counts["reads"]
    assert owner.reconcile(attempt_id)["outcome"] == "held" and fake.counts["reads"] == reads
    assert len(_settlements(attempt_id)) == (1 if lookup == "committed" else 0)
    assert _guards(instance) == ([] if lookup == "committed" else [("4711", "uncertain")])


# --- quiescence (B1) --------------------------------------------------------------------------------

def test_quiescence_is_refused_while_an_old_request_still_executes(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    owner.transport.timeout = 0.3
    fake.script["delay"] = 2.0
    assert owner.apply_once(effect_id)["outcome"] == "uncertain"
    owner.stop("lab: original stopped")
    _contain(instance, owner.generation)
    evidence = _quiescence_evidence(fake, _sessions(instance, owner))
    assert evidence["sessions"][0]["executing"]["executing"] == 1     # [fake] still running after revocation
    with pytest.raises(psycopg2.errors.RaiseException, match="quiescence evidence"):
        _record_quiescence(instance, owner, evidence)
    limit = time.monotonic() + 5
    while fake.executing and time.monotonic() < limit:
        time.sleep(0.05)
    assert _record_quiescence(instance, owner, _quiescence_evidence(fake, _sessions(instance, owner))) > 0


def test_a_request_not_yet_executing_at_revocation_can_never_mutate(client, app, instance, fake):
    """[fake][native] The race between revocation and a request that has not registered as executing:
    after revocation its authentication fails, so executing = 0 after revocation is sufficient."""
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    owner.transport.timeout = 0.3
    gate, arrived = threading.Event(), threading.Event()

    def pause():
        arrived.set()
        gate.wait(10)
    fake.pre_auth = pause
    assert owner.apply_once(effect_id)["outcome"] == "uncertain"      # the request waits before auth
    assert arrived.wait(5)
    owner.stop("lab: original stopped")
    _contain(instance, owner.generation)
    evidence = _quiescence_evidence(fake, _sessions(instance, owner))
    assert evidence["sessions"][0]["executing"]["executing"] == 0
    _record_quiescence(instance, owner, evidence)
    gate.set()
    fake.pre_auth = None
    time.sleep(0.3)
    assert fake.counts["receipts"] == fake.counts["effects"] == 0 and "4711" not in fake.alarms
    successor = _owner(instance, fake, owner_id="lab-successor")
    attempt_id = sql("SELECT attempt_id::text FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]
    rid = successor.reconcile(attempt_id)["reconciliation_id"]
    assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, "retired_after_quiescence", rid,
                          "lab: never executed") == "settled"
    assert _effect_row(effect_id) == ("BLOCKED", False)


@pytest.mark.parametrize("change", ["no_containment", "boolean_only", "revoke_after_observation",
                                    "missing_session", "executing_error", "executing_text", "wrong_scope"])
def test_quiescence_needs_containment_and_complete_ordered_evidence(client, app, instance, fake, change):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    owner.revoke()
    owner.login()                                                # two registered sessions
    owner.stop("lab: original stopped")
    if change != "no_containment":
        _contain(instance, owner.generation)
    evidence = _quiescence_evidence(fake, _sessions(instance, owner))
    first = evidence["sessions"][0]
    if change == "boolean_only":
        evidence = {"process_stopped": True, "no_requests_executing": True, "basis": "lab: booleans"}
    elif change == "revoke_after_observation":
        first["revoke"]["observed_at"] = _now()
    elif change == "missing_session":
        evidence["sessions"] = evidence["sessions"][1:]
    elif change == "executing_error":
        first["executing"]["status"] = 500
    elif change == "executing_text":
        first["executing"]["executing"] = "0"
    else:
        first["executing"]["scope"] = "provider"
    with pytest.raises(psycopg2.errors.RaiseException):
        _record_quiescence(instance, owner, evidence)


# --- operator settlement (A4, B1, B4, B5) -------------------------------------------------------------

def _operator_case(client, app, instance, fake, outcome):
    """An uncertain attempt whose original target then reads as each operator outcome requires."""
    mode = "close_before_body" if outcome == "retired_after_quiescence" else "close_after_body"
    effect_id, attempt_id, original = _uncertain(client, app, instance, fake, mode=mode)
    if outcome == "superseded_remote":
        fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True,
                               "acked_by_operation": "f" * 64, "comment": "someone else"}
    elif outcome == "confirmed_by_operator":
        fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True,
                               "comment": _comment(attempt_id)}
    return effect_id, attempt_id, original


OPERATOR = {"retired_after_quiescence": ("not_acked", "BLOCKED"),
            "superseded_remote": ("acked_by_other", "ALREADY_ACKED"),
            "confirmed_by_operator": ("acked_unattributed", "ALREADY_ACKED")}


@pytest.mark.parametrize("outcome", sorted(OPERATOR))
def test_operator_outcomes_need_quiescence_and_a_later_successor_read(client, app, instance, fake, outcome):
    classification, effect_state = OPERATOR[outcome]
    effect_id, attempt_id, original = _operator_case(client, app, instance, fake, outcome)

    def decide(rid, decision=None, note="lab decision"):
        return settler.settle(SETTLER_DSN, decision or str(uuid.uuid4()), attempt_id, outcome, rid, note)
    own = original.reconcile(attempt_id)                          # the live holder's own read
    assert own["classification"] == classification
    assert decide(own["reconciliation_id"]) == "reader_is_holder"
    successor = _successor(instance, fake, original, quiesce=False)
    assert decide(own["reconciliation_id"]) == "reader_owner_fenced"   # that reader is no longer current
    early = successor.reconcile(attempt_id)                       # contained, not yet quiescent
    assert early["classification"] == classification
    assert decide(early["reconciliation_id"]) == "holder_not_quiescent"
    _quiesce(instance, original, fake)
    assert decide(early["reconciliation_id"]) == "read_before_quiescence"
    later = successor.reconcile(attempt_id)
    assert later["classification"] == classification and later["outcome"] == "recorded"
    decision = str(uuid.uuid4())
    assert decide(later["reconciliation_id"], decision) == "settled"
    assert _effect_row(effect_id) == (effect_state, False) and _guards(instance) == []
    assert _settlements(attempt_id) == [(outcome, "operator", effect_state, "lab_settler")]
    frozen = sql("SELECT original_generation, original_incarnation::text, reader_generation, holders, "
                 "cardinality(quiescence_ids), prior_effect_state, prior_guard_state FROM voalack.settlements "
                 "WHERE attempt_id = %s", (attempt_id,))[0]
    assert frozen[:3] == (original.generation, original.incarnation, successor.generation)
    assert frozen[3] == [{"generation": original.generation, "incarnation": original.incarnation}]
    assert frozen[4:] == (1, "UNCERTAIN", "uncertain")
    assert decide(later["reconciliation_id"], decision) == "already_settled"           # identical replay
    assert decide(later["reconciliation_id"], decision, note="changed") == "decision_conflict"
    assert decide(later["reconciliation_id"]) == "conflict"                             # another decision
    assert successor.apply_once(effect_id)["reason"] == "effect_not_queued"            # never resent
    assert _no_ack_traffic(successor) and fake.counts["receipts"] <= 1


@pytest.mark.parametrize("drift", ["config", "reader_stopped"])
def test_operator_settlement_rechecks_the_reader_and_configuration(client, app, instance, fake, drift):
    effect_id, attempt_id, original = _operator_case(client, app, instance, fake, "retired_after_quiescence")
    successor = _successor(instance, fake, original)
    rid = successor.reconcile(attempt_id)["reconciliation_id"]
    if drift == "config":
        sql("UPDATE voalack.instance_config SET config_revision = config_revision + 1 WHERE instance_id = %s",
            (instance,), fetch=False)
        expected = "reader_config_changed"
    else:
        successor.stop("lab: reader stopped")
        expected = "reader_owner_fenced"
    for outcome in ("retired_after_quiescence", "confirmed_attributed"):
        assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, outcome, rid) == expected
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]


def test_operator_settlement_waits_for_a_configuration_change_and_refuses(client, app, instance, fake):
    effect_id, attempt_id, original = _operator_case(client, app, instance, fake, "retired_after_quiescence")
    successor = _successor(instance, fake, original)
    rid = successor.reconcile(attempt_id)["reconciliation_id"]
    timer = _drift_after_wait(instance, "config")
    started = time.monotonic()
    assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, "retired_after_quiescence", rid) == \
        "reader_config_changed"
    timer.join()
    assert time.monotonic() - started >= 0.5 and _guards(instance) == [("4711", "uncertain")]


def test_holder_inventory_must_be_known_and_covered(client, app, instance, fake):
    effect_id, attempt_id, original = _operator_case(client, app, instance, fake, "retired_after_quiescence")
    successor = _successor(instance, fake, original)
    generation, incarnation = _lab_holder(attempt_id, generation=0)
    sql("INSERT INTO voalack.owner_containment (instance_id, owner_generation, incarnation, evidence) "
        "VALUES (%s, %s, %s, '{\"basis\": \"lab\"}')", (instance, generation, incarnation), fetch=False)
    sql("SELECT voalack.record_quiescence(%s, %s, %s, %s::jsonb)",
        (instance, generation, incarnation, json.dumps({"process": {"label": "lab", "exit_observed_at": _now()},
                                                        "sessions": [], "basis": "lab"})))
    rid = successor.reconcile(attempt_id)["reconciliation_id"]
    decide = lambda: settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, "retired_after_quiescence", rid)
    assert decide() == "holder_sessions_unknown"                       # [lab] a holder with no known session
    sql("INSERT INTO voalack.provider_sessions VALUES (%s, %s, %s, %s, 'lab-cred')",
        ("b" * 64, instance, generation, incarnation), fetch=False)     # [lab] a session found later
    assert decide() == "quiescence_incomplete"
    assert _effect_row(effect_id) == ("UNCERTAIN", True)


@pytest.mark.parametrize("outcome", sorted(OPERATOR))
def test_operator_outcome_refuses_the_wrong_classification_or_attempt(client, app, instance, fake, outcome):
    effect_id, attempt_id, original = _uncertain(client, app, instance, fake)              # reads attributable
    successor = _successor(instance, fake, original)
    rid = successor.reconcile(attempt_id, settle=False)["reconciliation_id"]
    assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, outcome, rid) == "classification_mismatch"
    other_effect, other_attempt, _ = _uncertain(client, app, instance, fake, owner=successor, target_id="4712")
    assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), other_attempt, outcome, rid) == "wrong_reconciliation"
    assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, "no_effect", rid) == "bad_outcome"
    assert _effect_row(effect_id) == ("UNCERTAIN", True)


def test_operator_attributed_confirmation_needs_no_quiescence_and_frees_only_its_guard(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    other_effect, other_attempt, _ = _uncertain(client, app, instance, fake, owner=owner, target_id="4712")
    rid = owner.reconcile(attempt_id, settle=False)["reconciliation_id"]
    assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, "confirmed_attributed", rid) == "settled"
    assert _effect_row(effect_id) == ("REMOTE_CONFIRMED", False)
    assert _guards(instance) == [("4712", "uncertain")] and _effect_row(other_effect) == ("UNCERTAIN", True)


@pytest.mark.parametrize("fault", ["commit_then_lost", "rollback_then_lost"])
def test_unknown_operator_commit_is_resolved_by_the_same_decision(client, app, instance, fake, fault):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    rid = owner.reconcile(attempt_id, settle=False)["reconciliation_id"]
    decision = str(uuid.uuid4())

    def lost(conn):
        conn.commit() if fault == "commit_then_lost" else conn.rollback()
        raise psycopg2.OperationalError("lab: COMMIT acknowledgement lost")
    assert settler.settle(SETTLER_DSN, decision, attempt_id, "confirmed_attributed", rid, commit=lost) == \
        "unknown_commit"
    known = settler.status(SETTLER_DSN, decision)
    if fault == "commit_then_lost":
        assert known["outcome"] == "confirmed_attributed"
        assert settler.settle(SETTLER_DSN, decision, attempt_id, "confirmed_attributed", rid) == "already_settled"
    else:
        assert known is None                                     # absence: only the same decision may follow
        assert settler.settle(SETTLER_DSN, decision, attempt_id, "confirmed_attributed", rid) == "settled"
    assert len(_settlements(attempt_id)) == 1 and _effect_row(effect_id) == ("REMOTE_CONFIRMED", False)


def test_automatic_and_operator_settlement_race_settles_once(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    rid = owner.reconcile(attempt_id, settle=False)["reconciliation_id"]
    admin = psycopg2.connect(DSN)
    admin.cursor().execute("SELECT 1 FROM voalack.effects WHERE effect_id = %s FOR UPDATE", (effect_id,))
    results = {}

    def run(key, call):
        try:
            results[key] = call()
        except Exception as exc:                                 # recorded, so the assertion shows it
            results[key] = repr(exc)
    automatic = threading.Thread(target=run, args=("auto", lambda: _call(
        "SELECT voalack.settle_by_reconciliation(%s, %s, %s, %s, %s) AS o",
        (str(uuid.uuid4()), rid, instance, owner.generation, owner.incarnation))["o"]))
    operator = threading.Thread(target=run, args=("op", lambda: settler.settle(
        SETTLER_DSN, str(uuid.uuid4()), attempt_id, "confirmed_attributed", rid)))
    automatic.start()
    operator.start()
    try:
        # Both wait on a row lock: one directly behind the administrator, the other in the queue
        # behind it (pg_blocking_pids then names the first waiter, not the administrator).
        limit = time.monotonic() + 5
        while time.monotonic() < limit and sql(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                "AND usename IN ('lab_sender', 'lab_settler')")[0][0] < 2:
            time.sleep(0.02)
        assert not results                                       # [native] both wait on the same row
    finally:
        admin.commit()
        admin.close()
    automatic.join(10)
    operator.join(10)
    assert sorted(results.values()) == ["conflict", "settled"], results
    assert len(_settlements(attempt_id)) == 1 and _effect_row(effect_id) == ("REMOTE_CONFIRMED", False)


def test_settled_attempt_never_regresses(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    assert owner.reconcile(attempt_id)["outcome"] == "settled"
    args = (attempt_id, instance, owner.generation, owner.incarnation)
    assert _call("SELECT voalack.hold_attempt(%s, %s, %s, %s, 'lab') AS o", args)["o"] == "unchanged:uncertain"
    assert _call("SELECT voalack.record_result(%s, %s, %s, %s, '{}'::jsonb) AS o", args)["o"] == "unchanged:uncertain"
    assert _effect_row(effect_id) == ("REMOTE_CONFIRMED", False) and _guards(instance) == []
    for statement in ("UPDATE voalack.settlements SET outcome = 'superseded_remote'",
                      "DELETE FROM voalack.settlements", "UPDATE voalack.reconciliations SET classification = 'not_acked'",
                      "DELETE FROM voalack.reconciliation_reads", "DELETE FROM voalack.provider_sessions"):
        with pytest.raises(psycopg2.errors.RaiseException):
            sql(statement + " WHERE true", fetch=False)             # [native] immutable ledgers


def test_retirement_frees_the_target_for_a_new_human_action_only(client, app, instance, fake):
    effect_id, attempt_id, original = _operator_case(client, app, instance, fake, "retired_after_quiescence")
    successor = _successor(instance, fake, original)
    rid = successor.reconcile(attempt_id)["reconciliation_id"]
    assert settler.settle(SETTLER_DSN, str(uuid.uuid4()), attempt_id, "retired_after_quiescence", rid) == "settled"
    receipts = fake.counts["receipts"]
    assert successor.apply_once(effect_id)["reason"] == "effect_not_queued"            # the old action: never
    fresh = _effect(client, app, instance, occurrence_ref="lab-s3b-fresh")             # a new captured action
    assert successor.apply_once(fresh)["outcome"] == "confirmed"
    assert fake.counts["receipts"] == receipts + 1 and _effect_row(effect_id) == ("BLOCKED", False)


# --- roles and readiness (A7, B6) --------------------------------------------------------------------

ATTEMPT_COLUMNS = settler.SETTLER.column_reads[0][1].split(",")


def test_settler_is_ready_and_exactly_bounded(app):
    with psycopg2.connect(SETTLER_DSN) as conn:
        verifier.check_ready(conn, settler.SETTLER)
    with psycopg2.connect(SENDER_DSN) as conn:
        verifier.check_ready(conn, sender.SENDER)
    with psycopg2.connect(SETTLER_DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT " + ", ".join(ATTEMPT_COLUMNS) + " FROM voalack.attempts LIMIT 1")   # allowed columns
    probes = {
        SETTLER_DSN: ["SELECT request_bytes FROM voalack.attempts", "SELECT * FROM voalack.attempts",
                      "SELECT voalack.begin_reconciliation(gen_random_uuid(), gen_random_uuid(), 'x', 1, gen_random_uuid())",
                      "SELECT voalack.register_session('x', 'x', 1, gen_random_uuid())",
                      "SELECT voalack.record_quiescence('x', 1, gen_random_uuid(), '{}')",
                      "SELECT voalack.start_attempt(gen_random_uuid(), 1, 'x', 1, gen_random_uuid())",
                      "SELECT voalack._settle(gen_random_uuid(), 'x', 1, 'x', 'x', 'x', '[]', '{}', '')",
                      "SELECT * FROM voalack.prepared_intents", "SELECT * FROM voalack.attempt_evidence",
                      "SELECT * FROM voalack.reconciliation_reads",
                      "INSERT INTO voalack.settlements (decision_id) VALUES (gen_random_uuid())"],
        SENDER_DSN: ["SELECT voalack.settle_uncertain(gen_random_uuid(), gen_random_uuid(), 'x', 1, '')",
                     "SELECT voalack.record_quiescence('x', 1, gen_random_uuid(), '{}')",
                     "SELECT voalack._classify(gen_random_uuid(), '{}', now())",
                     "SELECT * FROM voalack.settlements", "SELECT * FROM voalack.quiescence",
                     "SELECT * FROM voalack.provider_sessions"],
        VERIFIER_DSN: ["SELECT voalack.settle_uncertain(gen_random_uuid(), gen_random_uuid(), 'x', 1, '')",
                       "SELECT voalack.begin_reconciliation(gen_random_uuid(), gen_random_uuid(), 'x', 1, gen_random_uuid())"],
        APP_DSN: ["SELECT voalack.settle_uncertain(gen_random_uuid(), gen_random_uuid(), 'x', 1, '')",
                  "SELECT voalack.settlement_status(gen_random_uuid())",
                  "SELECT voalack.register_session('x', 'x', 1, gen_random_uuid())"],
    }
    for dsn, statements in probes.items():
        for statement in statements:
            with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
                with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                    cur.execute(statement)


@pytest.mark.parametrize("setup, undo, condition", [
    ("GRANT SELECT ON voalack.prepared_intents TO voalack_settler",
     "REVOKE SELECT ON voalack.prepared_intents FROM voalack_settler", "extra_read"),
    ("GRANT SELECT (request_bytes) ON voalack.attempts TO voalack_settler",
     "REVOKE SELECT (request_bytes) ON voalack.attempts FROM voalack_settler", "column_read_drift"),
    ("GRANT SELECT ON voalack.attempts TO voalack_settler",
     "REVOKE SELECT ON voalack.attempts FROM voalack_settler; " + "GRANT SELECT ("
     + ", ".join(settler.SETTLER.column_reads[0][1].split(",")) + ") ON voalack.attempts TO voalack_settler",
     "column_read_drift"),
    ("GRANT SELECT (request_bytes) ON voalack.attempts TO PUBLIC",
     "REVOKE SELECT (request_bytes) ON voalack.attempts FROM PUBLIC", "column_read_drift"),
    ("REVOKE SELECT (settled_at) ON voalack.attempts FROM voalack_settler",
     "GRANT SELECT (settled_at) ON voalack.attempts TO voalack_settler", "column_read_drift"),
    ("GRANT voalack_sender TO lab_settler", "REVOKE voalack_sender FROM lab_settler", "admin_or_app_path"),
    ("GRANT EXECUTE ON FUNCTION voalack.record_quiescence(text, bigint, uuid, jsonb) TO voalack_settler",
     "REVOKE EXECUTE ON FUNCTION voalack.record_quiescence(text, bigint, uuid, jsonb) FROM voalack_settler",
     "execute_drift"),
    ("ALTER TABLE voalack.settlements DISABLE TRIGGER settlements_immutable",
     "ALTER TABLE voalack.settlements ENABLE TRIGGER settlements_immutable", "immutability_drift"),
    ("GRANT INSERT ON voalack.settlements TO voalack_settler",
     "REVOKE INSERT ON voalack.settlements FROM voalack_settler", "table_power"),
    ("CREATE FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint) RETURNS text LANGUAGE sql "
     "SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$ SELECT 'x' $$; "
     "ALTER FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint) OWNER TO voalack_admin; "
     "REVOKE EXECUTE ON FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint) FROM PUBLIC; "
     "GRANT EXECUTE ON FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint) TO voalack_settler",
     "DROP FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint)", "execute_drift"),
])
def test_settler_readiness_refuses_drift(app, setup, undo, condition):
    sql(setup, fetch=False)
    try:
        with psycopg2.connect(SETTLER_DSN) as conn:
            with pytest.raises(verifier.NotReady, match=condition):
                verifier.check_ready(conn, settler.SETTLER)
    finally:
        sql(undo, fetch=False)
    with psycopg2.connect(SETTLER_DSN) as conn:
        verifier.check_ready(conn, settler.SETTLER)                  # restored


def test_sender_readiness_refuses_a_settler_capability(app):
    sql("GRANT EXECUTE ON FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint, text) TO voalack_sender",
        fetch=False)
    try:
        with psycopg2.connect(SENDER_DSN) as conn:
            with pytest.raises(verifier.NotReady, match="execute_drift"):
                verifier.check_ready(conn, sender.SENDER)
    finally:
        sql("REVOKE EXECUTE ON FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint, text) FROM voalack_sender",
            fetch=False)


# --- upgrade from the integrated S3a schema (B6) -------------------------------------------------------

@pytest.fixture
def s3a_db():
    name = f"voalack_s3a_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    dsn = DSN.rsplit("/", 1)[0] + "/" + name
    try:
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("CREATE TYPE public.history AS (id text, event text, severity text, status text, value text, "
                        "text text, type text, update_time timestamp, \"user\" text, timeout integer); "
                        "CREATE TABLE public.alerts (id text PRIMARY KEY, customer text, status text, "
                        "history public.history[], "
                        # coexistence 3a: the columns the ownership class, lifetime and binding guard read
                        "resource text, event text, environment text, origin text, create_time timestamp)")
            cur.execute(open(S3A_SCHEMA).read())                     # the integrated e471642 installation
        yield dsn
    finally:
        admin.cursor().execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.close()


def test_upgrade_from_s3a_installs_the_settlement_ledger_and_roles(s3a_db):
    login = lambda dsn, user, password: dsn.replace("lab_admin:lab-only-admin", f"{user}:{password}")
    for _ in range(2):                                               # upgrade, then repeated application
        with psycopg2.connect(s3a_db) as conn:
            schema.apply(conn)
        with psycopg2.connect(login(s3a_db, "lab_settler", "lab-only-settler")) as conn:
            verifier.check_ready(conn, settler.SETTLER)
        with psycopg2.connect(login(s3a_db, "lab_sender", "lab-only-sender")) as conn:
            verifier.check_ready(conn, sender.SENDER)
    rolled = psycopg2.connect(s3a_db)
    try:
        rolled.cursor().execute("DROP TABLE voalack.settlements")    # lab: proves the ledger exists
        rolled.rollback()
    finally:
        rolled.close()
