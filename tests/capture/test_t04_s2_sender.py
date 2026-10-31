"""T04 S2: session owner, attempts with a one-time dispatch permit, physical-target guards and the
fake ONE adapter. Native PostgreSQL in the guest; the provider is a loopback fake (synthetic).

Labels: [native] real PostgreSQL transactions/roles/constraints; [scripted] Python commit-fault
hooks; [fake] fake-provider behaviour. Every case asserts adapter dispatch entries, transport ACK
writes, provider receipts and provider effects.
"""
import dataclasses
import json
import multiprocessing
import threading
import time
import uuid
import warnings
from datetime import timedelta

import psycopg2
import psycopg2.extras
import pytest

from conftest import DSN, OPERATOR, SENDER_DSN, VERIFIER_DSN, ack, basic, lab_anchor, new_alert, sql
from fake_one import FakeOne
from voalack import sender, verifier
from voalack.sender import FakeOneTransport, OwnerSession, OwnerStopped, UnknownCommit


@pytest.fixture
def instance():
    iid = f"lab-one-{uuid.uuid4().hex[:8]}"
    sql("INSERT INTO voalack.instance_config VALUES (%s, %s, 'fake-one/v1', 1)", (iid, f"cred-{iid}"), fetch=False)
    sql("INSERT INTO voalack.accepted_kids VALUES ('lab-k1') ON CONFLICT DO NOTHING", fetch=False)
    sql("INSERT INTO voalack.accepted_verifier_versions VALUES ('voalack-verifier/s1') ON CONFLICT DO NOTHING",
        fetch=False)
    return iid


@pytest.fixture
def fake():
    with FakeOne() as provider:
        yield provider


def _effect(client, app, instance, **kwargs):
    alert_id = new_alert(client, instance_id=instance, **kwargs)
    assert ack(client, alert_id).status_code == 200
    action_id = sql("SELECT action_id::text FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))[0][0]
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as conn:
        result = verifier.run_once(conn, "lab-verifier-s2", signing.ctx, signing.keys, action_id=action_id)
    assert result["outcome"] == "verified", result
    return result["effect_id"]


def _owner(instance, provider, **kwargs):
    # T04 S3c (disclosed fixture amendment): every owner reads the lab recovery anchor.
    owner = OwnerSession(SENDER_DSN, instance, kwargs.pop("owner_id", "lab-owner"), FakeOneTransport(provider.url),
                         anchor=kwargs.pop("anchor", None) or lab_anchor(), **kwargs)
    owner.acquire()
    return owner


def _counts(owner, provider):
    return (owner.counts["dispatch_entries"], owner.transport.counts["ack_writes"], provider.counts["receipts"],
            provider.counts["effects"])


def _effect_state(effect_id):
    return sql("SELECT state, in_flight_attempt IS NOT NULL FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0]


def _attempt(attempt_id):
    return sql("SELECT state, permit_state FROM voalack.attempts WHERE attempt_id = %s", (attempt_id,))[0]


def _guards(instance):
    return sql("SELECT target_id, state FROM voalack.target_guards WHERE instance_id = %s", (instance,))


def _contain(instance, generation, basis="lab: process stopped and provider idle"):
    sql("SELECT voalack.record_containment(%s, %s, %s::jsonb)",
        (instance, generation, json.dumps({"process_stopped": True, "no_requests_executing": True, "basis": basis})),
        fetch=False)


def _call(statement, args):
    with psycopg2.connect(SENDER_DSN) as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(statement, args)
        return cur.fetchone()


# --- positive and duplicates --------------------------------------------------------------

def test_verified_effect_is_sent_once_and_confirmed(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    result = owner.apply_once(effect_id)
    assert result["outcome"] == "confirmed", result
    assert _counts(owner, fake) == (1, 1, 1, 1)
    assert _effect_state(effect_id) == ("REMOTE_CONFIRMED", False) and _guards(instance) == []
    assert _attempt(result["attempt_id"]) == ("confirmed", "consumed")
    again = owner.apply_once(effect_id)                                   # [native] no second permit
    assert (again["outcome"], again["reason"]) == ("refused", "effect_not_queued")
    assert _counts(owner, fake) == (1, 1, 1, 1)


def test_same_physical_target_through_another_action_is_guarded(client, app, instance, fake):
    first = _effect(client, app, instance, occurrence_ref="lab-occ-a")
    second = _effect(client, app, instance, occurrence_ref="lab-occ-b")   # different effect key, same target
    owner = _owner(instance, fake)
    held = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                 (str(uuid.uuid4()), first, instance, owner.generation, owner.incarnation))
    assert held["outcome"] == "started"
    result = owner.apply_once(second)                                     # [native] in-flight guard
    assert (result["outcome"], result["reason"]) == ("refused", "target_guarded")
    fake.script["ack"] = "close_after_body"
    sql("SELECT voalack._release_no_dispatch(a.attempt_id, 'QUEUED') FROM voalack.attempts a "
        "WHERE a.effect_id = %s AND a.state = 'started'", (first,), fetch=True)
    uncertain = owner.apply_once(first)                                   # [fake] possibly applied
    assert uncertain["outcome"] == "uncertain", uncertain
    assert _guards(instance) == [("4711", "uncertain")]
    result = owner.apply_once(second)                                     # uncertain guard holds
    assert (result["outcome"], result["reason"]) == ("refused", "target_guarded")
    assert _counts(owner, fake) == (1, 1, 1, 1)


def test_attempt_id_is_idempotent_only_for_the_exact_tuple(client, app, instance, fake):
    first = _effect(client, app, instance, occurrence_ref="lab-occ-c")
    other = _effect(client, app, f"{instance}", target_id="4712", occurrence_ref="lab-occ-d")
    owner = _owner(instance, fake)
    attempt_id = str(uuid.uuid4())
    args = (attempt_id, first, instance, owner.generation, owner.incarnation)
    one = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", args)
    two = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", args)
    assert one == two and one["outcome"] == "started"
    conflict = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                     (attempt_id, other, instance, owner.generation, owner.incarnation))
    assert conflict["outcome"] == "attempt_id_conflict"
    consumed = _call("SELECT * FROM voalack.consume_dispatch(%s, %s, %s, %s)",
                     (attempt_id, instance, owner.generation, owner.incarnation))
    assert consumed["outcome"] == "dispatched"
    again = _call("SELECT * FROM voalack.consume_dispatch(%s, %s, %s, %s)",
                  (attempt_id, instance, owner.generation, owner.incarnation))
    assert again["outcome"] == "not_consumable:dispatched" and again["request_bytes"] is None
    replay = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", args)
    assert replay["outcome"] == "attempt_id_conflict"                     # consumed: never fresh authority
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_concurrent_starts_and_abort_versus_consume(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    outcomes, barrier = [], threading.Barrier(2)

    def start():
        barrier.wait(5)
        outcomes.append(_call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                              (str(uuid.uuid4()), effect_id, instance, owner.generation, owner.incarnation))["outcome"])
    threads = [threading.Thread(target=start) for _ in range(2)]
    [t.start() for t in threads]
    [t.join(20) for t in threads]
    assert sorted(outcomes) == ["effect_not_queued", "started"], outcomes     # [native]
    attempt_id = sql("SELECT attempt_id::text FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]
    results, barrier = {}, threading.Barrier(2)

    def consume():
        barrier.wait(5)
        results["consume"] = _call("SELECT * FROM voalack.consume_dispatch(%s, %s, %s, %s)",
                                   (attempt_id, instance, owner.generation, owner.incarnation))["outcome"]

    def abort():
        barrier.wait(5)
        results["abort"] = _call("SELECT voalack.abort_attempt(%s, %s, %s, %s) AS o",
                                 (attempt_id, instance, owner.generation, owner.incarnation))["o"]
    threads = [threading.Thread(target=consume), threading.Thread(target=abort)]
    [t.start() for t in threads]
    [t.join(20) for t in threads]
    state = _attempt(attempt_id)
    assert (results, state) in (
        ({"consume": "dispatched", "abort": "not_abortable:dispatched"}, ("dispatched", "consumed")),
        ({"consume": "not_consumable:aborted_before_dispatch", "abort": "aborted"}, ("aborted_before_dispatch", "revoked")),
    ), (results, state)
    assert _counts(owner, fake) == (0, 0, 0, 0)


# --- request semantics and last-boundary checks ------------------------------------------

def test_changed_request_bytes_are_refused(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    start = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                  (attempt_id := str(uuid.uuid4()), effect_id, instance, owner.generation, owner.incarnation))
    assert start["outcome"] == "started"
    with pytest.raises(psycopg2.errors.CheckViolation):                    # bytes without their digest
        sql("UPDATE voalack.attempts SET request_bytes = request_bytes || ' '::bytea WHERE attempt_id = %s",
            (attempt_id,), fetch=False)
    sql("UPDATE voalack.attempts a SET request_bytes = x.b, request_sha256 = encode(sha256(x.b), 'hex') "
        "FROM (SELECT convert_to(replace(convert_from(request_bytes, 'UTF8'), '\"4711\"', '\"4799\"'), 'UTF8') AS b "
        "FROM voalack.attempts WHERE attempt_id = %s) x WHERE a.attempt_id = %s",
        (attempt_id, attempt_id), fetch=False)                            # other target, recomputed digest
    consumed = _call("SELECT * FROM voalack.consume_dispatch(%s, %s, %s, %s)",
                     (attempt_id, instance, owner.generation, owner.incarnation))
    assert consumed["outcome"] == "aborted:request_changed" and consumed["request_bytes"] is None
    assert _attempt(attempt_id) == ("aborted_before_dispatch", "revoked") and _effect_state(effect_id)[0] == "BLOCKED"
    assert _counts(owner, fake) == (0, 0, 0, 0)


@pytest.mark.parametrize("change,reason", [
    ("UPDATE voalack.authorization_policy_active SET policy_revision = 3", "aborted:policy_revoked"),
    ("DELETE FROM voalack.accepted_kids WHERE kid = 'lab-k1'", "aborted:key_not_accepted"),
    ("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %(instance)s", "aborted:config_changed"),
])
def test_eligibility_lost_between_start_and_consume_sends_nothing(client, app, instance, fake, change, reason):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake, hooks={"after_start": lambda _: sql(change, {"instance": instance}, fetch=False)})
    try:
        result = owner.apply_once(effect_id)
    finally:
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
        sql("INSERT INTO voalack.accepted_kids VALUES ('lab-k1') ON CONFLICT DO NOTHING", fetch=False)
    if reason == "aborted:config_changed":
        # Amended (bot finding, owner bound to its configuration): the fenced login step now sees the
        # changed configuration first and stops the whole owner; the attempt keeps its unconsumed
        # permit for a successor to abort. The consume-time config check stays covered by the
        # final-check and session variants.
        assert (result["outcome"], result["reason"]) == ("held", "config_changed"), result
        assert owner.stopped == "config_changed" and _attempt(result["attempt_id"]) == ("started", "unconsumed")
    else:
        assert (result["outcome"], result["reason"]) == ("refused", reason), result
        assert _effect_state(effect_id) == ("BLOCKED", False) and _guards(instance) == []
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_newer_ack_between_start_and_consume_sends_nothing(client, app, instance, fake):
    alert_id = new_alert(client, instance_id=instance)
    assert ack(client, alert_id).status_code == 200
    action_id = sql("SELECT action_id::text FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))[0][0]
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as conn:
        effect_id = verifier.run_once(conn, "lab-v", signing.ctx, signing.keys, action_id=action_id)["effect_id"]

    def newer(_):
        assert client.put(f"/alert/{alert_id}/action", json={"action": "unack", "text": "lab"},
                          headers=basic(OPERATOR)).status_code == 200
        assert ack(app.test_client(), alert_id, text="lab newer").status_code == 200
    owner = _owner(instance, fake, hooks={"after_start": newer})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "aborted:generation_superseded"), result
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_deadline_passing_between_start_and_consume_sends_nothing(client, app, instance, fake):
    signing = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(signing, capture_window=timedelta(seconds=1),
                                                            execution_window=timedelta(seconds=3))
    try:
        effect_id = _effect(client, app, instance)
    finally:
        app.extensions["voalack_signing"] = signing
    deadline = sql("SELECT p.execution_expires_at FROM voalack.effects e JOIN voalack.prepared_intents p "
                   "ON p.action_id = e.action_id WHERE e.effect_id = %s", (effect_id,))[0][0]

    def wait(_):
        while not sql("SELECT clock_timestamp() > %s", (deadline,))[0][0]:
            time.sleep(0.05)
    owner = _owner(instance, fake, hooks={"after_start": wait})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "aborted:expired"), result
    assert _effect_state(effect_id) == ("BLOCKED", False)
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_delayed_handoff_after_consumption_is_held_not_sent(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake, handoff_bound=0.5, hooks={"before_send": lambda _: time.sleep(0.8)})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "handoff_not_immediate"), result
    assert _attempt(result["attempt_id"]) == ("uncertain", "consumed")
    assert _effect_state(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    assert _counts(owner, fake) == (0, 0, 0, 0)


# --- attribution ---------------------------------------------------------------------------

@pytest.mark.parametrize("ack_mode,read_back", [
    ("no_operation_id", "normal"),          # HTTP 200 + identical comment, no attributable operation
    ("success", "mismatch"),                # read-back does not show this operation's comment
    ("close_after_body", "normal"),         # applied, response lost
    ("close_before_body", "normal"),        # connection closed before the body was read
])
def test_unattributable_outcomes_stay_uncertain(client, app, instance, fake, ack_mode, read_back):
    effect_id = _effect(client, app, instance)
    fake.script.update(ack=ack_mode, read_back=read_back)
    owner = _owner(instance, fake)
    result = owner.apply_once(effect_id)
    assert result["outcome"] == "uncertain", result
    assert _effect_state(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    receipts = 0 if ack_mode == "close_before_body" else 1
    assert _counts(owner, fake) == (1, 1, receipts, receipts)
    assert owner.apply_once(effect_id)["reason"] == "effect_not_queued"
    assert _counts(owner, fake) == (1, 1, receipts, receipts)              # nothing added


# --- unknown COMMIT (scripted faults) -------------------------------------------------------

def _commit_then_raise(conn):
    conn.commit()
    raise UnknownCommit("lab: commit outcome hidden")


def _rollback_then_raise(conn):
    conn.rollback()
    raise UnknownCommit("lab: commit did not happen")


def test_unknown_start_commit_with_the_row_present_continues_once(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake, hooks={"commit:start": _commit_then_raise})
    result = owner.apply_once(effect_id)
    assert result["outcome"] == "confirmed", result
    assert _counts(owner, fake) == (1, 1, 1, 1)


def test_unknown_start_commit_with_the_row_absent_suspends_the_owner(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake, hooks={"commit:start": _rollback_then_raise})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "unknown_start_commit"), result
    assert sql("SELECT state FROM voalack.session_owners WHERE instance_id = %s", (instance,))[0][0] == "suspended"
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)
    with pytest.raises(psycopg2.errors.RaiseException, match="not free or contained"):
        _owner(instance, fake, owner_id="lab-successor")
    assert _counts(owner, fake) == (0, 0, 0, 0)


@pytest.mark.parametrize("fault,state", [(_commit_then_raise, ("uncertain", "consumed")),
                                         (_rollback_then_raise, ("uncertain", "revoked"))])
def test_unknown_consume_commit_never_sends(client, app, instance, fake, fault, state):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake, hooks={"commit:consume": fault})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "unknown_consume_commit"), result
    assert _attempt(result["attempt_id"]) == state and _effect_state(effect_id) == ("UNCERTAIN", True)
    assert owner.stopped == "unknown_consume_commit"
    assert _counts(owner, fake) == (0, 0, 0, 0)


# --- ownership --------------------------------------------------------------------------------

def test_no_takeover_while_active_or_suspended_and_fencing_after_containment(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    first = _owner(instance, fake)
    with pytest.raises(psycopg2.errors.RaiseException, match="not free or contained"):
        _owner(instance, fake, owner_id="lab-second")                     # active: refused
    first.stop("lab orderly stop")
    with pytest.raises(psycopg2.errors.RaiseException, match="not free or contained"):
        _owner(instance, fake, owner_id="lab-second")                     # suspended: still refused
    with pytest.raises(psycopg2.errors.RaiseException, match="quiescence"):
        sql("SELECT voalack.record_containment(%s, %s, '{\"basis\": \"declared dead\"}')",
            (instance, first.generation), fetch=False)
    _contain(instance, first.generation)
    second = _owner(instance, fake, owner_id="lab-second")
    assert second.generation == first.generation + 1
    stale = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                  (str(uuid.uuid4()), effect_id, instance, first.generation, first.incarnation))
    assert stale["outcome"] == "owner_fenced"
    replacement = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",   # old generation, new process
                        (str(uuid.uuid4()), effect_id, instance, second.generation, str(uuid.uuid4())))
    assert replacement["outcome"] == "owner_fenced"
    assert second.apply_once(effect_id)["outcome"] == "confirmed"
    assert _counts(second, fake) == (1, 1, 1, 1)


def test_owner_fenced_between_start_and_consume_sends_nothing(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    holder = {}

    def fence(_):
        _contain(instance, holder["owner"].generation)
        holder["successor"] = _owner(instance, fake, owner_id="lab-successor")
    owner = holder["owner"] = _owner(instance, fake, hooks={"after_start": fence})
    result = owner.apply_once(effect_id)
    # Amended (e47b668 review, S2-R3): the fenced login step now stops the owner before consume_dispatch,
    # so the attempt keeps its unconsumed permit until the successor definitively aborts it.
    assert (result["outcome"], result["reason"]) == ("held", "fenced"), result
    assert _attempt(result["attempt_id"]) == ("started", "unconsumed")
    released = holder["successor"].release_stale_started()
    assert [(str(r["attempt_id"]), r["outcome"]) for r in released] == [(result["attempt_id"], "aborted_before_dispatch")]
    assert _effect_state(effect_id) == ("QUEUED", False) and _guards(instance) == []
    assert holder["successor"].apply_once(effect_id)["outcome"] == "confirmed"
    assert _counts(owner, fake)[:2] == (0, 0) and (fake.counts["receipts"], fake.counts["effects"]) == (1, 1)


class _Crash(BaseException):
    pass


def test_crash_after_consume_is_uncertain_and_never_resent(client, app, instance, fake):
    effect_id = _effect(client, app, instance)

    def crash(_):
        raise _Crash()
    dead = _owner(instance, fake, hooks={"before_send": crash})
    with pytest.raises(_Crash):
        dead.apply_once(effect_id)
    attempt_id = sql("SELECT attempt_id::text FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]
    assert _attempt(attempt_id) == ("dispatched", "consumed")             # durable boundary passed
    with pytest.raises(psycopg2.errors.RaiseException, match="not free or contained"):
        _owner(instance, fake, owner_id="lab-replacement")                # no lease or time takeover
    _contain(instance, dead.generation)
    successor = _owner(instance, fake, owner_id="lab-replacement")
    assert [(str(r["attempt_id"]), r["outcome"]) for r in successor.release_stale_started()] == [(attempt_id, "uncertain")]
    assert _effect_state(effect_id) == ("UNCERTAIN", True)
    assert successor.apply_once(effect_id)["reason"] == "effect_not_queued"
    assert (fake.counts["receipts"], fake.counts["effects"]) == (0, 0)


def test_database_loss_stops_locally_without_writing_suspension(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    owner.login()
    pid = owner._db().get_backend_pid()
    sql("ALTER ROLE lab_sender NOLOGIN", fetch=False)
    try:
        sql("SELECT pg_terminate_backend(%s)", (pid,))
        with pytest.raises(OwnerStopped):
            owner.apply_once(effect_id)
        assert owner.stopped == "database_lost"
        assert sql("SELECT state FROM voalack.session_owners WHERE instance_id = %s", (instance,))[0][0] == "active"
        with pytest.raises(OwnerStopped):                                 # local stop, no DB needed
            owner.apply_once(effect_id)
    finally:
        sql("ALTER ROLE lab_sender LOGIN", fetch=False)
    with pytest.raises(psycopg2.errors.RaiseException, match="not free or contained"):
        _owner(instance, fake, owner_id="lab-replacement")
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["logins"] == 1


def _dying_sender(dsn, instance, url, effect_id, queue):
    owner = OwnerSession(dsn, instance, "lab-dying", FakeOneTransport(url), anchor=lab_anchor())  # T04 S3c
    queue.put((owner.acquire(), owner.incarnation))
    owner.apply_once(effect_id)                                           # killed while the request executes


def test_delayed_request_after_sender_death_blocks_takeover_until_quiescent(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    fake.script["delay"] = 2.0
    queue = multiprocessing.get_context("fork").Queue()
    process = multiprocessing.get_context("fork").Process(
        target=_dying_sender, args=(SENDER_DSN, instance, fake.url, effect_id, queue))
    process.start()
    generation, _ = queue.get(timeout=20)
    deadline = time.monotonic() + 20
    while fake.executing == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert fake.executing == 1
    process.kill()                                                        # sender death mid-request
    process.join(10)
    with fake.lock:                                                       # operator revokes the old session
        fake.sessions.clear()
    with pytest.raises(psycopg2.errors.RaiseException, match="not free or contained"):
        _owner(instance, fake, owner_id="lab-standby")                    # remote work still executing
    assert fake.executing == 1
    while fake.executing:
        time.sleep(0.05)
    _contain(instance, generation, basis="lab: sender killed, session revoked, provider shows no executing request")
    standby = _owner(instance, fake, owner_id="lab-standby")
    outcomes = standby.release_stale_started()
    assert [o["outcome"] for o in outcomes] == ["uncertain"]
    assert standby.apply_once(effect_id)["reason"] == "effect_not_queued"
    assert (fake.counts["receipts"], fake.counts["effects"]) == (1, 1)    # the dead sender's one request
    assert standby.counts["dispatch_entries"] == 0 and fake.max_concurrent[f"cred-{instance}"] == 1


def test_late_original_result_after_containment_is_evidence_only(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    holder = {}

    def fence(_):
        _contain(instance, holder["owner"].generation, basis="lab: scripted fence before the result is recorded")
        holder["successor"] = _owner(instance, fake, owner_id="lab-successor")
    owner = holder["owner"] = _owner(instance, fake, hooks={"before_record": fence})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "owner_fenced_after_send"), result
    assert _attempt(result["attempt_id"]) == ("dispatched", "consumed")   # not settled by a fenced owner
    kinds = sql("SELECT kind, owner_generation FROM voalack.attempt_evidence WHERE attempt_id = %s",
                (result["attempt_id"],))
    assert kinds == [("late_result", owner.generation)]
    assert holder["successor"].release_stale_started()[0]["outcome"] == "uncertain"
    assert _effect_state(effect_id) == ("UNCERTAIN", True)
    assert _counts(owner, fake) == (1, 1, 1, 1) and holder["successor"].counts["dispatch_entries"] == 0


def test_settled_attempts_are_never_downgraded_or_reopened(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    attempt_id = owner.apply_once(effect_id)["attempt_id"]
    args = (attempt_id, instance, owner.generation, owner.incarnation)
    assert _call("SELECT voalack.record_result(%s, %s, %s, %s, '{}'::jsonb) AS o", args)["o"] == "unchanged:confirmed"
    assert _call("SELECT voalack.hold_attempt(%s, %s, %s, %s, 'lab') AS o", args)["o"] == "unchanged:confirmed"
    assert _call("SELECT voalack.abort_attempt(%s, %s, %s, %s) AS o", args)["o"] == "not_abortable:confirmed"
    assert _attempt(attempt_id) == ("confirmed", "consumed") and _effect_state(effect_id) == ("REMOTE_CONFIRMED", False)


def test_fenced_owner_issues_no_provider_requests(client, app, instance, fake):
    owner = _owner(instance, fake)
    owner.login()
    owner.stop("lab")
    with pytest.raises(OwnerStopped):
        owner.login()
    _contain(instance, owner.generation)
    with pytest.raises(OwnerStopped):
        owner.revoke()
    assert fake.counts["logins"] == 1 and fake.counts["revokes"] == 0


# --- roles and readiness ----------------------------------------------------------------------

@pytest.mark.parametrize("statement", [
    "INSERT INTO voalack.attempts (attempt_id) VALUES (gen_random_uuid())",
    "UPDATE voalack.effects SET state = 'QUEUED'",
    "DELETE FROM voalack.target_guards",
    "UPDATE voalack.session_owners SET state = 'free'",
    "SELECT voalack.record_containment('x', 1, '{}'::jsonb)",
    "SELECT voalack._release_no_dispatch(gen_random_uuid(), 'QUEUED')",
    "SELECT voalack.promote_effect(gen_random_uuid(), 1, 1)",
    "SELECT * FROM voalack.prepared_intents",
    "SELECT * FROM voalack.authorization_policy",
    "SELECT voalack.encode_ack_request(1)",
])
def test_sender_role_denials(app, statement):
    with psycopg2.connect(SENDER_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(statement)


def _sender_ready_error():
    with psycopg2.connect(SENDER_DSN) as conn:
        try:
            verifier.check_ready(conn, sender.SENDER)
        except verifier.NotReady as exc:
            return str(exc)
    return None


def test_installed_sender_login_is_ready_and_the_verifier_is_not_a_sender(app):
    assert _sender_ready_error() is None
    with psycopg2.connect(VERIFIER_DSN) as conn:
        with pytest.raises(verifier.NotReady):
            verifier.check_ready(conn, sender.SENDER)


@pytest.mark.parametrize("drift,restore,failure", [
    ("GRANT voalack_verifier TO lab_sender", "REVOKE voalack_verifier FROM lab_sender", "admin_or_app_path"),
    ("GRANT EXECUTE ON FUNCTION voalack.record_containment(text, bigint, jsonb) TO voalack_sender",
     "REVOKE EXECUTE ON FUNCTION voalack.record_containment(text, bigint, jsonb) FROM voalack_sender", "execute_drift"),
    ("GRANT UPDATE (state) ON voalack.attempts TO voalack_sender",
     "REVOKE UPDATE (state) ON voalack.attempts FROM voalack_sender", "table_power"),
    ("ALTER TABLE voalack.attempt_evidence DISABLE TRIGGER attempt_evidence_immutable",
     "ALTER TABLE voalack.attempt_evidence ENABLE TRIGGER attempt_evidence_immutable", "immutability_drift"),
    ("ALTER TABLE voalack.target_guards DROP CONSTRAINT target_guards_attempt_id_key",
     "ALTER TABLE voalack.target_guards ADD CONSTRAINT target_guards_attempt_id_key UNIQUE (attempt_id)",
     "uniqueness_drift"),
    ("REVOKE SELECT ON voalack.attempts FROM voalack_sender", "GRANT SELECT ON voalack.attempts TO voalack_sender",
     "read_missing"),
    # e47b668 review (S2-R6): the physical guard key and the nullable in-flight marker
    ("ALTER TABLE voalack.target_guards DROP CONSTRAINT target_guards_pkey; ALTER TABLE voalack.target_guards "
     "ADD CONSTRAINT target_guards_pkey PRIMARY KEY (instance_id, target_id, target_kind)",
     "ALTER TABLE voalack.target_guards DROP CONSTRAINT target_guards_pkey; ALTER TABLE voalack.target_guards "
     "ADD CONSTRAINT target_guards_pkey PRIMARY KEY (instance_id, target_kind, target_id)", "uniqueness_drift"),
    ("ALTER TABLE voalack.effects DROP CONSTRAINT effects_in_flight_attempt_key",
     "ALTER TABLE voalack.effects ADD CONSTRAINT effects_in_flight_attempt_key UNIQUE (in_flight_attempt)",
     "uniqueness_drift"),
    # follow-up (review-bot findings): one owner per credential; no reads outside the profile
    ("ALTER TABLE voalack.instance_config DROP CONSTRAINT instance_config_credential_ref_key",
     "ALTER TABLE voalack.instance_config ADD CONSTRAINT instance_config_credential_ref_key UNIQUE (credential_ref)",
     "uniqueness_drift"),
    ("GRANT SELECT ON voalack.prepared_intents TO voalack_sender",
     "REVOKE SELECT ON voalack.prepared_intents FROM voalack_sender", "extra_read"),
    ("GRANT SELECT (payload) ON voalack.prepared_intents TO lab_sender",
     "REVOKE SELECT (payload) ON voalack.prepared_intents FROM lab_sender", "extra_read"),
    ("CREATE ROLE lab_reader NOLOGIN; GRANT SELECT ON voalack.captures TO lab_reader; GRANT lab_reader TO lab_sender",
     "REVOKE SELECT ON voalack.captures FROM lab_reader; DROP ROLE lab_reader", "extra_read"),
    ("CREATE ROLE lab_reader NOLOGIN; GRANT SELECT (history_text) ON voalack.captures TO lab_reader; "
     "GRANT lab_reader TO lab_sender WITH INHERIT FALSE, SET TRUE",
     "REVOKE SELECT (history_text) ON voalack.captures FROM lab_reader; DROP ROLE lab_reader", "extra_read"),
    ("GRANT SELECT ON voalack.captures TO PUBLIC", "REVOKE SELECT ON voalack.captures FROM PUBLIC", "extra_read"),
    ("SET ROLE voalack_admin; CREATE VIEW voalack.lab_extra_view AS SELECT 1 AS x; "
     "GRANT SELECT ON voalack.lab_extra_view TO voalack_sender", "DROP VIEW voalack.lab_extra_view", "extra_read"),
])
def test_sender_drift_is_not_ready_and_acquires_nothing(app, instance, fake, drift, restore, failure):
    sql(drift, fetch=False)
    try:
        error = _sender_ready_error()
        with pytest.raises(verifier.NotReady):
            _owner(instance, fake)
    finally:
        sql(restore, fetch=False)
    assert error is not None and failure in error, error
    assert sql("SELECT count(*) FROM voalack.session_owners WHERE instance_id = %s AND state = 'active'",
               (instance,))[0][0] == 0
    assert _sender_ready_error() is None


# --- e47b668 review corrections ------------------------------------------------------------

def test_refused_candidates_use_no_credential_or_network(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(-1)["reason"] == "no_effect"
    owner.stop("lab")
    _contain(instance, owner.generation)
    second = _owner(instance, fake, owner_id="lab-second")
    sql("SELECT voalack.start_attempt(%s, %s, %s, %s, %s)",
        (str(uuid.uuid4()), effect_id, instance, second.generation, second.incarnation), fetch=False)
    assert second.apply_once(effect_id)["reason"] == "effect_not_queued"           # already in flight
    assert owner.transport.counts == second.transport.counts == {"logins": 0, "ack_writes": 0, "reads": 0,
                                                                   "revokes": 0}
    assert fake.counts["logins"] == 0


def test_concurrent_apply_once_sends_at_most_once(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    results, barrier = [], threading.Barrier(3)

    def apply():
        barrier.wait(5)
        results.append(owner.apply_once(effect_id))
    threads = [threading.Thread(target=apply) for _ in range(3)]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert sorted(r["outcome"] for r in results) == ["confirmed", "refused", "refused"], results
    assert _counts(owner, fake) == (1, 1, 1, 1)


def test_concurrent_starts_on_one_physical_target_through_distinct_aliases(client, app, instance, fake):
    first = _effect(client, app, instance, occurrence_ref="lab-alias-a")
    second = _effect(client, app, instance, occurrence_ref="lab-alias-b")         # other alert, binding, occurrence
    owner = _owner(instance, fake)
    outcomes, barrier = [], threading.Barrier(2)

    def start(effect_id):
        barrier.wait(5)
        outcomes.append(_call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                              (str(uuid.uuid4()), effect_id, instance, owner.generation, owner.incarnation))["outcome"])
    threads = [threading.Thread(target=start, args=(e,)) for e in (first, second)]
    [t.start() for t in threads]
    [t.join(20) for t in threads]
    assert sorted(outcomes) == ["started", "target_guarded"], outcomes                # [native]
    assert len(_guards(instance)) == 1


@pytest.mark.parametrize("change,reason", [
    ("DELETE FROM voalack.accepted_kids WHERE kid = 'lab-k1'", "key_not_accepted"),
    ("UPDATE voalack.authorization_policy_active SET policy_revision = 3", "policy_revoked"),
    ("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %(instance)s", "config_changed"),
    ("SUSPEND", "owner_fenced"),
])
def test_final_check_after_consume_holds_without_sending(client, app, instance, fake, change, reason):
    effect_id = _effect(client, app, instance)
    holder = {}

    def invalidate(_):
        if change == "SUSPEND":
            sql("SELECT voalack.suspend_owner(%s, %s, %s)",
                (instance, holder["owner"].generation, holder["owner"].incarnation), fetch=False)
        else:
            sql(change, {"instance": instance}, fetch=False)
    owner = holder["owner"] = _owner(instance, fake, hooks={"before_send": invalidate})
    try:
        result = owner.apply_once(effect_id)
    finally:
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
        sql("INSERT INTO voalack.accepted_kids VALUES ('lab-k1') ON CONFLICT DO NOTHING", fetch=False)
    assert (result["outcome"], result["reason"]) == ("held", reason), result
    assert _attempt(result["attempt_id"]) == ("uncertain", "consumed")                 # never aborted or released
    assert _effect_state(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["reads"] == 1        # the preflight only (amended)


@pytest.mark.parametrize("ack_status,read_status", [(500, 200), (200, 500), (202, 200)])
def test_non_200_statuses_never_confirm(client, app, instance, fake, ack_status, read_status):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    ack_call, read_call = owner.transport.ack, owner.transport.read_alarm
    reads = []
    owner.transport.ack = lambda *a: (ack_status, ack_call(*a)[1])                     # scripted status

    def read_alarm(*a):                                    # amended: the preflight (first read) passes through
        reads.append(1)
        status, payload = read_call(*a)
        return (status if len(reads) == 1 else read_status), payload
    owner.transport.read_alarm = read_alarm
    assert owner.apply_once(effect_id)["outcome"] == "uncertain"
    assert _effect_state(effect_id) == ("UNCERTAIN", True)


def test_database_loss_after_start_stops_the_owner_locally(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    holder = {}
    owner = holder["owner"] = _owner(instance, fake, hooks={
        "after_start": lambda _: sql("SELECT pg_terminate_backend(%s)", (holder["owner"]._db().get_backend_pid(),))})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "database_lost") and owner.stopped == "database_lost"
    assert _attempt(result["attempt_id"]) == ("started", "unconsumed")                # left as the DB has it
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["logins"] == 0


def test_owner_fenced_before_consume_with_a_session_aborts_definitively(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    holder = {}

    def fence(_):
        _contain(instance, holder["owner"].generation)
        holder["successor"] = _owner(instance, fake, owner_id="lab-successor")
    # Amended for the follow-up preflight: fenced after the (fenced) preflight, so consume_dispatch itself
    # is the boundary that sees it.
    owner = holder["owner"] = _owner(instance, fake, hooks={"after_preflight": fence})
    owner.login()                                    # session exists: consume_dispatch itself sees the fence
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "aborted:owner_fenced"), result
    assert _attempt(result["attempt_id"]) == ("aborted_before_dispatch", "revoked")
    assert _effect_state(effect_id) == ("QUEUED", False) and _guards(instance) == []
    assert holder["successor"].apply_once(effect_id)["outcome"] == "confirmed"
    assert _counts(owner, fake)[:2] == (0, 0) and (fake.counts["receipts"], fake.counts["effects"]) == (1, 1)


# --- dddff53 review corrections -------------------------------------------------------------

def test_failed_hold_persistence_stops_the_whole_owner(client, app, instance, fake):
    effect_id = _effect(client, app, instance)

    def refuse_and_lose(_):
        sql("DELETE FROM voalack.accepted_kids WHERE kid = 'lab-k1'", fetch=False)      # final check fails
        sql("ALTER ROLE lab_sender NOLOGIN", fetch=False)                               # hold cannot connect
    owner = _owner(instance, fake, hooks={"before_send": refuse_and_lose})
    try:
        result = owner.apply_once(effect_id)
    finally:
        sql("ALTER ROLE lab_sender LOGIN", fetch=False)
        sql("INSERT INTO voalack.accepted_kids VALUES ('lab-k1') ON CONFLICT DO NOTHING", fetch=False)
    assert (result["outcome"], result["reason"]) == ("held", "key_not_accepted"), result
    assert owner.stopped == "database_lost"
    assert _attempt(result["attempt_id"]) == ("dispatched", "consumed")             # as the database has it
    with pytest.raises(OwnerStopped):
        owner.revoke()
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["revokes"] == 0 and fake.counts["reads"] == 1  # preflight (amended)


def test_repeated_start_never_outlives_the_original_deadline(client, app, instance, fake):
    signing = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(signing, capture_window=timedelta(seconds=1),
                                                            execution_window=timedelta(seconds=2))
    try:
        effect_id = _effect(client, app, instance)
    finally:
        app.extensions["voalack_signing"] = signing
    owner = _owner(instance, fake)
    args = (str(uuid.uuid4()), effect_id, instance, owner.generation, owner.incarnation)
    first = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", args)
    assert first["outcome"] == "started" and _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", args) == first
    deadline = sql("SELECT p.execution_expires_at FROM voalack.effects e JOIN voalack.prepared_intents p "
                   "USING (action_id) WHERE e.effect_id = %s", (effect_id,))[0][0]
    while not sql("SELECT clock_timestamp() >= %s", (deadline,))[0][0]:
        time.sleep(0.02)
    again = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", args)
    assert again["outcome"] == "expired" and again["request_sha256"] is None
    assert _attempt(args[0]) == ("started", "unconsumed")                           # unchanged, not refreshed


def test_new_start_waiting_on_the_guard_past_the_deadline_is_expired(client, app, instance, fake):
    signing = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(signing, capture_window=timedelta(seconds=1),
                                                            execution_window=timedelta(seconds=4))
    try:
        short = _effect(client, app, instance, occurrence_ref="lab-short")
    finally:
        app.extensions["voalack_signing"] = signing
    other = _effect(client, app, instance, occurrence_ref="lab-other")                # same physical target
    owner = _owner(instance, fake)
    admin = psycopg2.connect(DSN)                                                     # uncommitted competing guard
    admin.cursor().execute("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                           (str(uuid.uuid4()), other, instance, owner.generation, owner.incarnation))
    conn = psycopg2.connect(SENDER_DSN, options="-c lock_timeout=10000 -c statement_timeout=20000")
    box = {}

    def start():
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                        (str(uuid.uuid4()), short, instance, owner.generation, owner.incarnation))
            box.update(cur.fetchone())
        conn.commit()
    worker = threading.Thread(target=start)
    try:
        worker.start()
        limit = time.monotonic() + 5
        while not sql("SELECT count(*) FROM pg_stat_activity WHERE pid = %s AND %s = ANY(pg_blocking_pids(pid))",
                      (conn.get_backend_pid(), admin.get_backend_pid()))[0][0] and time.monotonic() < limit:
            time.sleep(0.02)
        deadline = sql("SELECT p.execution_expires_at FROM voalack.effects e JOIN voalack.prepared_intents p "
                       "USING (action_id) WHERE e.effect_id = %s", (short,))[0][0]
        while not sql("SELECT clock_timestamp() >= %s", (deadline,))[0][0]:
            time.sleep(0.02)
        admin.rollback()                                                              # the guard frees after expiry
        worker.join(15)
    finally:
        admin.close()
        conn.close()
    assert box.get("outcome") == "expired", box
    assert _effect_state(short) == ("QUEUED", False) and _guards(instance) == []


# --- follow-up: automated-review findings on PR #15 -----------------------------------------

def test_one_credential_cannot_back_two_instances(instance):
    with pytest.raises(psycopg2.errors.UniqueViolation):
        sql("INSERT INTO voalack.instance_config VALUES (%s, %s, 'fake-one/v1', 1)",
            (f"{instance}-alias", f"cred-{instance}"), fetch=False)


@pytest.mark.parametrize("change", ["credential", "revision"])
@pytest.mark.parametrize("logged_in", [False, True])
def test_configuration_change_after_acquire_stops_the_owner(client, app, instance, fake, logged_in, change):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    if logged_in:
        owner.login()                                                   # a session for the old credential
    if change == "credential":
        sql("UPDATE voalack.instance_config SET credential_ref = %s WHERE instance_id = %s",
            (f"cred-rotated-{instance}", instance), fetch=False)
    else:
        sql("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s", (instance,), fetch=False)
    with pytest.raises(OwnerStopped, match="config_changed"):
        owner.apply_once(effect_id)
    assert owner.stopped == "config_changed"
    assert sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0] == 0
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["logins"] == (1 if logged_in else 0)


def test_handoff_bound_includes_the_consume_commit(client, app, instance, fake):
    effect_id = _effect(client, app, instance)

    def slow_commit(conn):
        time.sleep(0.8)                                                  # COMMIT acknowledgement delayed
        conn.commit()
    owner = _owner(instance, fake, handoff_bound=0.5, hooks={"commit:consume": slow_commit})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "handoff_not_immediate"), result
    assert _attempt(result["attempt_id"]) == ("uncertain", "consumed")
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_verifier_with_an_extra_read_is_not_ready(app):
    sql("GRANT SELECT ON voalack.attempts TO voalack_verifier", fetch=False)
    try:
        with psycopg2.connect(VERIFIER_DSN) as conn:
            with pytest.raises(verifier.NotReady, match="extra_read"):
                verifier.check_ready(conn)
    finally:
        sql("REVOKE SELECT ON voalack.attempts FROM voalack_verifier", fetch=False)



# --- follow-up F1-F4 (design response d4639640) --------------------------------------------

def test_preflight_positive_reads_before_and_after(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    assert _counts(owner, fake) == (1, 1, 1, 1) and fake.counts["reads"] == 2          # preflight + read-back


def test_already_acknowledged_target_is_closed_without_dispatch(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    original = {"target_id": "4711", "kind": "triggered_alarm", "acked": True, "acked_by_operation": "someone-else",
                "comment": "operator note"}                     # kind: S3a explicit fake contract (amended)
    fake.alarms["4711"] = dict(original)
    owner = _owner(instance, fake)
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "already_acked"), result
    assert _attempt(result["attempt_id"]) == ("aborted_before_dispatch", "revoked")
    assert _effect_state(effect_id) == ("ALREADY_ACKED", False) and _guards(instance) == []
    assert fake.alarms["4711"] == original                                               # not overwritten
    assert sql("SELECT kind FROM voalack.attempt_evidence WHERE attempt_id = %s", (result["attempt_id"],)) == [
        ("preflight_already_acked",)]
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["reads"] == 1


@pytest.mark.parametrize("mode", ["error", "ambiguous", "wrong_target", "transport_error"])
def test_uninterpretable_preflight_is_a_definitive_no_dispatch(client, app, instance, fake, mode):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    if mode == "transport_error":
        def failing(*_):
            raise ConnectionResetError("lab: scripted transport failure")
        owner.transport.read_alarm = failing
    else:
        fake.script["read"] = mode
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "preflight_unavailable"), result
    assert _attempt(result["attempt_id"]) == ("aborted_before_dispatch", "revoked")
    assert _effect_state(effect_id) == ("QUEUED", False) and _guards(instance) == []
    assert sql("SELECT kind FROM voalack.attempt_evidence WHERE attempt_id = %s", (result["attempt_id"],)) == [
        ("preflight_unavailable",)]
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_preflight_delay_past_the_deadline_is_refused_at_consume(client, app, instance, fake):
    signing = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(signing, capture_window=timedelta(seconds=1),
                                                            execution_window=timedelta(seconds=3))
    try:
        effect_id = _effect(client, app, instance)
    finally:
        app.extensions["voalack_signing"] = signing
    remaining = sql("SELECT extract(epoch FROM p.execution_expires_at - clock_timestamp()) FROM voalack.effects e "
                    "JOIN voalack.prepared_intents p USING (action_id) WHERE e.effect_id = %s", (effect_id,))[0][0]
    fake.script["read_delay"] = float(remaining) + 0.3
    owner = _owner(instance, fake)
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "aborted:expired"), result
    assert _effect_state(effect_id) == ("BLOCKED", False)
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_configuration_change_during_preflight_is_refused_at_consume(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake, hooks={"after_preflight": lambda _: sql(
        "UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s", (instance,), fetch=False)})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "aborted:config_changed"), result
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_start_refuses_configuration_drift_in_sql(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    admin = psycopg2.connect(DSN)                                          # native configuration-row wait
    admin.cursor().execute("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s", (instance,))
    conn = psycopg2.connect(SENDER_DSN, options="-c lock_timeout=10000")
    box = {}

    def start():
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                        (str(uuid.uuid4()), effect_id, instance, owner.generation, owner.incarnation))
            box.update(cur.fetchone())
        conn.commit()
    worker = threading.Thread(target=start)
    try:
        worker.start()
        limit = time.monotonic() + 5
        while not sql("SELECT count(*) FROM pg_stat_activity WHERE pid = %s AND %s = ANY(pg_blocking_pids(pid))",
                      (conn.get_backend_pid(), admin.get_backend_pid()))[0][0] and time.monotonic() < limit:
            time.sleep(0.02)
        admin.commit()
        worker.join(15)
    finally:
        admin.close()
        conn.close()
    assert box.get("outcome") == "config_changed", box
    assert sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0] == 0


def test_native_consume_wait_counts_toward_the_handoff_bound(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    admin = psycopg2.connect(DSN)

    def hold_effect_row(_):
        admin.cursor().execute("SELECT 1 FROM voalack.effects WHERE effect_id = %s FOR UPDATE", (effect_id,))
        threading.Timer(0.8, admin.rollback).start()                       # consume waits ~0.8 s natively
    owner = _owner(instance, fake, handoff_bound=0.5, hooks={"after_preflight": hold_effect_row})
    try:
        result = owner.apply_once(effect_id)
    finally:
        time.sleep(0.9)
        admin.close()
    assert (result["outcome"], result["reason"]) == ("held", "handoff_not_immediate"), result
    assert _attempt(result["attempt_id"]) == ("uncertain", "consumed")
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_rotated_credential_stays_reserved_until_containment(client, app, instance, fake):
    first = _owner(instance, fake)                                         # acquired under cred-<instance>
    sql("UPDATE voalack.instance_config SET credential_ref = %s WHERE instance_id = %s",
        (f"cred-rotated-{instance}", instance), fetch=False)
    other = f"{instance}-b"
    sql("INSERT INTO voalack.instance_config VALUES (%s, %s, 'fake-one/v1', 1)", (other, f"cred-{instance}"), fetch=False)
    with pytest.raises(psycopg2.errors.RaiseException, match="credential is held"):
        _owner(other, fake, owner_id="lab-b")
    _contain(instance, first.generation)
    second = _owner(other, fake, owner_id="lab-b")
    assert second.generation == 1 and fake.counts["logins"] == 0


# --- follow-up preliminary concerns (4ebc45e5) ----------------------------------------------

def _no_new_network(owner, fake, before):
    with pytest.raises(OwnerStopped):
        owner.login()
    with pytest.raises(OwnerStopped):
        owner.revoke()
    assert (dict(owner.transport.counts), dict(fake.counts)) == before


@pytest.mark.parametrize("hook,expected", [
    ("after_preflight", ("refused", "aborted:config_changed")),          # consume detects it
    ("before_send", ("held", "config_changed")),                        # the final check detects it
])
def test_detected_configuration_drift_stops_the_owner_even_after_an_aba_restore(client, app, instance, fake,
                                                                               hook, expected):
    effect_id = _effect(client, app, instance)
    change = lambda _: sql("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s",
                           (instance,), fetch=False)
    owner = _owner(instance, fake, hooks={hook: change})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == expected, result
    assert owner.stopped == "config_changed"
    if hook == "before_send":
        assert _attempt(result["attempt_id"]) == ("uncertain", "consumed")      # consumed: held, guard kept
        assert _guards(instance) == [("4711", "uncertain")]
    else:
        assert _attempt(result["attempt_id"]) == ("aborted_before_dispatch", "revoked")
    sql("UPDATE voalack.instance_config SET config_revision = 1 WHERE instance_id = %s", (instance,), fetch=False)
    before = (dict(owner.transport.counts), dict(fake.counts))
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)
    _no_new_network(owner, fake, before)
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_configuration_drift_is_not_concealed_by_an_eligibility_refusal(client, app, instance, fake):
    effect_id = _effect(client, app, instance)

    def both(_):
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 3", fetch=False)
        sql("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s", (instance,), fetch=False)
    owner = _owner(instance, fake, hooks={"after_preflight": both})
    try:
        result = owner.apply_once(effect_id)
    finally:
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
    assert (result["outcome"], result["reason"]) == ("refused", "aborted:config_changed"), result
    assert owner.stopped == "config_changed"


def test_already_acked_observed_under_changed_configuration_is_not_settled(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True,   # kind: S3a (amended)
                           "acked_by_operation": "someone-else", "comment": "x"}
    fake.script["read_delay"] = 0.8
    owner = _owner(instance, fake)
    timer = threading.Timer(0.3, lambda: sql("UPDATE voalack.instance_config SET config_revision = 2 "
                                             "WHERE instance_id = %s", (instance,), fetch=False))
    owner.login()
    timer.start()                                                        # changes while the preflight executes
    result = owner.apply_once(effect_id)
    timer.join(5)
    assert (result["outcome"], result["reason"]) == ("held", "config_changed"), result
    assert owner.stopped == "config_changed"
    assert _attempt(result["attempt_id"]) == ("started", "unconsumed")        # no settlement, guard kept
    assert _effect_state(effect_id) == ("QUEUED", True) and _guards(instance) == [("4711", "in_flight")]
    assert sql("SELECT kind FROM voalack.attempt_evidence WHERE attempt_id = %s", (result["attempt_id"],)) == [
        ("late_preflight",)]
    assert _counts(owner, fake) == (0, 0, 0, 0)


def test_owner_acquired_before_the_snapshot_existed_is_stopped(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    sql("UPDATE voalack.session_owners SET bound_credential_ref = NULL, bound_config_revision = NULL, "
        "bound_provider_contract = NULL WHERE instance_id = %s", (instance,), fetch=False)   # upgrade from d263af6
    with pytest.raises(OwnerStopped, match="config_changed"):
        owner.apply_once(effect_id)
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["logins"] == 0
    # A legacy owner with an unknown credential blocks every other acquisition until it is contained
    # (fail closed, see the next test); contain it so later tests are unaffected.
    _contain(instance, owner.generation)


def test_reinstalling_the_schema_adds_the_credential_uniqueness_to_an_existing_table(app):
    # [lab] S3c-2b-4 (reviews 53fd486f and 3d30c299, after s3c2b4g1-test-1's deadlock at this test cascaded into 361
    # verifier refusals): the upgrade path runs in a DEDICATED disposable database with the full assembly installed,
    # never in the shared app database, so a failure here cannot leave other tests without the uniqueness. The
    # uniqueness is durably absent on the existing table before the reinstall; the reinstall and the verifier assertions
    # are the original ones. Every connection this test opens is closed in all cases; the diagnostic and the cleanup
    # are bounded (connect and statement timeouts); a reinstall failure propagates as the ORIGINAL exception (its other
    # backends, or why they are unavailable, attached as a note); a cleanup failure never replaces an earlier failure.
    # Review 900afe47: the database is dropped only if THIS test's CREATE succeeded (a failed or colliding CREATE owns
    # nothing); connection-close errors are kept as secondary evidence and never replace the first failure.
    from test_t04_s3a_upgrade import STUB_ALERTA
    from voalack import schema
    from voalack.schema import schema_sql
    name = f"voalack_reinstall_{uuid.uuid4().hex[:8]}"
    dsn = DSN.rsplit("/", 1)[0] + "/" + name
    owned = []

    def connect(target):
        conn = psycopg2.connect(target, connect_timeout=10)
        owned.append(conn)
        return conn

    admin = psycopg2.connect(DSN, connect_timeout=10)
    admin.autocommit = True
    primary = None
    created = False
    try:
        with admin.cursor() as cur:
            cur.execute(f"CREATE DATABASE {name}")
        created = True
        conn = connect(dsn)
        with conn.cursor() as cur:
            cur.execute(STUB_ALERTA)
        conn.commit()
        schema.apply(connect(dsn))
        conn = connect(dsn)
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE voalack.instance_config DROP CONSTRAINT instance_config_credential_ref_key")
        conn.commit()
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_constraint WHERE conname = 'instance_config_credential_ref_key'")
            assert cur.fetchone()[0] == 0                                # durably absent before the upgrade
        conn.rollback()
        conn = connect(dsn)
        try:
            with conn.cursor() as cur:                                   # idempotent upgrade path
                cur.execute(schema_sql())                                # (no parameters: '%' is literal)
            conn.commit()
        except psycopg2.Error as exc:
            try:
                with admin.cursor() as cur:
                    cur.execute("SET statement_timeout = '10s'")
                    cur.execute("SELECT pid, usename, state, wait_event_type, left(query, 120) FROM pg_stat_activity "
                                "WHERE datname = %s ORDER BY pid LIMIT 20", (name,))
                    exc.add_note(f"backends of {name} at the failure: {cur.fetchall()}")
            except Exception as diag:                                    # never replaces the primary failure
                exc.add_note(f"backend diagnostic unavailable: {type(diag).__name__}: {diag}")
            raise
        conn = connect(dsn)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_constraint WHERE conname = 'instance_config_credential_ref_key'")
            assert cur.fetchone()[0] == 1
        conn.rollback()
        verifier.check_ready(connect(SENDER_DSN.rsplit("/", 1)[0] + "/" + name), sender.SENDER)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        secondary = []                                                   # close errors: evidence, never the failure
        for conn in owned:
            try:
                conn.close()
            except Exception as exc:
                secondary.append(f"close: {type(exc).__name__}: {exc}")
        cleanup = None
        if created:                                                      # only a database this test created
            try:
                with admin.cursor() as cur:
                    cur.execute("SET statement_timeout = '30s'")
                    cur.execute(f"DROP DATABASE {name} WITH (FORCE)")
            except Exception as exc:
                cleanup = exc
        try:
            admin.close()
        except Exception as exc:
            secondary.append(f"admin close: {type(exc).__name__}: {exc}")
        first = primary
        if cleanup is not None:
            if first is not None:
                first.add_note(f"the disposable database cleanup also failed: {type(cleanup).__name__}: {cleanup}")
            else:
                first = AssertionError(f"disposable database {name} was not dropped: {cleanup}")
                first.__cause__ = cleanup
        for note in secondary:                                           # kept with the failure, else as a warning
            if first is not None:
                first.add_note(note)
            else:
                warnings.warn(f"disposable database {name}: {note}")
        if first is not None and primary is None:
            raise first


@pytest.mark.parametrize("legacy_state", ["active", "suspended"])
def test_legacy_owner_with_unknown_credential_blocks_other_acquisitions(client, app, instance, fake, legacy_state):
    legacy = _owner(instance, fake, owner_id="lab-legacy")
    legacy.login()                                                       # old session still live at the provider
    sql("UPDATE voalack.session_owners SET bound_credential_ref = NULL, bound_config_revision = NULL, "
        "bound_provider_contract = NULL, state = %s WHERE instance_id = %s", (legacy_state, instance), fetch=False)
    sql("UPDATE voalack.instance_config SET credential_ref = %s WHERE instance_id = %s",
        (f"cred-rotated-{instance}", instance), fetch=False)
    other = f"{instance}-b"
    sql("INSERT INTO voalack.instance_config VALUES (%s, %s, 'fake-one/v1', 1)", (other, f"cred-{instance}"), fetch=False)
    before = dict(fake.counts)
    with pytest.raises(psycopg2.errors.RaiseException, match="credential is held"):
        _owner(other, fake, owner_id="lab-b")
    assert dict(fake.counts) == before and fake.max_concurrent[f"cred-{instance}"] == 1
    with fake.lock:                                                      # operator revokes the old session
        fake.sessions.clear()
    _contain(instance, legacy.generation, basis="lab: legacy owner stopped, session revoked, provider idle")
    second = _owner(other, fake, owner_id="lab-b")
    assert second.generation == 1 and dict(fake.counts) == before


# --- 0421319 review (F2-R1): configuration fence at final settlement -------------------------

def test_settlement_waiting_on_a_configuration_change_is_held_and_stops_the_owner(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    admin = psycopg2.connect(DSN)

    def change_while_settling(_):
        admin.cursor().execute("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s",
                               (instance,))
        threading.Timer(0.5, admin.commit).start()                       # settlement waits, then sees it
    owner = _owner(instance, fake, hooks={"before_record": change_while_settling})
    try:
        result = owner.apply_once(effect_id)
    finally:
        time.sleep(0.6)
        admin.close()
    assert (result["outcome"], result["reason"]) == ("held", "config_changed"), result
    assert owner.stopped == "config_changed"
    assert _attempt(result["attempt_id"]) == ("uncertain", "consumed")
    assert _effect_state(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    assert [k for (k,) in sql("SELECT kind FROM voalack.attempt_evidence WHERE attempt_id = %s ORDER BY evidence_id",
                              (result["attempt_id"],))] == ["late_result"]
    sql("UPDATE voalack.instance_config SET config_revision = 1 WHERE instance_id = %s", (instance,), fetch=False)
    before = (dict(owner.transport.counts), dict(fake.counts))           # ABA restore: still stopped locally
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)
    _no_new_network(owner, fake, before)
    assert _counts(owner, fake) == (1, 1, 1, 1)


def test_database_failure_at_settlement_stops_without_settling(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    holder = {}

    def lose_database(_):
        sql("ALTER ROLE lab_sender NOLOGIN", fetch=False)                # suspension cannot be persisted either
        sql("SELECT pg_terminate_backend(%s)", (holder["owner"]._db().get_backend_pid(),))
    owner = holder["owner"] = _owner(instance, fake, hooks={"before_record": lose_database})
    try:
        result = owner.apply_once(effect_id)
    finally:
        sql("ALTER ROLE lab_sender LOGIN", fetch=False)
    assert (result["outcome"], result["reason"]) == ("held", "database_lost"), result
    assert owner.stopped == "database_lost"
    assert _attempt(result["attempt_id"]) == ("dispatched", "consumed")          # as the database has it
    assert _guards(instance) == [("4711", "in_flight")] and _effect_state(effect_id)[0] == "QUEUED"
    before = (dict(owner.transport.counts), dict(fake.counts))
    _no_new_network(owner, fake, before)
    assert _counts(owner, fake) == (1, 1, 1, 1)
