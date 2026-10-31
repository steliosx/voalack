"""T04 S3a: explicit-connect transport, no-write settlement (not_sent), bounded durable retry and
target refusals. Fake ONE provider on loopback.

Labels: [native] a real kernel-level connect refusal or real PostgreSQL behaviour; [scripted] a
Python hook replaces a call (connect timeout, socket closed after connect, status substitution).
Counts per phase: adapter dispatch entries, ACK connects / connect failures, ACK write-phase entries,
provider receipts and effects.
"""
import dataclasses
import json
import socket
import time
import uuid
from datetime import timedelta

import psycopg2
import pytest

from conftest import DSN, SENDER_DSN, sql
from test_t04_s2_sender import (_attempt, _call, _contain, _effect, _effect_state, _guards, _owner, fake,  # noqa: F401
                                instance)
from voalack.sender import OwnerStopped, UnknownCommit


def _closed_port():
    """A loopback port bound but never listening, held for the test (no reuse race). Amended after
    review 9329f672: the original closed-and-released port gave PermissionError in another guest."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    return probe.getsockname()[1], probe


def _phase(owner, fake):
    return {"dispatch": owner.counts["dispatch_entries"], "connects": owner.transport.phase_counts["ack_connects"],
            "connect_failures": owner.transport.phase_counts["ack_connect_failures"],
            "writes": owner.transport.counts["ack_writes"], "receipts": fake.counts["receipts"],
            "effects": fake.counts["effects"]}


def _refuse_ack_connects(owner, times):
    """Point only the ACK connection at a closed port for the next ``times`` sends; login and reads
    keep the provider's port. [native refusal; the port switch is scripted]"""
    good, left = owner.transport.port, {"n": times}
    closed, held = _closed_port()

    def before_send(_):
        owner.transport.port = closed if left["n"] > 0 else good
        left["n"] -= 1

    def after_start(_):
        owner.transport.port = good                  # preflight reads use the provider's port
    owner.hooks["after_start"] = after_start
    return {"before_send": before_send, "held_socket": held,
            "restore": lambda: (setattr(owner.transport, "port", good), held.close())}


def _effect_budget(effect_id):
    return sql("SELECT state, attempt_count, next_attempt_after IS NOT NULL FROM voalack.effects WHERE effect_id = %s",
               (effect_id,))[0]


# --- not_sent ---------------------------------------------------------------------------------

def test_refused_connect_is_not_sent_with_zero_writes(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    hooks = _refuse_ack_connects(owner, 1)
    owner.hooks.update(before_send=hooks["before_send"])
    result = owner.apply_once(effect_id)
    hooks["restore"]()
    # Amended after review 9329f672 (original asserted ConnectionRefusedError only): a native
    # kernel refusal of the loopback connect; which errno the guest network maps it to (ECONNREFUSED
    # or EACCES) is recorded from the original invocation and must be consistent with the class.
    assert result["outcome"] == "not_sent", result
    assert result["reason"] in ("ConnectionRefusedError", "PermissionError"), result
    assert _attempt(result["attempt_id"]) == ("not_sent", "consumed")
    assert _effect_budget(effect_id) == ("QUEUED", 1, True) and _guards(instance) == []
    evidence = sql("SELECT kind, detail FROM voalack.attempt_evidence WHERE attempt_id = %s", (result["attempt_id"],))
    assert evidence[0][0] == "not_sent" and evidence[0][1]["ack_writes"] == 0
    native = evidence[0][1]["connect"]
    assert (native["class"], native["errno"]) in (("ConnectionRefusedError", "ECONNREFUSED"),
                                                  ("PermissionError", "EACCES")), native
    assert native["class"] == result["reason"] and native["socket_after_connect"] is None
    assert evidence[0][1]["request_sha256"] == sql("SELECT request_sha256 FROM voalack.attempts WHERE attempt_id = %s",
                                                   (result["attempt_id"],))[0][0]
    assert _phase(owner, fake) == {"dispatch": 1, "connects": 1, "connect_failures": 1, "writes": 0, "receipts": 0,
                                   "effects": 0}
    again = owner.apply_once(effect_id)                                   # durable backoff, same owner
    assert (again["outcome"], again["reason"]) == ("refused", "backoff_pending")


def test_retry_after_not_sent_confirms_with_exactly_one_receipt(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    hooks = _refuse_ack_connects(owner, 1)
    owner.hooks.update(before_send=hooks["before_send"])
    result = owner.apply_with_retry(effect_id)
    assert result["outcome"] == "confirmed", result
    assert _effect_budget(effect_id)[:2] == ("REMOTE_CONFIRMED", 2)
    assert sql("SELECT state FROM voalack.attempts WHERE effect_id = %s ORDER BY started_at", (effect_id,)) == [
        ("not_sent",), ("confirmed",)]
    assert _phase(owner, fake) == {"dispatch": 2, "connects": 2, "connect_failures": 1, "writes": 1, "receipts": 1,
                                   "effects": 1}


def test_budget_of_three_attempts_then_blocked(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    hooks = _refuse_ack_connects(owner, 5)
    owner.hooks.update(before_send=hooks["before_send"])
    result = owner.apply_with_retry(effect_id)
    hooks["restore"]()
    assert (result["outcome"], result.get("retry"), result.get("effect_state")) == ("not_sent", "stopped", "BLOCKED")
    assert _effect_budget(effect_id)[:2] == ("BLOCKED", 3)
    assert _phase(owner, fake)["receipts"] == 0 and _phase(owner, fake)["writes"] == 0
    assert owner.apply_once(effect_id)["reason"] == "effect_not_queued"
    sql("SELECT voalack._pin_epoch(); "                    # T04 S4 (disclosed fixture amendment): pin first
        "UPDATE voalack.effects SET state = 'QUEUED' WHERE effect_id = %s", (effect_id,), fetch=False)  # lab only
    assert owner.apply_once(effect_id)["reason"] == "attempt_budget_exhausted"   # budget itself, independently


def test_restarted_owner_cannot_reset_backoff_or_budget(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    first = _owner(instance, fake)
    hooks = _refuse_ack_connects(first, 1)
    first.hooks.update(before_send=hooks["before_send"])
    assert first.apply_once(effect_id)["outcome"] == "not_sent"
    sql("UPDATE voalack.effects SET next_attempt_after = clock_timestamp() + interval '30 seconds' "
        "WHERE effect_id = %s", (effect_id,), fetch=False)                # lab: a long backoff window
    first.stop("lab restart")
    _contain(instance, first.generation)
    restarted = _owner(instance, fake, owner_id="lab-restarted")
    assert restarted.apply_once(effect_id)["reason"] == "backoff_pending"
    assert _effect_budget(effect_id)[:2] == ("QUEUED", 1)


def test_scripted_connect_timeout_without_socket_is_not_sent(client, app, instance, fake, monkeypatch):
    effect_id = _effect(client, app, instance)

    def no_socket(*_args, **_kwargs):
        raise TimeoutError("lab: scripted connect timeout")
    owner = _owner(instance, fake, hooks={"before_send": lambda _: monkeypatch.setattr(socket, "create_connection",
                                                                                        no_socket)})
    result = owner.apply_once(effect_id)
    monkeypatch.undo()
    assert (result["outcome"], result["reason"]) == ("not_sent", "TimeoutError"), result
    assert _phase(owner, fake)["writes"] == 0 and fake.counts["receipts"] == 0


# --- after a successful connect: never not_sent ---------------------------------------------

@pytest.mark.parametrize("change,reason", [
    ("config", "config_changed"), ("suspend", "owner_fenced"), ("handoff", "handoff_not_immediate"),
    ("deadline", "expired"),
])
def test_refusal_after_connect_holds_with_zero_writes(client, app, instance, fake, change, reason):
    signing = app.extensions["voalack_signing"]
    if change == "deadline":
        app.extensions["voalack_signing"] = dataclasses.replace(signing, capture_window=timedelta(seconds=1),
                                                                execution_window=timedelta(seconds=3))
    try:
        effect_id = _effect(client, app, instance)
    finally:
        app.extensions["voalack_signing"] = signing
    holder = {}

    def after_connect(_):
        if change == "config":
            sql("UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s", (instance,), fetch=False)
        elif change == "suspend":
            o = holder["owner"]
            sql("SELECT voalack.suspend_owner(%s, %s, %s)", (instance, o.generation, o.incarnation), fetch=False)
        elif change == "handoff":
            time.sleep(0.6)                                               # a slow connect
        else:
            deadline = sql("SELECT p.execution_expires_at FROM voalack.effects e JOIN voalack.prepared_intents p "
                           "USING (action_id) WHERE e.effect_id = %s", (effect_id,))[0][0]
            while not sql("SELECT clock_timestamp() >= %s", (deadline,))[0][0]:
                time.sleep(0.05)
    bound = 0.5 if change == "handoff" else 10.0
    owner = holder["owner"] = _owner(instance, fake, handoff_bound=bound, hooks={"after_connect": after_connect})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", reason), result
    assert _attempt(result["attempt_id"]) == ("uncertain", "consumed")
    assert _guards(instance) == [("4711", "uncertain")]
    assert _phase(owner, fake) == {"dispatch": 1, "connects": 1, "connect_failures": 0, "writes": 0, "receipts": 0,
                                   "effects": 0}
    if change in ("config", "suspend"):
        assert owner.stopped in ("config_changed", "fenced")


def test_no_implicit_reconnect_after_the_socket_is_lost(client, app, instance, fake):
    effect_id = _effect(client, app, instance)

    def drop_socket(conn):
        conn.sock.close()                                                 # [scripted] lost after connect
        conn.sock = None
    owner = _owner(instance, fake, hooks={"after_connect": drop_socket})
    result = owner.apply_once(effect_id)
    assert result["outcome"] == "uncertain", result                      # write phase entered: never not_sent
    assert _phase(owner, fake) == {"dispatch": 1, "connects": 1, "connect_failures": 0, "writes": 1, "receipts": 0,
                                   "effects": 0}


# --- after the write: uncertain, no retry ---------------------------------------------------

@pytest.mark.parametrize("mode", ["close_before_body", "close_after_body", "status_401", "status_403",
                                  "status_429", "status_500", "post_connect_timeout"])
def test_post_write_failures_are_uncertain_and_never_retried(client, app, instance, fake, mode):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    if mode.startswith("status_"):
        call = owner.transport.ack
        owner.transport.ack = lambda *a: (int(mode[7:]), call(*a)[1])   # [scripted] status, real payload
    elif mode == "post_connect_timeout":
        owner.transport.timeout = 0.5
        fake.script["delay"] = 1.5                                        # the fake completes later
    else:
        fake.script["ack"] = mode
    result = owner.apply_with_retry(effect_id)
    assert result["outcome"] == "uncertain" and "retry" not in result, result
    assert _attempt(result["attempt_id"])[0] == "uncertain" and _guards(instance) == [("4711", "uncertain")]
    assert sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0] == 1
    assert _phase(owner, fake)["writes"] == 1 and _phase(owner, fake)["connect_failures"] == 0
    if mode == "post_connect_timeout":
        limit = time.monotonic() + 5
        while fake.counts["effects"] == 0 and time.monotonic() < limit:   # late remote completion
            time.sleep(0.05)
        assert fake.counts["effects"] == 1 and _attempt(result["attempt_id"])[0] == "uncertain"


# --- record_not_sent boundaries -------------------------------------------------------------------

def test_record_not_sent_requires_the_exact_dispatched_attempt_and_zero_writes(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    attempt_id = str(uuid.uuid4())
    started = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                    (attempt_id, effect_id, instance, owner.generation, owner.incarnation))
    args = (attempt_id, instance, owner.generation, owner.incarnation)
    good = {"request_sha256": started["request_sha256"], "ack_writes": 0}
    call = "SELECT voalack.record_not_sent(%s, %s, %s, %s, %s::jsonb) AS o"
    assert _call(call, args + (json.dumps(good),))["o"] == "not_recordable:started"      # not consumed yet
    assert _call("SELECT * FROM voalack.consume_dispatch(%s, %s, %s, %s)", args)["outcome"] == "dispatched"
    assert _call(call, args + (json.dumps({**good, "ack_writes": 1}),))["o"] == "evidence_mismatch"
    assert _call(call, args + (json.dumps({**good, "request_sha256": "0" * 64}),))["o"] == "evidence_mismatch"
    assert _call(call, (attempt_id, instance, owner.generation, str(uuid.uuid4()), json.dumps(good)))["o"] == \
        "owner_fenced"
    assert _call(call, args + (json.dumps(good),))["o"] == "not_sent"
    assert _call(call, args + (json.dumps(good),))["o"] == "not_recordable:not_sent"     # no second release
    assert _attempt(attempt_id) == ("not_sent", "consumed")


def test_unknown_not_sent_commit_stops_without_retry(client, app, instance, fake):
    effect_id = _effect(client, app, instance)

    def rollback_then_raise(conn):
        conn.rollback()
        raise UnknownCommit("lab: not_sent commit hidden")
    owner = _owner(instance, fake, hooks={"commit:not_sent": rollback_then_raise})
    hooks = _refuse_ack_connects(owner, 3)
    owner.hooks.update(before_send=hooks["before_send"])
    result = owner.apply_with_retry(effect_id)
    hooks["restore"]()
    assert (result["outcome"], result["reason"]) == ("held", "unknown_not_sent_commit"), result
    assert owner.stopped == "unknown_not_sent_commit"
    assert _attempt(result["attempt_id"]) == ("dispatched", "consumed")       # as the database has it
    assert _phase(owner, fake)["connects"] == 1 and fake.counts["receipts"] == 0
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)


# --- target refusals (A6) --------------------------------------------------------------------

@pytest.mark.parametrize("mode,reason,state", [("grouped", "unsupported_target", "BLOCKED"),
                                               ("no_kind", "preflight_unavailable", "QUEUED")])
def test_unsupported_or_unstated_target_kind_sends_nothing(client, app, instance, fake, mode, reason, state):
    effect_id = _effect(client, app, instance)
    fake.script["read"] = mode
    owner = _owner(instance, fake)
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", reason), result
    assert _effect_state(effect_id) == (state, False) and _guards(instance) == []
    assert _phase(owner, fake)["connects"] == 0 and fake.counts["receipts"] == 0


def test_uncertain_guard_survives_policy_loss_and_alias_occurrences(client, app, instance, fake):
    first = _effect(client, app, instance, occurrence_ref="lab-s3a-first")
    fake.script["ack"] = "close_after_body"
    owner = _owner(instance, fake)
    assert owner.apply_once(first)["outcome"] == "uncertain"
    fake.script["ack"] = "success"
    alias = _effect(client, app, instance, occurrence_ref="lab-s3a-alias")
    sql("UPDATE voalack.authorization_policy_active SET policy_revision = 3", fetch=False)
    try:
        assert owner.apply_once(alias)["reason"] in ("policy_revoked", "target_guarded")
    finally:
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
    assert owner.apply_once(alias)["reason"] == "target_guarded"
    assert _guards(instance) == [("4711", "uncertain")] and fake.counts["receipts"] == 1


def test_record_not_sent_refuses_when_the_attempt_no_longer_owns_its_guard(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    attempt_id = str(uuid.uuid4())
    args = (attempt_id, instance, owner.generation, owner.incarnation)
    started = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", (attempt_id, effect_id) + args[1:])
    assert _call("SELECT * FROM voalack.consume_dispatch(%s, %s, %s, %s)", args)["outcome"] == "dispatched"
    sql("DELETE FROM voalack.target_guards WHERE attempt_id = %s", (attempt_id,), fetch=False)   # lab: lost guard
    evidence = json.dumps({"request_sha256": started["request_sha256"], "ack_writes": 0})
    assert _call("SELECT voalack.record_not_sent(%s, %s, %s, %s, %s::jsonb) AS o", args + (evidence,))["o"] == \
        "not_recordable:dispatched"
    assert _attempt(attempt_id) == ("dispatched", "consumed") and _effect_state(effect_id) == ("QUEUED", True)


# --- preliminary review 121dc428: retry lineage (P1) and scheduling on the shared connection (P2) ---

def _expire_backoff(effect_id):
    sql("UPDATE voalack.effects SET next_attempt_after = clock_timestamp() - interval '1 second' "
        "WHERE effect_id = %s", (effect_id,), fetch=False)               # lab: backoff already elapsed


def _commit_then_raise(conn):
    conn.commit()
    raise UnknownCommit("lab: not_sent committed, acknowledgement lost")


def _rollback_then_raise(conn):
    conn.rollback()
    raise UnknownCommit("lab: not_sent rolled back, acknowledgement lost")


@pytest.mark.parametrize("fault,attempt_state", [(_commit_then_raise, ("not_sent", "consumed")),
                                                 (_rollback_then_raise, ("dispatched", "consumed"))])
def test_unknown_not_sent_commit_grants_no_retry_to_a_successor(client, app, instance, fake, fault, attempt_state):
    effect_id = _effect(client, app, instance)
    first = _owner(instance, fake, hooks={"commit:not_sent": fault})
    hooks = _refuse_ack_connects(first, 1)
    first.hooks.update(before_send=hooks["before_send"])
    result = first.apply_once(effect_id)
    hooks["restore"]()
    assert (result["outcome"], result["reason"]) == ("held", "unknown_not_sent_commit") and first.stopped
    assert _attempt(result["attempt_id"]) == attempt_state
    _contain(instance, first.generation)
    successor = _owner(instance, fake, owner_id="lab-successor")
    _expire_backoff(effect_id)
    retried = successor.apply_once(effect_id)
    expected = "retry_lineage_mismatch" if attempt_state[0] == "not_sent" else "effect_not_queued"
    assert (retried["outcome"], retried["reason"]) == ("refused", expected), retried
    assert sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0] == 1
    assert successor.transport.counts == {"ack_writes": 0, "logins": 0, "reads": 0, "revokes": 0}
    assert successor.transport.phase_counts["ack_connects"] == 0 and fake.counts["receipts"] == 0


def test_reconstructed_process_cannot_retry_a_known_not_sent(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    first = _owner(instance, fake)
    hooks = _refuse_ack_connects(first, 1)
    first.hooks.update(before_send=hooks["before_send"])
    assert first.apply_once(effect_id)["outcome"] == "not_sent"          # known commit, then the process dies
    hooks["restore"]()
    first.stop("lab: process died")
    _contain(instance, first.generation)
    successor = _owner(instance, fake, owner_id="lab-reconstructed")
    _expire_backoff(effect_id)
    assert successor.apply_once(effect_id)["reason"] == "retry_lineage_mismatch"
    assert successor.transport.counts == {"ack_writes": 0, "logins": 0, "reads": 0, "revokes": 0}
    assert _effect_budget(effect_id)[:2] == ("QUEUED", 1)


def test_scheduling_read_cannot_commit_another_operations_transaction(client, app, instance, fake):
    import threading
    first = _effect(client, app, instance, occurrence_ref="lab-sched-a", target_id="4711")
    second = _effect(client, app, instance, occurrence_ref="lab-sched-b", target_id="4712")
    gate, observed = threading.Event(), {}
    owner = _owner(instance, fake)
    hooks = _refuse_ack_connects(owner, 1)
    owner.hooks.update(before_send=hooks["before_send"],
                       before_schedule=lambda _: gate.wait(10))          # the retry loop pauses here

    def start_commit(conn):                                              # second effect: start executed, not committed
        gate.set()                                                       # let the scheduler try its read now
        time.sleep(0.5)
        observed["visible"] = sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (second,))[0][0]
        conn.commit()
    worker = threading.Thread(target=lambda: observed.update(first=owner.apply_with_retry(first)))
    worker.start()
    limit = time.monotonic() + 10
    while not sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s AND state = 'not_sent'",
                  (first,))[0][0] and time.monotonic() < limit:
        time.sleep(0.02)
    owner.hooks["commit:start"] = start_commit
    owner.hooks.pop("before_send")
    observed["second"] = owner.apply_once(second)
    owner.hooks.pop("commit:start")
    worker.join(30)
    hooks["restore"]()
    assert observed["visible"] == 0, observed                            # not committed early by the scheduler
    assert observed["second"]["outcome"] == "confirmed" and observed["first"]["outcome"] == "confirmed", observed


# --- follow-up: automated-review findings on PR #17 -------------------------------------------

def test_budget_used_by_aborted_attempts_blocks_the_effect(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    fake.script["read"] = "error"                                         # every preflight is unavailable
    owner = _owner(instance, fake)
    reasons = [owner.apply_once(effect_id)["reason"] for _ in range(3)]
    assert reasons == ["preflight_unavailable"] * 3
    assert _effect_budget(effect_id)[:2] == ("BLOCKED", 3)               # not QUEUED forever
    assert owner.apply_once(effect_id)["reason"] == "effect_not_queued"
    assert _phase(owner, fake)["connects"] == 0 and fake.counts["receipts"] == 0


def test_upgrade_counts_existing_attempts_into_the_budget(client, app, instance, fake):
    from voalack.schema import schema_sql
    effect_id = _effect(client, app, instance)
    fake.script["read"] = "error"
    owner = _owner(instance, fake)
    for _ in range(2):
        assert owner.apply_once(effect_id)["reason"] == "preflight_unavailable"
    sql("UPDATE voalack.effects SET attempt_count = 0 WHERE effect_id = %s", (effect_id,), fetch=False)  # as before S3a
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute(schema_sql())                                         # the upgrade path
    assert _effect_budget(effect_id)[:2] == ("QUEUED", 2)
    assert owner.apply_once(effect_id)["reason"] == "preflight_unavailable"
    assert _effect_budget(effect_id)[:2] == ("BLOCKED", 3)


@pytest.mark.parametrize("path", ["login_failed", "preflight_unavailable"])
def test_aborts_through_the_third_attempt_block_and_fewer_keep_the_budget(client, app, instance, fake, path):
    effect_id = _effect(client, app, instance)
    if path == "login_failed":
        fake.script["login"] = "fail"
    else:
        fake.script["read"] = "error"
    owner = _owner(instance, fake)
    for expected_count in (1, 2):                                        # lower counts: still retryable
        assert owner.apply_once(effect_id)["reason"] == path
        assert _effect_budget(effect_id)[:2] == ("QUEUED", expected_count)
    assert owner.apply_once(effect_id)["reason"] == path
    assert _effect_budget(effect_id)[:2] == ("BLOCKED", 3)
    assert _phase(owner, fake)["connects"] == 0 and fake.counts["receipts"] == 0


def test_release_keeps_already_acked_and_blocked_dispositions(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    sql("UPDATE voalack.effects SET attempt_count = 2 WHERE effect_id = %s", (effect_id,), fetch=False)  # lab
    fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True,
                           "acked_by_operation": "someone-else", "comment": "x"}
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["reason"] == "already_acked"        # third attempt, ALREADY_ACKED kept
    assert _effect_budget(effect_id)[:2] == ("ALREADY_ACKED", 3)


def test_schema_migration_excludes_concurrent_attempt_creation(client, app, instance, fake):
    import threading
    from voalack.schema import schema_sql
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    admin = psycopg2.connect(DSN)
    admin.cursor().execute("SET lock_timeout = '30s'")                  # fail loudly rather than hang
    admin.cursor().execute(schema_sql())                                 # migration transaction, not committed
    box = {}

    def start():
        box["row"] = _call("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                           (str(uuid.uuid4()), effect_id, instance, owner.generation, owner.incarnation))
    conn_probe = threading.Thread(target=start)
    conn_probe.start()
    try:
        limit = time.monotonic() + 5
        blocked = 0
        while time.monotonic() < limit and not blocked:
            blocked = sql("SELECT count(*) FROM pg_stat_activity WHERE %s = ANY(pg_blocking_pids(pid))",
                          (admin.get_backend_pid(),))[0][0]
            time.sleep(0.02)
        assert blocked, "attempt creation was not excluded by the migration transaction"
        assert "row" not in box
        admin.commit()
        conn_probe.join(15)
    finally:
        admin.close()
    assert box["row"]["outcome"] == "started"
    assert _effect_budget(effect_id)[:2] == ("QUEUED", 1)
