"""Audit 2026-11-08 finding 5: a lock timeout in the first step of a send no longer stops the owner.

Any database error during apply_once stopped the owner for good, including a row-lock wait in
start_attempt that ran past the sender's lock_timeout, before anything was stored; the verifier
treats the same error as "try again later". One busy moment then halted all sending for that ONE
instance until an administrator contained the owner. Now only that case is deferred: the
statement's transaction is rolled back, the effect stays QUEUED and untouched, the owner keeps
running and a later pass sends the effect once. The same error once the attempt is stored, and
every other database error in the first step, still stop the owner; a fence or configuration
change that was waiting behind the lock stops it at the next fence.

[native] PostgreSQL row locks, held from a second connection for the whole call (no sleeps racing
the timeout); [fake] loopback provider.
"""
import sys
import threading
import time

import psycopg2
import pytest

from conftest import DSN, sql
from test_t04_s2_sender import (_attempt, _counts, _effect, _effect_state, _guards, _owner,  # noqa: F401
                                fake, instance)
from voalack import sender
from voalack.sender import OwnerStopped

WAITED = 0.9 * sender.LOCK_TIMEOUT_MS / 1000          # lower bound only: a native wait really happened


def _row(effect_id):
    """The whole effect row: state, in-flight marker, attempt budget, backoff and retry lineage."""
    return sql("SELECT to_jsonb(e) FROM voalack.effects e WHERE e.effect_id = %s", (effect_id,))[0][0]


def _attempts(effect_id):
    return sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]


def _owner_state(owner):
    """The owner's state as the database fence reads it (active, suspended, contained, ...)."""
    return sql("SELECT voalack.check_owner(%s, %s, %s)",
               (owner.instance_id, owner.generation, owner.incarnation))[0][0]


def _hold(statement, args):
    """A second connection holding a row lock (or an uncommitted change) until it is released."""
    conn = psycopg2.connect(DSN)
    conn.cursor().execute(statement, args)
    return conn


def _record_stops(owner):
    """Each stop with the database error being handled when it was called (None outside a handler)."""
    stops, original = [], owner.stop

    def stop(reason):
        stops.append((reason, sys.exc_info()[0]))
        original(reason)
    owner.stop = stop
    return stops


LOCK_EFFECT = "SELECT 1 FROM voalack.effects WHERE effect_id = %s FOR UPDATE"


def test_lock_timeout_at_start_defers_the_effect_and_a_later_pass_sends_it_once(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    other = _effect(client, app, instance, target_id="4712", occurrence_ref="lab-audit5-other")
    owner = _owner(instance, fake)
    before = _row(effect_id)
    holder = _hold(LOCK_EFFECT, (effect_id,))
    try:
        started = time.monotonic()
        result = owner.apply_once(effect_id)                  # [native] start_attempt waits past lock_timeout
        waited = time.monotonic() - started
        assert (result["outcome"], result["reason"]) == ("deferred", "lock_timeout"), result
        assert waited >= WAITED, waited
        assert owner.stopped is None and _owner_state(owner) == "active"
        assert _row(effect_id) == before and _row(effect_id)["attempt_count"] == 0     # QUEUED, budget unspent
        assert _attempts(effect_id) == 0 and _guards(instance) == []
        assert owner.journal == {}
        assert (fake.counts["logins"], fake.counts["reads"]) == (0, 0)               # no credential or network
        sent = owner.apply_once(other)                        # the owner keeps sending while the row is busy
        assert sent["outcome"] == "confirmed", sent
    finally:
        holder.rollback()
        holder.close()
    later = owner.apply_once(effect_id)                       # a later pass, lock released, same owner
    assert later["outcome"] == "confirmed", later
    assert _effect_state(effect_id) == ("REMOTE_CONFIRMED", False) and _guards(instance) == []
    assert _attempts(effect_id) == 1 and _attempt(later["attempt_id"]) == ("confirmed", "consumed")
    again = owner.apply_once(effect_id)
    assert (again["outcome"], again["reason"]) == ("refused", "effect_not_queued")
    assert _counts(owner, fake) == (2, 2, 2, 2)               # one ACK per effect, never a second


def test_lock_timeout_after_the_attempt_is_stored_still_stops_the_owner(client, app, instance, fake):
    effect_id = _effect(client, app, instance)
    holder = {}

    def lock_effect_row(_):                                   # after start_attempt's COMMIT
        holder["conn"] = _hold(LOCK_EFFECT, (effect_id,))
    owner = _owner(instance, fake, hooks={"after_preflight": lock_effect_row})
    stops = _record_stops(owner)
    try:
        started = time.monotonic()
        result = owner.apply_once(effect_id)                  # [native] consume_dispatch waits past lock_timeout
        waited = time.monotonic() - started
    finally:
        if "conn" in holder:
            holder["conn"].rollback()
            holder["conn"].close()
    assert (result["outcome"], result["reason"]) == ("held", "database_lost"), result
    assert stops[:1] == [("database_lost", psycopg2.errors.LockNotAvailable)] and waited >= WAITED, (stops, waited)
    assert owner.stopped == "database_lost" and _owner_state(owner) == "suspended"
    assert _attempt(result["attempt_id"]) == ("started", "unconsumed")              # as the database has it
    assert _effect_state(effect_id) == ("QUEUED", True) and _guards(instance) == [("4711", "in_flight")]
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)
    assert _counts(owner, fake) == (0, 0, 0, 0)


@pytest.mark.parametrize("change,reason", [
    ("UPDATE voalack.instance_config SET config_revision = config_revision + 1 WHERE instance_id = %(instance)s",
     "config_changed"),
    ("SELECT voalack.record_containment(%(instance)s, %(generation)s, "
     "'{\"process_stopped\": true, \"no_requests_executing\": true, \"basis\": \"lab: audit 5\"}'::jsonb)",
     "fenced"),
], ids=["config_change", "containment"])
def test_a_change_waiting_behind_the_lock_stops_the_owner_at_the_next_fence(client, app, instance, fake,
                                                                           change, reason):
    """start_attempt waits on the instance_config (FOR SHARE) or owner row (FOR SHARE) that the
    uncommitted change holds; nothing is stored, and once the change commits the fence stops."""
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    before = _row(effect_id)
    holder = _hold(change, {"instance": instance, "generation": owner.generation})
    try:
        result = owner.apply_once(effect_id)                  # [native]
        assert (result["outcome"], result["reason"]) == ("deferred", "lock_timeout"), result
        assert owner.stopped is None
        holder.commit()
    finally:
        holder.close()
    with pytest.raises(OwnerStopped, match=reason):
        owner.apply_once(effect_id)
    assert owner.stopped == reason
    assert _row(effect_id) == before and _attempts(effect_id) == 0 and _guards(instance) == []
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["logins"] == 0


@pytest.mark.parametrize("ending", ["statement_timeout", "connection_lost"])
def test_other_errors_in_the_same_wait_still_stop_the_owner(client, app, instance, fake, ending):
    """Only the lock timeout is deferred. In this owner's session the lock wait has no bound of its
    own (lock_timeout 0); it ends by statement_timeout (QueryCanceled) or by losing the backend."""
    effect_id = _effect(client, app, instance)
    owner = _owner(instance, fake)
    conn = owner._db()
    with conn.cursor() as cur:
        cur.execute("SET lock_timeout = 0")
        if ending == "statement_timeout":
            cur.execute("SET statement_timeout = 1000")
    conn.commit()
    pid = conn.get_backend_pid()
    before = _row(effect_id)
    stops = _record_stops(owner)
    holder, worker = _hold(LOCK_EFFECT, (effect_id,)), None
    try:
        if ending == "statement_timeout":
            result = owner.apply_once(effect_id)              # [native]
        else:
            box = {}

            def run():
                try:
                    box["result"] = owner.apply_once(effect_id)
                except BaseException as exc:                  # recorded, so the assertion shows it
                    box["error"] = repr(exc)
            worker = threading.Thread(target=run)
            worker.start()
            limit, waiting = time.monotonic() + 8, []         # the session's statement_timeout is 10 s
            while not waiting and time.monotonic() < limit:
                waiting = sql("SELECT 1 FROM pg_stat_activity WHERE pid = %s AND wait_event_type = 'Lock' "
                              "AND %s = ANY(pg_blocking_pids(pid))", (pid, holder.get_backend_pid()))
                if not waiting:
                    time.sleep(0.02)
            assert waiting, "the owner's start_attempt was not seen waiting on the row lock"
            sql("SELECT pg_terminate_backend(%s)", (pid,))   # [native] connection lost mid-statement
            worker.join(10)
            assert not worker.is_alive() and "error" not in box, box
            result = box["result"]
    finally:
        holder.rollback()
        holder.close()
        if worker is not None:
            worker.join(15)
    assert stops and stops[0][0] == "database_lost", stops
    if ending == "statement_timeout":
        assert stops[0][1] is psycopg2.errors.QueryCanceled, stops
    else:
        assert issubclass(stops[0][1], psycopg2.Error) and not issubclass(
            stops[0][1], psycopg2.errors.LockNotAvailable), stops
    assert (result["outcome"], result["reason"]) == ("held", "database_lost"), result
    assert owner.stopped == "database_lost"
    assert _row(effect_id) == before and _attempts(effect_id) == 0 and _guards(instance) == []
    with pytest.raises(OwnerStopped):
        owner.apply_once(effect_id)
    assert _counts(owner, fake) == (0, 0, 0, 0) and fake.counts["logins"] == 0
