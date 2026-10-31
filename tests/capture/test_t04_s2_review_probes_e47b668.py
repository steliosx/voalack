"""Independent candidate probes. Native database transitions; synthetic loopback provider.

Expected assertions express approved S2 safeguards, not the candidate's implementation.
Named before_send hooks schedule native changes, rather than replace product decisions.
"""
import dataclasses
import hashlib
from pathlib import Path
import json
import os
import threading
import time
from datetime import timedelta

import psycopg2
import pytest

from conftest import DSN, sql
from test_t04_s2_sender import instance, fake, _effect, _owner

Path("/out/probe-source-sha256.txt").write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() + "\n")


def witness(name, owner, provider, result, **extra):
    data = dict(name=name, result=result, dispatch=owner.counts,
                transport=owner.transport.counts, provider=provider.counts, **extra)
    with open(os.environ.get('PROBE_WITNESS', '/out/probe-witness.jsonl'), 'a') as f:
        f.write(json.dumps(data, default=str) + '\n')


@pytest.mark.parametrize('change', ['key', 'config', 'owner'])
def test_no_ack_after_final_boundary_invalidation(client, app, instance, fake, change):
    effect = _effect(client, app, instance)
    holder = {}
    def invalidate(_):
        if change == 'key':
            sql("DELETE FROM voalack.accepted_kids WHERE kid = 'lab-k1'", fetch=False)
        elif change == 'config':
            sql('UPDATE voalack.instance_config SET config_revision = 2 WHERE instance_id = %s',
                (instance,), fetch=False)
        else:
            o = holder['owner']
            sql('SELECT voalack.suspend_owner(%s, %s, %s)',
                (instance, o.generation, o.incarnation), fetch=False)
    owner = holder['owner'] = _owner(instance, fake, hooks={'before_send': invalidate})
    try:
        result = owner.apply_once(effect)
    finally:
        sql("INSERT INTO voalack.accepted_kids VALUES ('lab-k1') ON CONFLICT DO NOTHING", fetch=False)
    witness('final_boundary_' + change, owner, fake, result)
    assert owner.transport.counts['ack_writes'] == fake.counts['receipts'] == 0, result


def test_refused_candidate_does_not_login(app, instance, fake):
    owner = _owner(instance, fake)
    result = owner.apply_once(-1)
    witness('refused_candidate_login', owner, fake, result)
    assert result['outcome'] == 'refused'
    assert owner.transport.counts == {'logins': 0, 'ack_writes': 0, 'reads': 0, 'revokes': 0}


def test_suspended_owner_does_not_read_back_after_ack(client, app, instance, fake):
    effect = _effect(client, app, instance)
    fake.script['delay'] = 0.5
    owner = _owner(instance, fake)
    result, errors = {}, []
    def apply():
        try:
            result.update(owner.apply_once(effect))
        except BaseException as exc:
            errors.append(repr(exc))
    thread = threading.Thread(target=apply)
    thread.start()
    limit = time.monotonic() + 15
    while fake.executing == 0 and time.monotonic() < limit:
        time.sleep(0.01)
    assert fake.executing == 1
    # Real database suspension while the already-authorized ACK is on the wire.
    sql('SELECT voalack.suspend_owner(%s, %s, %s)',
        (instance, owner.generation, owner.incarnation), fetch=False)
    thread.join(15)
    assert not thread.is_alive() and not errors, errors
    witness('suspended_during_ack_no_readback', owner, fake, result)
    # Amended for the S2 follow-up preflight (disclosed; original bytes 618d755d... in the signed record):
    # exactly the one preflight read before the ACK, and no read-back after the suspension.
    assert owner.transport.counts['reads'] == fake.counts['reads'] == 1, result


@pytest.mark.parametrize('operation', ['ack', 'read_alarm'])
def test_non_success_http_evidence_is_not_confirmed(client, app, instance, fake, operation):
    effect = _effect(client, app, instance)
    owner = _owner(instance, fake)
    original = getattr(owner.transport, operation)
    calls = []
    def failing_status(*args):
        _, payload = original(*args)
        calls.append(1)
        # Amended for the S2 follow-up preflight (disclosed): the first read is the preflight and passes
        # through unchanged, so the scripted 500 still applies to the read-back it was written for.
        if operation == 'read_alarm' and len(calls) == 1:
            return _, payload
        return 500, payload       # scripted fake HTTP status; keep exact attributable payload
    setattr(owner.transport, operation, failing_status)
    result = owner.apply_once(effect)
    witness('http_500_' + operation, owner, fake, result)
    assert result['outcome'] == 'uncertain', result


def test_native_delayed_consume_commit_does_not_send_after_deadline(client, app, instance, fake):
    signing = app.extensions['voalack_signing']
    app.extensions['voalack_signing'] = dataclasses.replace(
        signing, capture_window=timedelta(seconds=1), execution_window=timedelta(milliseconds=1500))
    try:
        effect = _effect(client, app, instance)
    finally:
        app.extensions['voalack_signing'] = signing
    deadline = sql('SELECT p.execution_expires_at FROM voalack.effects e JOIN voalack.prepared_intents p '
                   'ON p.action_id = e.action_id WHERE e.effect_id = %s', (effect,))[0][0]
    owner = _owner(instance, fake)
    blocker = psycopg2.connect(DSN)
    blocker.autocommit = True
    lock_id = 982381
    with blocker.cursor() as cur:
        cur.execute('SELECT pg_advisory_lock(%s)', (lock_id,))
    sql('''CREATE FUNCTION public.lab_s2_commit_wait() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.state = 'dispatched' AND OLD.state = 'started' THEN
            PERFORM pg_advisory_lock(982381);
            PERFORM pg_advisory_unlock(982381);
          END IF;
          RETURN NEW;
        END; $$''', fetch=False)
    sql('''CREATE CONSTRAINT TRIGGER lab_s2_commit_wait AFTER UPDATE ON voalack.attempts
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lab_s2_commit_wait()''',
        fetch=False)
    result, errors = {}, []
    def apply():
        try:
            result.update(owner.apply_once(effect))
        except BaseException as exc:
            errors.append(repr(exc))
    pid = owner._db().get_backend_pid()
    thread = threading.Thread(target=apply)
    thread.start()
    blocked = []
    try:
        limit = time.monotonic() + 10
        while time.monotonic() < limit:
            blocked = sql('SELECT query, wait_event_type, wait_event FROM pg_stat_activity '
                          'WHERE pid = %s AND %s = ANY(pg_blocking_pids(pid))',
                          (pid, blocker.get_backend_pid()))
            if blocked:
                break
            time.sleep(0.02)
        assert blocked and blocked[0][0] == 'COMMIT', (blocked, errors)
        while not sql('SELECT clock_timestamp() > %s', (deadline,))[0][0]:
            time.sleep(0.02)
        with blocker.cursor() as cur:
            cur.execute('SELECT pg_advisory_unlock(%s)', (lock_id,))
        thread.join(15)
        assert not thread.is_alive() and not errors, errors
        witness('native_consume_commit_delayed_past_deadline', owner, fake, result,
                deadline=deadline, pg_commit_wait=blocked,
                provider_time=sql('SELECT clock_timestamp()')[0][0])
        assert owner.transport.counts['ack_writes'] == fake.counts['receipts'] == 0, result
    finally:
        blocker.close()
        thread.join(15)
        sql('DROP TRIGGER IF EXISTS lab_s2_commit_wait ON voalack.attempts', fetch=False)
        sql('DROP FUNCTION IF EXISTS public.lab_s2_commit_wait()', fetch=False)


def test_native_database_loss_inside_attempt_stops_owner(client, app, instance, fake):
    effect = _effect(client, app, instance)
    holder = {}
    def lose_database(_):
        sql('SELECT pg_terminate_backend(%s)', (holder['owner']._db().get_backend_pid(),))
    owner = holder['owner'] = _owner(instance, fake, hooks={'after_start': lose_database})
    result = {}
    try:
        result = owner.apply_once(effect)
    except psycopg2.OperationalError as exc:
        result = {'exception': type(exc).__name__}
    witness('native_db_loss_inside_attempt', owner, fake, result, local_stop=owner.stopped)
    assert owner.stopped is not None, result
    assert owner.transport.counts['ack_writes'] == fake.counts['receipts'] == 0


@pytest.mark.parametrize('constraint,relation,restore', [
    ('target_guards_pkey', 'target_guards', 'PRIMARY KEY (instance_id, target_kind, target_id)'),
    ('effects_in_flight_attempt_key', 'effects', 'UNIQUE (in_flight_attempt)'),
])
def test_sender_readiness_checks_dispatch_exclusion_constraints(app, constraint, relation, restore):
    from conftest import SENDER_DSN
    from voalack import verifier, sender
    with psycopg2.connect(SENDER_DSN) as conn:
        verifier.check_ready(conn, sender.SENDER)
    sql(f'ALTER TABLE voalack.{relation} DROP CONSTRAINT {constraint}', fetch=False)
    refused = False
    try:
        with psycopg2.connect(SENDER_DSN) as conn:
            try:
                verifier.check_ready(conn, sender.SENDER)
            except verifier.NotReady:
                refused = True
    finally:
        sql(f'ALTER TABLE voalack.{relation} ADD CONSTRAINT {constraint} {restore}', fetch=False)
    assert refused, f'readiness accepted missing {constraint}'
