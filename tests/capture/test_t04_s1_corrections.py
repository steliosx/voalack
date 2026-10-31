"""T04 S1 review corrections (S1-R1..R5 on d195c1a): current ACK generation, the complete original
history, protected promotion, unknown keys past the deadline, and verifier readiness.

Pauses use lab-only trigger functions in schema `lab` (outside `voalack`, so the verifier's
readiness check does not see them as drift) that wait on an advisory lock held by the test.
"""
import contextlib
import dataclasses
import threading
import time
from datetime import timedelta

import psycopg2
import pytest

from conftest import DSN, OPERATOR, VERIFIER_DSN, ack, basic, new_alert, sql
from voalack import envelope as v2
from voalack import verifier


def _captured(client, **kwargs):
    alert_id = new_alert(client, **kwargs)
    assert ack(client, alert_id).status_code == 200
    action_id = sql("SELECT action_id::text FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))[0][0]
    return alert_id, action_id


def _verify(app, action_id, keys=None, **kwargs):
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as conn:
        return verifier.run_once(conn, kwargs.pop("claimant", "lab-verifier-r"), signing.ctx, keys or signing.keys,
                                 action_id=action_id, **kwargs)


def _effects(action_id):
    return sql("SELECT state FROM voalack.effects WHERE action_id = %s", (action_id,))


def _records(action_id):
    return sql("SELECT outcome, reason FROM voalack.verifications WHERE action_id = %s ORDER BY verification_id",
               (action_id,))


def _unack(client, alert_id):
    assert client.put(f"/alert/{alert_id}/action", json={"action": "unack", "text": "lab reopen"},
                      headers=basic(OPERATOR)).status_code == 200


@contextlib.contextmanager
def _paused(table, gate):
    """Every INSERT into voalack.<table> waits until the test releases ``gate``."""
    sql("CREATE SCHEMA IF NOT EXISTS lab; GRANT USAGE ON SCHEMA lab TO PUBLIC", fetch=False)
    sql(f"CREATE FUNCTION lab.pause_{gate}() RETURNS trigger LANGUAGE plpgsql AS "
        f"$$ BEGIN PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END $$", fetch=False)
    sql(f"CREATE TRIGGER lab_pause_{gate} BEFORE INSERT ON voalack.{table} "
        f"FOR EACH ROW EXECUTE FUNCTION lab.pause_{gate}()", fetch=False)
    holder = psycopg2.connect(DSN)
    holder.autocommit = True
    holder.cursor().execute("SELECT pg_advisory_lock(%s)", (gate,))
    try:
        yield holder
    finally:
        holder.cursor().execute("SELECT pg_advisory_unlock_all()")
        holder.close()
        sql(f"DROP TRIGGER lab_pause_{gate} ON voalack.{table}", fetch=False)
        sql(f"DROP FUNCTION lab.pause_{gate}()", fetch=False)


def _release(holder, gate):
    holder.cursor().execute("SELECT pg_advisory_unlock(%s)", (gate,))


def _wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _blocked_by(pid):
    return sql("SELECT count(*) FROM pg_stat_activity WHERE %s = ANY(pg_blocking_pids(pid))", (pid,))[0][0] > 0


def _is_blocked(pid):
    return sql("SELECT cardinality(pg_blocking_pids(%s)) > 0", (pid,))[0][0]


def _in_thread(target):
    box = {}

    def run():
        try:
            box["result"] = target(box)
        except Exception as exc:                      # surfaced by the caller's assertions
            box["error"] = exc
    thread = threading.Thread(target=run)
    thread.start()
    return thread, box


def _verify_in_thread(app, action_id, **kwargs):
    # The lab pause is itself a lock wait (advisory lock), bounded by the verifier's lock_timeout.
    kwargs.setdefault("lock_timeout_ms", 10000)

    def target(box):
        signing = app.extensions["voalack_signing"]
        with psycopg2.connect(VERIFIER_DSN) as conn:
            box["pid"] = conn.get_backend_pid()
            return verifier.run_once(conn, "lab-verifier-t", signing.ctx, signing.keys, action_id=action_id,
                                     **kwargs)
    return _in_thread(target)


# --- S1-R1: the current ACK generation --------------------------------------------------------

def test_older_generation_is_refused_after_a_newer_committed_ack(client, app):
    alert_id, old = _captured(client)
    _unack(client, alert_id)
    assert ack(client, alert_id, text="lab newer ack").status_code == 200
    assert sql("SELECT generation FROM voalack.prepared_intents WHERE alert_id = %s ORDER BY generation",
               (alert_id,)) == [(1,), (2,)]
    calls = []
    result = _verify(app, old, on_promoted=calls.append)
    assert (result["outcome"], result["reason"]) == ("refused", "generation_superseded"), result
    assert _effects(old) == [] and calls == []
    assert _records(old) == [("verified", "ok"), ("refused", "generation_superseded")]


def test_promotion_waiting_behind_an_in_flight_newer_ack_is_refused(client, app):
    alert_id, old = _captured(client)
    _unack(client, alert_id)
    gate = 73600101
    with _paused("prepared_intents", gate) as holder:
        newer, newer_box = _in_thread(lambda box: ack(app.test_client(), alert_id, text="lab newer ack").status_code)
        assert _wait_until(lambda: _blocked_by(holder.get_backend_pid()))      # holds the generation row
        worker, box = _verify_in_thread(app, old)
        assert _wait_until(lambda: "pid" in box and _is_blocked(box["pid"])), box
        _release(holder, gate)
        newer.join(20)
        worker.join(20)
    assert newer_box.get("result") == 200, newer_box
    assert "error" not in box, box
    assert (box["result"]["outcome"], box["result"]["reason"]) == ("refused", "generation_superseded"), box
    assert _effects(old) == []


def test_newer_ack_waits_for_a_promotion_in_progress(client, app):
    alert_id, old = _captured(client)
    _unack(client, alert_id)
    gate = 73600102
    with _paused("effects", gate) as holder:
        worker, box = _verify_in_thread(app, old)
        assert _wait_until(lambda: _blocked_by(holder.get_backend_pid()))      # promotion holds the generation
        newer, newer_box = _in_thread(lambda box: ack(app.test_client(), alert_id, text="lab newer ack").status_code)
        assert _wait_until(lambda: sql("SELECT count(*) FROM pg_stat_activity WHERE %s = ANY(pg_blocking_pids(pid))",
                                       (box["pid"],))[0][0] > 0), "the newer ACK did not wait for the promotion"
        _release(holder, gate)
        worker.join(20)
        newer.join(20)
    assert "error" not in box and box["result"]["outcome"] == "verified", box
    assert newer_box.get("result") == 200, newer_box
    created, newer_at = sql("SELECT e.created_at, (SELECT created_at FROM voalack.prepared_intents "
                            "WHERE alert_id = %s AND generation = 2) FROM voalack.effects e WHERE e.action_id = %s",
                            (alert_id, old))[0]
    assert created < newer_at                       # the promotion linearizes before the newer ACK


# --- S1-R2: the complete original capture ---------------------------------------------------

@pytest.mark.parametrize("statement,reason", [
    ("UPDATE voalack.captures SET history_text = 'lab changed note' WHERE action_id = %s", "history_mismatch"),
    ("UPDATE voalack.captures SET history_type = 'unack' WHERE action_id = %s", "history_not_ack"),
    ("UPDATE voalack.captures SET history_status = 'open' WHERE action_id = %s", "history_not_ack"),
    ("UPDATE voalack.captures SET history_time = history_time + interval '1 second' WHERE action_id = %s",
     "history_mismatch"),
    ("UPDATE voalack.prepared_intents SET payload = payload || '{\"note\": \"lab changed\"}' WHERE action_id = %s",
     "history_mismatch"),
])
def test_original_history_mismatch_is_refused(client, app, statement, reason):
    _, action_id = _captured(client)
    sql(statement, (action_id,), fetch=False)                 # lab-admin metadata corruption
    calls = []
    result = _verify(app, action_id, on_promoted=calls.append)
    assert (result["outcome"], result["reason"]) == ("refused", reason), result
    assert _effects(action_id) == [] and calls == []


def test_consistently_changed_note_does_not_reproduce_the_signed_message(client, app):
    _, action_id = _captured(client)
    sql("UPDATE voalack.captures SET history_text = 'lab rewritten note' WHERE action_id = %s", (action_id,),
        fetch=False)
    sql("UPDATE voalack.prepared_intents SET payload = payload || '{\"note\": \"lab rewritten note\"}' "
        "WHERE action_id = %s", (action_id,), fetch=False)
    result = _verify(app, action_id)
    assert (result["outcome"], result["reason"]) == ("refused", "message_mismatch"), result
    assert _effects(action_id) == []


def test_capture_changed_before_protection_is_not_promoted(client, app):
    # Amended (034ba00 review): the original rows are locked from record_verification on, so a
    # change can only commit before that. After the claim (which skips rows being changed), the
    # administrator's uncommitted change is in place when the verifier reads the committed rows;
    # the verifier's protection waits for it to commit.
    _, action_id = _captured(client)
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT claim_epoch FROM voalack.claim_verification('lab-before', 60, %s)", (action_id,))
        epoch = cur.fetchone()[0]
    admin = psycopg2.connect(DSN)
    try:
        admin.cursor().execute("UPDATE voalack.captures SET history_text = 'lab changed later' WHERE action_id = %s",
                               (action_id,))

        def target(box):
            with psycopg2.connect(VERIFIER_DSN) as conn:
                box["pid"] = conn.get_backend_pid()
                return verifier.process(conn, action_id, epoch, signing.ctx, signing.keys)
        worker, box = _in_thread(target)
        assert _wait_until(lambda: _blocked_by(admin.get_backend_pid())), box
        admin.commit()
        worker.join(20)
    finally:
        admin.close()
    assert "error" not in box, box
    assert (box["result"]["outcome"], box["result"]["reason"]) == ("refused", "capture_changed"), box
    assert _effects(action_id) == [] and _records(action_id) == [("verified", "ok"), ("refused", "capture_changed")]


@pytest.mark.parametrize("statement", [
    "UPDATE voalack.captures SET history_text = 'lab changed during promotion' WHERE action_id = %s",
    "UPDATE voalack.prepared_intents SET execution_expires_at = execution_expires_at + interval '1 hour' "
    "WHERE action_id = %s",
    "UPDATE voalack.prepared_intents SET mac = repeat('0', 64) WHERE action_id = %s",
])
def test_original_rows_cannot_change_during_promotion(client, app, statement):
    _, action_id = _captured(client)
    original = sql("SELECT voalack.capture_fingerprint(%s)", (action_id,))[0][0]
    gate = 73600202
    with _paused("effects", gate) as holder:
        worker, box = _verify_in_thread(app, action_id)
        assert _wait_until(lambda: _blocked_by(holder.get_backend_pid())), box
        with pytest.raises(psycopg2.errors.QueryCanceled):        # protected: the change waits
            with psycopg2.connect(DSN) as admin, admin.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = '2s'")
                cur.execute(statement, (action_id,))
        _release(holder, gate)
        worker.join(20)
    assert "error" not in box and box["result"]["outcome"] == "verified", box
    assert _effects(action_id) == [("QUEUED",)]
    assert sql("SELECT voalack.capture_fingerprint(%s)", (action_id,))[0][0] == original


def test_promotion_in_progress_is_skipped_by_other_claimants(client, app):
    _, action_id = _captured(client)
    gate = 73600203
    with _paused("effects", gate) as holder:
        worker, box = _verify_in_thread(app, action_id, lease_seconds=1)
        assert _wait_until(lambda: _blocked_by(holder.get_backend_pid())), box
        time.sleep(1.2)                                       # its lease lapses during the paused insert
        with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
            started = time.monotonic()
            cur.execute("SELECT * FROM voalack.claim_verification('lab-other', 60, %s)", (action_id,))
            assert cur.fetchone() is None and time.monotonic() - started < 1   # skipped, not waited on
        _release(holder, gate)
        worker.join(20)
    assert isinstance(box.get("error"), psycopg2.errors.RaiseException), box   # stale at the last check
    assert _effects(action_id) == []
    assert _verify(app, action_id)["outcome"] == "verified" and _effects(action_id) == [("QUEUED",)]


# --- S1-R3: protected promotion -------------------------------------------------------------

def test_policy_change_waits_for_a_promotion_in_progress(client, app):
    _, action_id = _captured(client)
    gate = 73600301
    try:
        with _paused("effects", gate) as holder:
            worker, box = _verify_in_thread(app, action_id)
            assert _wait_until(lambda: _blocked_by(holder.get_backend_pid()))
            with pytest.raises(psycopg2.errors.QueryCanceled):
                with psycopg2.connect(DSN) as admin, admin.cursor() as cur:
                    cur.execute("SET LOCAL statement_timeout = '2s'")
                    cur.execute("UPDATE voalack.authorization_policy_active SET policy_revision = 3")
            _release(holder, gate)
            worker.join(20)
    finally:
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
    assert "error" not in box and box["result"]["outcome"] == "verified", box
    assert _effects(action_id) == [("QUEUED",)]


@pytest.mark.parametrize("change,reason", [
    (["UPDATE voalack.authorization_policy_active SET policy_revision = 3"], "policy_revoked"),
    (["INSERT INTO voalack.binding_revisions SELECT binding_id, 2, customer, source_namespace, instance_id, resource,"
      " event, environment, origin, combination_id, capture_id, target_kind, target_id, alarm_template_id, object_id,"
      " repeat_count, triggered_time, occurrence_ref, occurrence_evidence_sha256, snapshot_sha256, clock_timestamp(),"
      " alert_lifetime_id FROM voalack.binding_revisions WHERE binding_id = %(binding)s AND binding_revision = 1",
      "UPDATE voalack.bindings SET binding_revision = 2 WHERE alert_id = %(alert)s"], "binding_changed"),
])
def test_promotion_waiting_behind_a_committed_change_is_refused(client, app, change, reason):
    alert_id, action_id = _captured(client)
    admin = psycopg2.connect(DSN)
    try:
        cur = admin.cursor()
        for statement in change:
            cur.execute(statement, {"binding": f"lab-{alert_id}", "alert": alert_id})
        worker, box = _verify_in_thread(app, action_id)
        assert _wait_until(lambda: _blocked_by(admin.get_backend_pid())), box
        admin.commit()
        worker.join(20)
    finally:
        admin.close()
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
    assert "error" not in box, box
    assert (box["result"]["outcome"], box["result"]["reason"]) == ("refused", reason), box
    assert _effects(action_id) == []


def test_lock_wait_is_bounded_and_records_nothing(client, app):
    _, action_id = _captured(client)
    admin = psycopg2.connect(DSN)
    try:
        admin.cursor().execute("UPDATE voalack.authorization_policy_active SET policy_revision = 1")
        result = _verify(app, action_id, lease_seconds=1, lock_timeout_ms=300)
    finally:
        admin.rollback()
        admin.close()
    assert (result["outcome"], result["reason"]) == ("deferred", "lock_timeout"), result
    assert _records(action_id) == [] and _effects(action_id) == []
    time.sleep(1.1)                                   # the lapsed claim is retried later
    assert _verify(app, action_id)["outcome"] == "verified" and _effects(action_id) == [("QUEUED",)]


def test_deadline_passing_during_promotion_is_refused(client, app):
    signing = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(signing, capture_window=timedelta(seconds=1),
                                                            execution_window=timedelta(seconds=2))
    try:
        _, action_id = _captured(client)
    finally:
        app.extensions["voalack_signing"] = signing
    deadline = sql("SELECT execution_expires_at FROM voalack.prepared_intents WHERE action_id = %s", (action_id,))[0][0]
    gate = 73600302
    with _paused("effects", gate) as holder:
        worker, box = _verify_in_thread(app, action_id)
        assert _wait_until(lambda: _blocked_by(holder.get_backend_pid())), box
        assert _wait_until(lambda: sql("SELECT clock_timestamp() > %s", (deadline,))[0][0])
        _release(holder, gate)
        worker.join(20)
    assert "error" not in box, box
    assert (box["result"]["outcome"], box["result"]["reason"]) == ("refused", "expired"), box
    assert _effects(action_id) == []


def test_claim_lapsing_during_promotion_is_refused(client, app):
    _, action_id = _captured(client)
    gate = 73600303
    with _paused("effects", gate) as holder:
        worker, box = _verify_in_thread(app, action_id, lease_seconds=1)
        assert _wait_until(lambda: _blocked_by(holder.get_backend_pid())), box
        time.sleep(1.2)
        _release(holder, gate)
        worker.join(20)
    assert isinstance(box.get("error"), psycopg2.errors.RaiseException), box
    assert "stale or expired" in str(box["error"])
    assert _effects(action_id) == []


# --- S1-R4: unknown keys and the original deadline -------------------------------------------

def _without_key(app):
    signing = app.extensions["voalack_signing"]
    scope = (signing.ctx.deployment_id, signing.ctx.provider, signing.ctx.purpose)
    return v2.KeyRing({scope + ("lab-k9",): b"k" * 32}, {scope: "lab-k9"})


def test_unknown_key_after_the_original_deadline_is_terminal(client, app):
    signing = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(signing, capture_window=timedelta(seconds=1),
                                                            execution_window=timedelta(seconds=1))
    try:
        _, action_id = _captured(client)
    finally:
        app.extensions["voalack_signing"] = signing
    time.sleep(1.2)
    calls = []
    result = _verify(app, action_id, keys=_without_key(app), on_promoted=calls.append)
    assert (result["outcome"], result["reason"]) == ("refused", "expired"), result
    assert _effects(action_id) == [] and calls == []
    assert _verify(app, action_id) is None                     # never reclaimed


def test_held_work_does_not_starve_new_captures(client, app):
    _, held = _captured(client)
    assert _verify(app, held, keys=_without_key(app), lease_seconds=1)["reason"] == "key_unavailable"
    time.sleep(1.1)
    _, fresh = _captured(client)                              # newer than the lapsed hold, never claimed
    never_claimed = {row[0] for row in sql(
        "SELECT c.action_id::text FROM voalack.captures c WHERE NOT EXISTS (SELECT 1 FROM voalack.verification_claims vc"
        " WHERE vc.action_id = c.action_id)")}
    assert fresh in never_claimed and held not in never_claimed
    order = []
    with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
        while True:                                          # drain every claimable capture, in claim order
            cur.execute("SELECT action_id::text FROM voalack.claim_verification('lab-fair', 300)")
            row = cur.fetchone()
            conn.commit()
            if row is None:
                break
            order.append(row[0])
    assert held in order and fresh in order
    assert never_claimed & set(order[order.index(held):]) == set()   # every never-claimed capture came first


# --- S1-R5: verifier readiness ----------------------------------------------------------------

def _ready_error(dsn=VERIFIER_DSN, setup=None):
    with psycopg2.connect(dsn) as conn:
        if setup:
            conn.cursor().execute(setup)
            conn.commit()
        try:
            verifier.check_ready(conn)
        except verifier.NotReady as exc:
            return str(exc)
    return None


def test_installed_verifier_login_is_ready(app):
    assert _ready_error() is None


def test_superuser_login_is_not_ready(app):
    assert "privileged_login" in _ready_error(DSN)


def test_changed_session_role_is_not_ready(app):
    assert "session_role_changed" in _ready_error(setup="SET ROLE voalack_verifier")


def test_replication_session_is_not_ready(app):
    # Ordinary ('origin') sessions fire the immutability trigger; a replica session would not.
    sql("GRANT SET ON PARAMETER session_replication_role TO lab_verifier", fetch=False)
    try:
        assert "replication_role" in _ready_error(setup="SET session_replication_role = replica")
    finally:
        sql("REVOKE SET ON PARAMETER session_replication_role FROM lab_verifier", fetch=False)


@pytest.mark.parametrize("drift,restore,failure", [
    ("GRANT voalack_admin TO lab_verifier", "REVOKE voalack_admin FROM lab_verifier", "admin_or_app_path"),
    ("GRANT voalack_app TO lab_verifier", "REVOKE voalack_app FROM lab_verifier", "admin_or_app_path"),
    ("CREATE ROLE lab_mid NOLOGIN; GRANT voalack_admin TO lab_mid; GRANT lab_mid TO lab_verifier",
     "DROP ROLE lab_mid", "admin_or_app_path"),
    ("CREATE ROLE lab_mid NOLOGIN; GRANT voalack_admin TO lab_mid WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; "
     "GRANT lab_mid TO lab_verifier", "DROP ROLE lab_mid", "admin_or_app_path"),
    ("CREATE ROLE lab_power NOLOGIN CREATEROLE; GRANT lab_power TO lab_verifier", "DROP ROLE lab_power",
     "privileged_membership"),
    ("GRANT EXECUTE ON FUNCTION voalack.capture_ack() TO PUBLIC",
     "REVOKE EXECUTE ON FUNCTION voalack.capture_ack() FROM PUBLIC", "public_execute"),
    ("ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin GRANT EXECUTE ON FUNCTIONS TO PUBLIC",
     "ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC", "default_execute"),
    ("ALTER FUNCTION voalack.promote_effect(uuid, bigint, bigint) SET search_path = public, voalack",
     "ALTER FUNCTION voalack.promote_effect(uuid, bigint, bigint) SET search_path = pg_catalog, voalack, pg_temp",
     "definer_config_drift"),
    ("GRANT INSERT ON voalack.effects TO voalack_verifier", "REVOKE INSERT ON voalack.effects FROM voalack_verifier",
     "table_power"),
    ("GRANT EXECUTE ON FUNCTION voalack.lock_grant(text, text) TO voalack_verifier",
     "REVOKE EXECUTE ON FUNCTION voalack.lock_grant(text, text) FROM voalack_verifier", "execute_drift"),
    ("REVOKE SELECT ON voalack.captures FROM voalack_verifier", "GRANT SELECT ON voalack.captures TO voalack_verifier",
     "read_missing"),
    ("ALTER TABLE voalack.verifications DISABLE TRIGGER verifications_immutable",
     "ALTER TABLE voalack.verifications ENABLE TRIGGER verifications_immutable", "immutability_drift"),
    ("ALTER TABLE voalack.effects OWNER TO lab_admin", "ALTER TABLE voalack.effects OWNER TO voalack_admin",
     "relation_owner_drift"),
    ("CREATE FUNCTION voalack.lab_extra() RETURNS int LANGUAGE sql AS 'SELECT 1'", "DROP FUNCTION voalack.lab_extra()",
     "function_owner_drift"),
    # Second 034ba00 review: an extra overload of an approved name, owned and configured like the
    # installed functions, is not an approved capability.
    ("CREATE FUNCTION voalack.claim_verification(text) RETURNS integer LANGUAGE sql SECURITY DEFINER "
     "SET search_path = pg_catalog, voalack, pg_temp AS 'SELECT 1'; "
     "ALTER FUNCTION voalack.claim_verification(text) OWNER TO voalack_admin; "
     "REVOKE ALL ON FUNCTION voalack.claim_verification(text) FROM PUBLIC; "
     "GRANT EXECUTE ON FUNCTION voalack.claim_verification(text) TO voalack_verifier",
     "DROP FUNCTION voalack.claim_verification(text)", "execute_drift"),
    # 034ba00 review (S1-R5): column grants, roles usable only through SET, trigger mode and form,
    # replication role, and full immediate uniqueness on both effect columns.
    ("GRANT UPDATE (state) ON voalack.effects TO voalack_verifier",
     "REVOKE UPDATE (state) ON voalack.effects FROM voalack_verifier", "table_power"),
    ("GRANT INSERT (reason) ON voalack.verifications TO lab_verifier",
     "REVOKE INSERT (reason) ON voalack.verifications FROM lab_verifier", "table_power"),
    ("GRANT REFERENCES (action_id) ON voalack.captures TO voalack_verifier",
     "REVOKE REFERENCES (action_id) ON voalack.captures FROM voalack_verifier", "table_power"),
    ("CREATE ROLE lab_writer NOLOGIN; GRANT UPDATE ON voalack.effects TO lab_writer; "
     "GRANT lab_writer TO lab_verifier WITH INHERIT FALSE, SET TRUE",
     "REVOKE UPDATE ON voalack.effects FROM lab_writer; DROP ROLE lab_writer", "table_power"),
    ("CREATE ROLE lab_runner NOLOGIN; GRANT EXECUTE ON FUNCTION voalack.capture_ack() TO lab_runner; "
     "GRANT lab_runner TO lab_verifier WITH INHERIT FALSE, SET TRUE",
     "REVOKE EXECUTE ON FUNCTION voalack.capture_ack() FROM lab_runner; DROP ROLE lab_runner", "execute_drift"),
    ("GRANT USAGE ON SEQUENCE voalack.effects_effect_id_seq TO voalack_verifier",
     "REVOKE USAGE ON SEQUENCE voalack.effects_effect_id_seq FROM voalack_verifier", "table_power"),
    ("ALTER TABLE voalack.verifications ENABLE REPLICA TRIGGER verifications_immutable",
     "ALTER TABLE voalack.verifications ENABLE TRIGGER verifications_immutable", "immutability_drift"),
    ("DROP TRIGGER verifications_immutable ON voalack.verifications; CREATE TRIGGER verifications_immutable "
     "BEFORE UPDATE OF reason ON voalack.verifications FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change()",
     "DROP TRIGGER verifications_immutable ON voalack.verifications; CREATE TRIGGER verifications_immutable "
     "BEFORE UPDATE OR DELETE ON voalack.verifications FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change()",
     "immutability_drift"),
    ("DROP TRIGGER verifications_immutable ON voalack.verifications; CREATE TRIGGER verifications_immutable "
     "BEFORE UPDATE OF reason OR DELETE ON voalack.verifications FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change()",
     "DROP TRIGGER verifications_immutable ON voalack.verifications; CREATE TRIGGER verifications_immutable "
     "BEFORE UPDATE OR DELETE ON voalack.verifications FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change()",
     "immutability_drift"),
    ("DROP TRIGGER verifications_immutable ON voalack.verifications; CREATE TRIGGER verifications_immutable "
     "BEFORE UPDATE OR DELETE ON voalack.verifications FOR EACH ROW WHEN (false) EXECUTE FUNCTION voalack.refuse_change()",
     "DROP TRIGGER verifications_immutable ON voalack.verifications; CREATE TRIGGER verifications_immutable "
     "BEFORE UPDATE OR DELETE ON voalack.verifications FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change()",
     "immutability_drift"),
    ("ALTER TABLE voalack.effects DROP CONSTRAINT effects_action_id_key; CREATE UNIQUE INDEX lab_partial_action "
     "ON voalack.effects (action_id) WHERE state = 'REMOTE_CONFIRMED'",
     "DROP INDEX voalack.lab_partial_action; ALTER TABLE voalack.effects ADD CONSTRAINT effects_action_id_key "
     "UNIQUE (action_id)", "uniqueness_drift"),
    ("ALTER TABLE voalack.effects DROP CONSTRAINT effects_effect_key_key; CREATE UNIQUE INDEX lab_expression_key "
     "ON voalack.effects (lower(effect_key))",
     "DROP INDEX voalack.lab_expression_key; ALTER TABLE voalack.effects ADD CONSTRAINT effects_effect_key_key "
     "UNIQUE (effect_key)", "uniqueness_drift"),
    ("ALTER TABLE voalack.effects DROP CONSTRAINT effects_effect_key_key; ALTER TABLE voalack.effects ADD CONSTRAINT "
     "effects_effect_key_key UNIQUE (effect_key) DEFERRABLE INITIALLY DEFERRED",
     "ALTER TABLE voalack.effects DROP CONSTRAINT effects_effect_key_key; ALTER TABLE voalack.effects ADD CONSTRAINT "
     "effects_effect_key_key UNIQUE (effect_key)", "uniqueness_drift"),
    ("ALTER TABLE voalack.effects DROP CONSTRAINT effects_action_id_key; ALTER TABLE voalack.effects ADD CONSTRAINT "
     "effects_action_id_key UNIQUE (action_id, effect_key)",
     "ALTER TABLE voalack.effects DROP CONSTRAINT effects_action_id_key; ALTER TABLE voalack.effects ADD CONSTRAINT "
     "effects_action_id_key UNIQUE (action_id)", "uniqueness_drift"),
])
def test_role_and_catalog_drift_is_not_ready(client, app, drift, restore, failure):
    import contextlib
    from conftest import guard_bypassed
    _, action_id = _captured(client)
    # Coexistence 3a S3a (amended openly): drift of a protected function's ACL is refused DDL under the enabled guard,
    # so those cases create it under the disclosed lab bypass; the readiness oracle is unchanged.
    protected = "voalack.capture_ack()" in drift
    with (guard_bypassed(f"legacy readiness drift witness: {failure}") if protected else contextlib.nullcontext()):
        sql(drift, fetch=False)
        try:
            error = _ready_error()
            with pytest.raises(verifier.NotReady):
                _verify(app, action_id)
        finally:
            sql(restore, fetch=False)
    assert error is not None and failure in error, error
    assert sql("SELECT count(*) FROM voalack.verification_claims WHERE action_id = %s", (action_id,))[0][0] == 0
    assert _ready_error() is None                               # restored
