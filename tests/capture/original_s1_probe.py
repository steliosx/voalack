import dataclasses
import threading
import time
from datetime import timedelta

import psycopg2
import pytest

from conftest import DSN, VERIFIER_DSN, OPERATOR, ack, basic, new_alert, sql
from voalack import envelope as v2, verifier


def captured(client):
    alert_id = new_alert(client)
    assert ack(client, alert_id).status_code == 200
    action_id = sql("SELECT action_id::text FROM voalack.prepared_intents WHERE alert_id=%s", (alert_id,))[0][0]
    return alert_id, action_id


def verify(app, action_id, keys=None):
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as conn:
        return verifier.run_once(conn, "independent-verifier", signing.ctx, keys or signing.keys, action_id=action_id)


def no_effect(action_id):
    assert sql("SELECT count(*) FROM voalack.effects WHERE action_id=%s", (action_id,))[0][0] == 0


def test_old_generation_cannot_promote_after_a_new_real_ack(client, app):
    alert_id, old_action = captured(client)
    assert client.put(f"/alert/{alert_id}/action", json={"action": "unack", "text": "independent reopen"},
                      headers=basic(OPERATOR)).status_code == 200
    assert ack(client, alert_id, text="independent newer ack").status_code == 200
    generations = sql("SELECT generation FROM voalack.prepared_intents WHERE alert_id=%s ORDER BY generation",
                      (alert_id,))
    assert generations == [(1,), (2,)]
    result = verify(app, old_action)
    print("OLD_GENERATION_RESULT", result["outcome"], result["reason"])
    assert result["outcome"] == "refused", result
    no_effect(old_action)


@pytest.mark.parametrize("field,statement", [
    ("text", "UPDATE voalack.captures SET history_text='independent changed note' WHERE action_id=%s"),
    ("type", "UPDATE voalack.captures SET history_type='unack' WHERE action_id=%s"),
    ("status", "UPDATE voalack.captures SET history_status='open' WHERE action_id=%s"),
    ("time", "UPDATE voalack.captures SET history_time=history_time+interval '1 second' WHERE action_id=%s"),
])
def test_original_capture_history_mismatch_cannot_promote(client, app, field, statement):
    _, action_id = captured(client)
    sql(statement, (action_id,), fetch=False)  # disclosed lab-admin metadata corruption
    result = verify(app, action_id)
    print("HISTORY_RESULT", field, result["outcome"], result["reason"])
    assert result["outcome"] == "refused", result
    no_effect(action_id)


def test_unknown_key_hold_stops_at_original_execution_deadline(client, app):
    original = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(original, capture_window=timedelta(seconds=1),
                                                           execution_window=timedelta(seconds=1))
    try:
        _, action_id = captured(client)
    finally:
        app.extensions["voalack_signing"] = original
    time.sleep(1.2)
    scope = (original.ctx.deployment_id, original.ctx.provider, original.ctx.purpose)
    unavailable = v2.KeyRing({scope+("lab-k9",): b"k"*32}, {scope: "lab-k9"})
    result = verify(app, action_id, keys=unavailable)
    print("EXPIRED_UNKNOWN_KEY_RESULT", result["outcome"], result["reason"])
    assert result["outcome"] == "refused", result
    no_effect(action_id)


def test_policy_revocation_during_promotion_prevents_effect(client, app):
    _, action_id = captured(client)
    gate = 73511821
    results = {}
    # Native PostgreSQL fault injection: pause INSERT after promote_effect's eligibility reads.
    sql("CREATE FUNCTION voalack.independent_pause_effect() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN PERFORM pg_advisory_xact_lock(73511821); RETURN NEW; END $$", fetch=False)
    sql("CREATE TRIGGER independent_pause_effect BEFORE INSERT ON voalack.effects "
        "FOR EACH ROW EXECUTE FUNCTION voalack.independent_pause_effect()", fetch=False)

    def worker():
        try:
            with psycopg2.connect(VERIFIER_DSN) as conn:
                results["pid"] = conn.get_backend_pid()
                results["result"] = verifier.run_once(conn, "independent-race", app.extensions["voalack_signing"].ctx,
                                                      app.extensions["voalack_signing"].keys, action_id=action_id)
        except Exception as exc:
            results["error"] = type(exc).__name__

    holder = psycopg2.connect(DSN)
    thread = None
    try:
        with holder.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (gate,))
        thread = threading.Thread(target=worker); thread.start()
        deadline = time.monotonic()+10
        reached = False
        while time.monotonic() < deadline:
            if "pid" in results:
                blockers = sql("SELECT pg_blocking_pids(%s)", (results["pid"],))[0][0]
                if holder.get_backend_pid() in blockers:
                    reached = True
                    break
            time.sleep(0.02)
        assert reached, results
        # Short timeout proves policy pointer is not protected until effect insertion commits.
        with psycopg2.connect(DSN) as admin, admin.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout='2s'")
            cur.execute("UPDATE voalack.authorization_policy_active SET policy_revision=3")
        with holder.cursor() as cur:
            cur.execute("SELECT pg_advisory_unlock(%s)", (gate,))
        thread.join(15); assert not thread.is_alive(), results
        assert "error" not in results, results
        result = results["result"]
        print("REVOKED_DURING_PROMOTION_RESULT", result["outcome"], result["reason"])
        assert result["outcome"] == "refused", result
        no_effect(action_id)
    finally:
        try:
            with holder.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock_all()")
        finally:
            holder.close()
        if thread is not None: thread.join(15)
        sql("UPDATE voalack.authorization_policy_active SET policy_revision=1", fetch=False)
        sql("DROP TRIGGER independent_pause_effect ON voalack.effects", fetch=False)
        sql("DROP FUNCTION voalack.independent_pause_effect()", fetch=False)
