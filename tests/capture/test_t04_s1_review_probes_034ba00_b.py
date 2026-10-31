"""Additional exact-head qualification; retains six original S1 refusal witnesses.

Three catalog mutations use disclosed lab-admin connections. No product source is changed.
"""
import psycopg2
import pytest
from conftest import DSN, VERIFIER_DSN, ack, new_alert, sql
from voalack import verifier
from original_s1_probe import (
    test_old_generation_cannot_promote_after_a_new_real_ack,
    test_original_capture_history_mismatch_cannot_promote,
    test_unknown_key_hold_stops_at_original_execution_deadline,
    verify,
)


def readiness():
    with psycopg2.connect(VERIFIER_DSN) as conn:
        try:
            verifier.check_ready(conn)
        except verifier.NotReady as exc:
            return str(exc)
    return None


def capture(client, occurrence):
    alert_id = new_alert(client, occurrence_ref=occurrence)
    assert ack(client, alert_id).status_code == 200
    return sql("SELECT action_id::text FROM voalack.prepared_intents WHERE alert_id=%s", (alert_id,))[0][0]


def test_replica_only_immutability_trigger_is_not_ready(client, app):
    action_id = capture(client, "independent-replica-trigger")
    sql("ALTER TABLE voalack.verifications ENABLE REPLICA TRIGGER verifications_immutable", fetch=False)
    try:
        error = readiness()
        print("REPLICA_ONLY_READINESS", error)
        if error is None:
            result = verify(app, action_id)
            assert result["outcome"] == "verified", result
            sql("UPDATE voalack.verifications SET reason='independent rewritten provenance' WHERE action_id=%s",
                (action_id,), fetch=False)
            assert sql("SELECT reason FROM voalack.verifications WHERE action_id=%s", (action_id,)) == [
                ("independent rewritten provenance",)]
            print("REPLICA_ONLY_PROVENANCE_UPDATE", "allowed")
        assert error is not None, "Readiness accepted an immutability trigger that does not fire on normal sessions"
    finally:
        sql("ALTER TABLE voalack.verifications ENABLE TRIGGER verifications_immutable", fetch=False)


def test_partial_effect_key_index_is_not_ready(client, app):
    first = capture(client, "independent-shared-partial-key")
    second = capture(client, "independent-shared-partial-key")
    sql("ALTER TABLE voalack.effects DROP CONSTRAINT effects_effect_key_key", fetch=False)
    sql("CREATE UNIQUE INDEX independent_partial_effect_key ON voalack.effects(effect_key) "
        "WHERE state='REMOTE_CONFIRMED'", fetch=False)
    try:
        error = readiness()
        print("PARTIAL_UNIQUE_READINESS", error)
        if error is None:
            a, b = verify(app, first), verify(app, second)
            assert a["outcome"] == b["outcome"] == "verified", (a,b)
            rows = sql("SELECT count(*),count(DISTINCT effect_key) FROM voalack.effects WHERE action_id IN (%s,%s)",
                       (first,second))
            assert rows == [(2,1)], rows
            print("PARTIAL_UNIQUE_QUEUED_EFFECTS", 2, "DISTINCT_KEYS", 1)
        assert error is not None, "Readiness accepted a partial index instead of full effect-key uniqueness"
    finally:
        sql("DELETE FROM voalack.effects WHERE action_id IN (%s,%s)", (first,second), fetch=False)
        sql("DROP INDEX voalack.independent_partial_effect_key", fetch=False)
        sql("ALTER TABLE voalack.effects ADD CONSTRAINT effects_effect_key_key UNIQUE(effect_key)", fetch=False)


def test_extra_allowed_name_overload_is_not_ready(app):
    sql("CREATE FUNCTION voalack.promote_effect() RETURNS integer LANGUAGE sql SECURITY DEFINER "
        "SET search_path=pg_catalog,voalack,pg_temp AS 'SELECT 1'; "
        "ALTER FUNCTION voalack.promote_effect() OWNER TO voalack_admin; "
        "REVOKE ALL ON FUNCTION voalack.promote_effect() FROM PUBLIC; "
        "GRANT EXECUTE ON FUNCTION voalack.promote_effect() TO voalack_verifier", fetch=False)
    try:
        error = readiness()
        print("OVERLOAD_READINESS", error)
        with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
            cur.execute("SELECT voalack.promote_effect()")
            assert cur.fetchone() == (1,)
        print("EXTRA_OVERLOAD_EXECUTABLE", True)
        assert error is not None, "Readiness identifies approved functions by name without exact signature"
    finally:
        sql("DROP FUNCTION voalack.promote_effect()", fetch=False)
