"""T04 S1 finding: stored intent deadlines equal the signed ones to the microsecond."""
import json

import pytest

from conftest import ack, new_alert, sql
from voalack import envelope as v2


def test_stored_deadlines_equal_the_signed_ones(client):
    alert_id = new_alert(client)
    assert ack(client, alert_id).status_code == 200
    issued, capture, execution, canonical = sql(
        "SELECT issued_at, capture_expires_at, execution_expires_at, envelope_canonical "
        "FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))[0]
    env = json.loads(bytes(canonical))
    assert (issued, capture, execution) == (v2.parse_utc(env["issued_at"]), v2.parse_utc(env["capture_expires_at"]),
                                            v2.parse_utc(env["execution_expires_at"]))


def test_alerta_datetime_adapter_keeps_only_milliseconds_but_strings_are_exact(app):
    # Documents why exact signed strings are bound: the process-global adapter Alerta registers.
    from datetime import datetime, timezone
    import psycopg2
    from conftest import APP_DSN
    exact = datetime(2026, 10, 2, 12, 0, 0, 123789, tzinfo=timezone.utc)
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT %s::timestamptz, %s::timestamptz", (exact, "2026-10-02T12:00:00.123789Z"))
        adapted, from_string = cur.fetchone()
    assert adapted.microsecond == 123000 and from_string == exact      # floored, not rounded


def captured_non_ms(client):
    """A real capture whose signed issuance has a sub-millisecond part. Issuance comes from the live
    database clock, so this retries: each try misses with probability 1/1000 (not deterministic;
    five misses in a row ~1e-15)."""
    for _ in range(5):
        alert_id = new_alert(client)
        assert ack(client, alert_id).status_code == 200
        action_id, canonical = sql("SELECT action_id::text, envelope_canonical FROM voalack.prepared_intents "
                                   "WHERE alert_id = %s", (alert_id,))[0]
        env = json.loads(bytes(canonical))
        if v2.parse_utc(env["issued_at"]).microsecond % 1000:
            return alert_id, action_id, env
    raise AssertionError("no non-millisecond issuance observed")


def test_stored_values_are_exact_for_a_non_millisecond_issuance(client):
    _, action_id, env = captured_non_ms(client)
    issued, capture, execution = sql("SELECT issued_at, capture_expires_at, execution_expires_at "
                                     "FROM voalack.prepared_intents WHERE action_id = %s", (action_id,))[0]
    assert issued.microsecond % 1000
    assert (issued, capture, execution) == tuple(v2.parse_utc(env[k]) for k in
                                                 ("issued_at", "capture_expires_at", "execution_expires_at"))


@pytest.mark.parametrize("at,inside", [
    ("2026-10-02T12:00:00.000123Z", True),     # exactly issued_at
    ("2026-10-02T12:00:00.000122Z", False),    # 1 µs before issuance
    ("2026-10-02T12:01:00.123455Z", True),     # 1 µs before expiry
    ("2026-10-02T12:01:00.123456Z", False),    # exactly at expiry: exclusive
    ("2026-10-02T12:01:00.123000Z", True),     # would equal a millisecond-truncated expiry
    ("2026-10-02T12:00:00.000000Z", False),    # would equal a millisecond-truncated issuance
])
def test_commit_window_uses_exact_microseconds(app, at, inside):
    import psycopg2
    from conftest import APP_DSN
    from voalack.boundary import _within_capture_window
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        assert _within_capture_window(cur, "2026-10-02T12:00:00.000123Z", "2026-10-02T12:01:00.123456Z", at) is inside


# --- verifier: exact deadline comparisons and legacy precision ------------------------------

def _iso(value):
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _evaluate(app, action_id, at):
    import psycopg2.extras
    from conftest import VERIFIER_DSN
    from voalack import verifier
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return verifier.evaluate(cur, action_id, signing.ctx, signing.keys, at=at)[:2]


def test_verifier_execution_deadline_is_exact_and_exclusive(client, app):
    from datetime import timedelta
    _, action_id, env = captured_non_ms(client)
    deadline = v2.parse_utc(env["execution_expires_at"])
    assert deadline.microsecond % 1000
    assert _evaluate(app, action_id, env["execution_expires_at"]) == ("refused", "expired")
    assert _evaluate(app, action_id, _iso(deadline - timedelta(microseconds=1))) == ("verified", "ok")
    floored = deadline.replace(microsecond=deadline.microsecond - deadline.microsecond % 1000)
    assert _evaluate(app, action_id, _iso(floored)) == ("verified", "ok")   # a truncated deadline would refuse


LEGACY = ("UPDATE voalack.prepared_intents SET issued_at = date_trunc('milliseconds', issued_at), "
          "capture_expires_at = date_trunc('milliseconds', capture_expires_at), "
          "execution_expires_at = date_trunc('milliseconds', execution_expires_at) WHERE action_id = %s")


def test_pre_fix_millisecond_rows_are_held_with_a_named_reason_then_expire(client, app):
    from datetime import timedelta
    _, action_id, env = captured_non_ms(client)
    sql(LEGACY, (action_id,), fetch=False)
    deadline = v2.parse_utc(env["execution_expires_at"])
    assert _evaluate(app, action_id, None) == ("hold", "legacy_deadline_precision")
    assert _evaluate(app, action_id, _iso(deadline - timedelta(microseconds=1))) == ("hold",
                                                                                      "legacy_deadline_precision")
    assert _evaluate(app, action_id, env["execution_expires_at"]) == ("refused", "expired")


def test_other_stored_deadline_differences_are_refused(client, app):
    _, action_id, _ = captured_non_ms(client)
    sql("UPDATE voalack.prepared_intents SET execution_expires_at = execution_expires_at + interval '1 millisecond' "
        "WHERE action_id = %s", (action_id,), fetch=False)
    assert _evaluate(app, action_id, None) == ("refused", "deadline_mismatch")
