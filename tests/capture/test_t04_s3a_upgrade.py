"""T04 S3a follow-up: a real S2-to-S3a schema upgrade with historical attempts.

A fresh database gets the integrated S2 schema (73ed54e, vendored unchanged as
fixtures/schema_s2_73ed54e.sql) over a minimal stub of Alerta's alerts table (only what the capture
trigger's definition needs), historical rows written as an S2 deployment would have left them, and
then the current schema through ``voalack.schema.apply`` (one administrative transaction).
"""
import hashlib
import os
import uuid

import psycopg2
import pytest

from conftest import DSN
from voalack import schema

S2_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "schema_s2_73ed54e.sql")
STUB_ALERTA = """
CREATE TYPE public.history AS (id text, event text, severity text, status text, value text, text text,
                               type text, update_time timestamp, "user" text, timeout integer);
CREATE TABLE public.alerts (id text PRIMARY KEY, customer text, status text, history public.history[],
                            -- coexistence 3a: the columns the ownership class, lifetime and binding guard read
                            resource text, event text, environment text, origin text, create_time timestamp);
"""


@pytest.fixture
def upgrade_db():
    name = f"voalack_upgrade_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    dsn = DSN.rsplit("/", 1)[0] + "/" + name
    try:
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(STUB_ALERTA)
            cur.execute(open(S2_SCHEMA).read())                       # the S2 installation
            cur.execute("INSERT INTO voalack.instance_config VALUES ('up-inst', 'up-cred', 'fake-one/v1', 1)")
        yield dsn
    finally:
        admin.cursor().execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.close()


def _seed(cur, label, effect_state, attempts, in_flight=None):
    """One effect with its capture chain and ``attempts`` = [(state, permit), ...] as S2 left them."""
    action = str(uuid.uuid4())
    cur.execute("INSERT INTO voalack.prepared_intents (action_id, alert_id, txid, actor_login, payload) "
                "VALUES (%s, %s, 1, 'lab', '{}')", (action, f"alert-{label}"))
    cur.execute("INSERT INTO voalack.captures (action_id, alert_id, txid, history_user, history_time) "
                "VALUES (%s, %s, 1, 'lab', now())", (action, f"alert-{label}"))
    cur.execute("INSERT INTO voalack.verifications (action_id, claim_epoch, verifier_version, deployment_id, provider,"
                " outcome, reason, envelope_sha256, capture_fingerprint) VALUES (%s, 1, 'v', 'd', 'p', 'verified', "
                "'ok', %s, %s) RETURNING verification_id", (action, "a" * 64, "b" * 64))
    verification = cur.fetchone()[0]
    target = str(abs(hash(label)) % 10 ** 9 + 1)
    cur.execute("INSERT INTO voalack.effects (effect_key, instance_id, target_id, action_id, verification_id, state) "
                "VALUES (%s, 'up-inst', %s, %s, %s, %s) RETURNING effect_id",
                (f"key-{label}", target, action, verification, effect_state))
    effect = cur.fetchone()[0]
    ids = []
    for state, permit in attempts:
        attempt = str(uuid.uuid4())
        body = f"{label}-{attempt}".encode()
        cur.execute("INSERT INTO voalack.attempts (attempt_id, effect_id, action_id, instance_id, credential_ref, "
                    "provider_contract, config_revision, owner_generation, incarnation, target_kind, target_id, "
                    "request_bytes, request_sha256, permit_state, state, dispatched_at) "
                    "VALUES (%s, %s, %s, 'up-inst', 'up-cred', 'fake-one/v1', 1, 1, %s, 'triggered_alarm', %s, %s, %s, "
                    "%s, %s, CASE WHEN %s THEN now() END)",
                    (attempt, effect, action, str(uuid.uuid4()), target, psycopg2.Binary(body),
                     hashlib.sha256(body).hexdigest(), permit, state, state in ("dispatched", "uncertain", "confirmed")))
        ids.append(attempt)
    if in_flight is not None:
        attempt = ids[in_flight]
        guard_state = "uncertain" if effect_state == "UNCERTAIN" else "in_flight"
        cur.execute("INSERT INTO voalack.target_guards VALUES ('up-inst', 'triggered_alarm', %s, %s, %s)",
                    (target, attempt, guard_state))
        cur.execute("UPDATE voalack.effects SET in_flight_attempt = %s WHERE effect_id = %s", (attempt, effect))
    return effect


ABORTED = ("aborted_before_dispatch", "revoked")
SCENARIOS = {
    "none": ("QUEUED", [], None, (0, "QUEUED", False)),
    "one_aborted": ("QUEUED", [ABORTED], None, (1, "QUEUED", False)),
    "three_aborted": ("QUEUED", [ABORTED] * 3, None, (3, "BLOCKED", False)),
    "four_with_uncertain": ("UNCERTAIN", [ABORTED] * 3 + [("uncertain", "consumed")], 3, (4, "UNCERTAIN", True)),
    "confirmed_mixed": ("REMOTE_CONFIRMED", [ABORTED, ("confirmed", "consumed")], None, (2, "REMOTE_CONFIRMED", False)),
    "started_in_flight": ("QUEUED", [("started", "unconsumed")], 0, (1, "QUEUED", True)),
    "third_started_in_flight": ("QUEUED", [ABORTED, ABORTED, ("started", "unconsumed")], 2, (3, "QUEUED", True)),
}


def _state(cur, effect):
    cur.execute("SELECT e.attempt_count, e.state, e.in_flight_attempt IS NOT NULL, "
                "(SELECT count(*) FROM voalack.target_guards g WHERE g.attempt_id = e.in_flight_attempt) "
                "FROM voalack.effects e WHERE e.effect_id = %s", (effect,))
    return cur.fetchone()


def test_s2_to_s3a_upgrade_counts_history_and_retires_exhausted_queues(upgrade_db):
    with psycopg2.connect(upgrade_db) as conn, conn.cursor() as cur:
        effects = {name: _seed(cur, name, state, attempts, in_flight)
                   for name, (state, attempts, in_flight, _) in SCENARIOS.items()}
    with psycopg2.connect(upgrade_db) as conn:
        schema.apply(conn)                                              # the upgrade
    with psycopg2.connect(upgrade_db) as conn, conn.cursor() as cur:
        for name, (_, _, _, (count, state, in_flight)) in SCENARIOS.items():
            got = _state(cur, effects[name])
            assert got[:3] == (count, state, in_flight), (name, got)
            assert got[3] == (1 if in_flight else 0), (name, got)     # guards untouched
        # Coexistence 3a migration: the seeded history names alerts with no row here, so each id is reserved
        # closed as migration_prior_absent, and lifetime-1 is recorded.
        cur.execute("SELECT DISTINCT alert_id FROM voalack.prepared_intents ORDER BY 1")
        history = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT alert_id, origin, closed_at IS NOT NULL, close_reason FROM voalack_lifetime.alert_lifetimes "
                    "ORDER BY 1")
        assert cur.fetchall() == [(a, "migration_prior_absent", True, "migration_prior_absent") for a in history]
        cur.execute("SELECT count(*) FROM voalack_lifetime.migrations WHERE version = 'lifetime-1'")
        assert cur.fetchone()[0] == 1
        before = {name: _state(cur, effect) for name, effect in effects.items()}
    with psycopg2.connect(upgrade_db) as conn:
        schema.apply(conn)                                              # repeated application: no change
    with psycopg2.connect(upgrade_db) as conn, conn.cursor() as cur:
        assert {name: _state(cur, effect) for name, effect in effects.items()} == before
        cur.execute("UPDATE voalack.effects SET attempt_count = 5 WHERE effect_id = %s", (effects["one_aborted"],))
    with psycopg2.connect(upgrade_db) as conn:
        schema.apply(conn)
    with psycopg2.connect(upgrade_db) as conn, conn.cursor() as cur:
        assert _state(cur, effects["one_aborted"])[:2] == (5, "BLOCKED")   # never lowered; exhausted → retired


def test_rolled_back_upgrade_leaves_the_s2_installation(upgrade_db):
    with psycopg2.connect(upgrade_db) as conn, conn.cursor() as cur:
        _seed(cur, "rollback", "QUEUED", [ABORTED] * 3)
    conn = psycopg2.connect(upgrade_db)
    try:
        conn.cursor().execute(schema.full_sql())             # 3a S3a: the full apply (guard, schema, guard)
        conn.rollback()
    finally:
        conn.close()
    with psycopg2.connect(upgrade_db) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM information_schema.columns WHERE table_schema = 'voalack' "
                    "AND table_name = 'effects' AND column_name = 'attempt_count'")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT state FROM voalack.effects")
        assert cur.fetchall() == [("QUEUED",)]
