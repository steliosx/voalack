"""T04 S3b: operator settlement of uncertain attempts (an explicit trusted operator capability).

The settler login has no network access, credential or sender capability. It records one decision
per uncertain attempt through ``settle_uncertain``; the database requires the reconciliation, and
for every outcome except an attributed confirmation, containment and quiescence of every holder of
the physical target and a read of the original target taken after them. An unknown COMMIT is
resolved by looking up the same decision id, never by a new or conflicting decision.
"""
from __future__ import annotations

from typing import Optional

import psycopg2

from . import verifier

LOCK_TIMEOUT_MS = 2000
STATEMENT_TIMEOUT_MS = 10000
CONNECT_TIMEOUT_S = 2

SETTLER = verifier.Profile(
    "voalack_settler", ("voalack_admin", "voalack_app", "voalack_verifier", "voalack_sender", "voalack_projector"),
    ("voalack.settle_uncertain(uuid, uuid, text, bigint, text)", "voalack.settlement_status(uuid)",
     "voalack.settle_recovered_hold(uuid, bigint, text, bigint, text)",              # T04 S3c
     "voalack.recovery_settlement_status(uuid)"),
    ("effects", "target_guards", "session_owners", "owner_containment", "provider_sessions", "quiescence",
     "reconciliations", "settlements",
     "recovered_effects", "recovered_holds", "recovery_reconciliations", "recovery_settlements",   # T04 S3c
     "recovery_adoptions"),
    (("owner_containment", "owner_containment_immutable"), ("quiescence", "quiescence_immutable"),
     ("provider_sessions", "provider_sessions_immutable"),
     ("reconciliation_reads", "reconciliation_reads_immutable"), ("reconciliations", "reconciliations_immutable"),
     ("settlements", "settlements_immutable"),
     ("recovered_effects", "recovered_effects_immutable"), ("recovery_adoptions", "recovery_adoptions_immutable"),
     ("recovery_reconciliations", "recovery_reconciliations_immutable"),
     ("recovery_settlements", "recovery_settlements_immutable"),
     ("recovery_reads", "recovery_reads_immutable"), ("recovery_cleanups", "recovery_cleanups_immutable")),
    (("settlements", "decision_id", True), ("settlements", "attempt_id", True), ("reconciliations", "read_id", True),
     ("recovery_settlements", "decision_id", True), ("recovery_settlements", "hold_id", True),      # T04 S3c
     ("quiescence", "instance_id,owner_generation,incarnation", True),
     ("target_guards", "instance_id,target_kind,target_id", True), ("target_guards", "attempt_id", True),
     ("provider_sessions", "session_ref", True)),
    # attempts: exactly these columns (never request_bytes, the ACK body)
    (("attempts", "attempt_id,effect_id,action_id,instance_id,credential_ref,provider_contract,config_revision,"
                  "owner_generation,incarnation,target_kind,target_id,request_sha256,permit_state,state,"
                  "started_at,dispatched_at,settled_at"),),
    # T04 S3c: a recovered hold only changes from active to released
    (("recovered_holds", "recovered_holds_release_only", "recovered_hold_release_only()"),),
    # T04 S4: the outcome events of the settler's own writes (the hold release is the settlement insert)
    (verifier.EVENT_SETTLEMENTS, verifier.EVENT_EFFECTS_STATE, verifier.EVENT_RECOVERY_SETTLEMENTS))


def _connect(dsn: str):
    return psycopg2.connect(dsn, connect_timeout=CONNECT_TIMEOUT_S,
                            options=f"-c lock_timeout={LOCK_TIMEOUT_MS} -c statement_timeout={STATEMENT_TIMEOUT_MS}")


def settle(dsn: str, decision_id: str, attempt_id: str, outcome: str, reconciliation_id: int,
           note: str = "", commit=None) -> str:
    """One operator decision. Returns the database outcome, or ``unknown_commit`` when the COMMIT's
    result is unknown (resolve with ``status`` for the same decision id). ``commit`` is a lab hook."""
    conn = _connect(dsn)
    try:
        verifier.check_ready(conn, SETTLER)
        with conn.cursor() as cur:
            cur.execute("SELECT voalack.settle_uncertain(%s, %s, %s, %s, %s)",
                        (decision_id, attempt_id, outcome, reconciliation_id, note))
            result = cur.fetchone()[0]
        try:
            (commit or (lambda c: c.commit()))(conn)
        except (psycopg2.OperationalError, psycopg2.InterfaceError, ConnectionError):
            return "unknown_commit"
        return result
    finally:
        conn.close()


def settle_hold(dsn: str, decision_id: str, hold_id: int, outcome: str, recovery_reconciliation_id: int,
                note: str = "", commit=None) -> str:
    """T04 S3c: one operator decision on a recovered hold (same contract as ``settle``)."""
    conn = _connect(dsn)
    try:
        verifier.check_ready(conn, SETTLER)
        with conn.cursor() as cur:
            cur.execute("SELECT voalack.settle_recovered_hold(%s, %s, %s, %s, %s)",
                        (decision_id, hold_id, outcome, recovery_reconciliation_id, note))
            result = cur.fetchone()[0]
        try:
            (commit or (lambda c: c.commit()))(conn)
        except (psycopg2.OperationalError, psycopg2.InterfaceError, ConnectionError):
            return "unknown_commit"
        return result
    finally:
        conn.close()


def hold_status(dsn: str, decision_id: str) -> Optional[dict]:
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM voalack.recovery_settlement_status(%s)", (decision_id,))
        row = cur.fetchone()
        return None if row is None else dict(zip(("hold_id", "outcome", "decided_at"), row))


def status(dsn: str, decision_id: str) -> Optional[dict]:
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM voalack.settlement_status(%s)", (decision_id,))
        row = cur.fetchone()
        return None if row is None else dict(zip(("attempt_id", "outcome", "effect_state", "decided_at"), row))
