"""T04 S4: the projector (display only; no endpoint, credential or delivery capability).

Publishes one Alerta note per outcome event through ``voalack.project_next``, which does the whole
step in one database transaction: the note, its protected publication record, the marker and the
position commit or roll back together. The projector reads the external recovery anchor and passes
its exact epoch and head; the database refuses (``paused``) unless that is its open line. A changed
anchor head after a step stops the process. Projection never sends, settles, releases or requeues.
"""
from __future__ import annotations

from typing import Optional

import psycopg2
import psycopg2.errors
import psycopg2.extras

from . import recovery, verifier

LOCK_TIMEOUT_MS = 2000          # bounded wait on the alert row (Alerta's own ACK transaction holds it)
STATEMENT_TIMEOUT_MS = 10000
CONNECT_TIMEOUT_S = 2

PROJECTOR = verifier.Profile(
    "voalack_projector", ("voalack_admin", "voalack_app", "voalack_verifier", "voalack_sender", "voalack_settler"),
    ("voalack.project_next(text, bigint, text)", "voalack.projection_status(uuid)",
     "voalack.projection_resolve(uuid, bigint, text, text)"),
    ("outcome_events", "projections", "projection_actions", "projection_positions"),
    (("outcome_events", "outcome_events_immutable"), ("projections", "projections_immutable")),
    (("outcome_events", "action_id,revision", True), ("projections", "action_id,revision", True),
     ("projection_actions", "action_id", True), ("projection_positions", "action_id", True)),
    events=verifier.ALL_EVENTS)


class AnchorChanged(RuntimeError):
    """The anchor's head moved while this projector worked: the process stops (nothing to undo)."""


class UnknownCommit(RuntimeError):
    """The outcome of a step's COMMIT is unknown; resolve it with ``resolve`` in a new connection."""

    def __init__(self, step: dict):
        super().__init__("projection COMMIT outcome unknown")
        self.step = step


def connect(dsn: str):
    return psycopg2.connect(dsn, connect_timeout=CONNECT_TIMEOUT_S,
                            options=f"-c lock_timeout={LOCK_TIMEOUT_MS} -c statement_timeout={STATEMENT_TIMEOUT_MS}")


def step(conn, anchor_dir: str, name: str) -> dict:
    """One projection step. Returns the database's answer: ``paused``, ``idle`` (nothing pending), ``busy``
    (everything pending is locked by other projectors), ``retry`` or ``done`` with the action, revision,
    note id and status; ``deferred`` when a bounded wait ran out."""
    head = recovery.Anchor(anchor_dir).head()
    verifier.check_ready(conn, PROJECTOR)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", (name, head.epoch, head.sha256))
        result = dict(cur.fetchone())
    except (psycopg2.errors.LockNotAvailable, psycopg2.errors.QueryCanceled) as exc:
        conn.rollback()
        timeout = "lock_timeout" if isinstance(exc, psycopg2.errors.LockNotAvailable) else "statement_timeout"
        return {"outcome": "deferred", "reason": timeout}
    except Exception:
        conn.rollback()
        raise
    try:
        conn.commit()
    except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
        raise UnknownCommit(result) from exc
    if result.get("action_id") is not None:
        result["action_id"] = str(result["action_id"])
    after = recovery.Anchor(anchor_dir).head()
    if (after.seq, after.sha256) != (head.seq, head.sha256):
        raise AnchorChanged(f"anchor head moved from {head.seq} to {after.seq}")
    return result


def resolve(dsn: str, unknown: dict) -> str:
    """After an unknown COMMIT: in a new connection and transaction, compare the step this projector
    remembers with the stored event, its marker and, for a published disposition, the protected publication
    and the actual note (voalack.projection_resolve). ``committed`` only when every binding agrees,
    ``not_committed`` when there is no marker (the next step simply runs again), otherwise ``conflict``.
    Nothing is written here."""
    if unknown.get("outcome") != "done":
        return "not_committed"
    with connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack.projection_resolve(%s, %s, %s, %s)",
                    (str(unknown["action_id"]), unknown["revision"], unknown["note_id"], unknown["status"]))
        return cur.fetchone()[0]


def status(conn, action_id: str) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT voalack.projection_status(%s)", (action_id,))
        value = cur.fetchone()[0]
    conn.rollback()
    return value


def run(dsn: str, anchor_dir: str, name: str, max_steps: Optional[int] = None) -> list:
    """Project until no event is pending (``idle``), everything pending is locked by other projectors
    (``busy``), the database is not open at the anchor's head (``paused``), a bounded wait ran out
    (``deferred``) or ``max_steps`` steps ran. Returns the step results."""
    results = []
    with connect(dsn) as conn:
        while max_steps is None or len(results) < max_steps:
            result = step(conn, anchor_dir, name)
            results.append(result)
            if result["outcome"] in ("idle", "busy", "paused", "deferred"):
                break
    return results
