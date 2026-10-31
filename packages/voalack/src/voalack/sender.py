"""T04 S2: the ONE session owner and the only send path (fake ONE provider contract only).

One ``OwnerSession`` per process incarnation owns one configured instance. It serializes every
provider operation (login, read, ACK, read-back, revoke) and fences each one against the database
owner row (instance, generation, incarnation). ``apply_once`` is the only way bytes reach the
transport: it starts a durable attempt, consumes its one-time dispatch permit at the last local
boundary, sends the bytes the database built exactly once, and records the result. Anything
uncertain is held; nothing is ever resent.

DB fencing cannot recall a request already on the wire: containment of a previous owner and the
live write hold (U1/U2) remain necessary.

T04 S3c: authority also depends on the external recovery anchor. An owner acquires only at the
anchor's open head, which the database must name; it re-reads the anchor before every provider
operation and final dispatch check and stops on any change. A volatile journal, written before each
permit consumption, stops the owner when the database shows a regression of its own attempts.
"""
from __future__ import annotations

import errno as errno_codes
import hashlib
import http.client
import json
import re
import threading
import time
import uuid
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

import psycopg2
import psycopg2.extras

from . import recovery, verifier

HANDOFF_BOUND_SECONDS = 1.0     # consume → transport; beyond this the attempt is held, not sent
LOCK_TIMEOUT_MS = 2000
STATEMENT_TIMEOUT_MS = 10000
CONNECT_TIMEOUT_S = 2


def _connect(dsn: str):
    """Every sender connection, including best-effort ones, has bounded connect, lock and statement time."""
    return psycopg2.connect(dsn, connect_timeout=CONNECT_TIMEOUT_S,
                            options=f"-c lock_timeout={LOCK_TIMEOUT_MS} -c statement_timeout={STATEMENT_TIMEOUT_MS}")

SENDER = verifier.Profile(
    "voalack_sender", ("voalack_admin", "voalack_app", "voalack_verifier", "voalack_settler", "voalack_projector"),
    ("voalack.acquire_owner(text, text, uuid, bigint, integer, text, text)",       # T04 S3c
     "voalack.check_owner(text, bigint, uuid)",
     "voalack.suspend_owner(text, bigint, uuid)", "voalack.start_attempt(uuid, bigint, text, bigint, uuid)",
     "voalack.consume_dispatch(uuid, text, bigint, uuid)", "voalack.check_dispatch(uuid, text, bigint, uuid)",
     "voalack.abort_attempt(uuid, text, bigint, uuid)",
     "voalack.close_already_acked(uuid, text, bigint, uuid, jsonb)",
     "voalack.record_not_sent(uuid, text, bigint, uuid, jsonb)",
     "voalack.close_unsupported_target(uuid, text, bigint, uuid, jsonb)",
     "voalack.hold_attempt(uuid, text, bigint, uuid, text)",
     "voalack.record_result(uuid, text, bigint, uuid, jsonb)",
     "voalack.record_evidence(uuid, bigint, uuid, text, jsonb)",
     "voalack.release_stale_started(text, bigint, uuid)",
     "voalack.register_session(text, text, bigint, uuid)",                      # T04 S3b
     "voalack.begin_reconciliation(uuid, uuid, text, bigint, uuid)",
     "voalack.record_reconciliation(uuid, text, bigint, uuid, jsonb)",
     "voalack.settle_by_reconciliation(uuid, bigint, text, bigint, uuid)", "voalack.settlement_status(uuid)",
     "voalack.journal_facts(text, bigint, uuid, uuid[])",                           # T04 S3c
     "voalack.begin_recovery_read(uuid, bigint, text, bigint, uuid)",
     "voalack.record_recovery_read(uuid, text, bigint, uuid, jsonb)",
     "voalack.begin_observation(uuid, text, text, bigint, uuid)",                # T05b S1
     "voalack.record_observation(uuid, text, bigint, uuid, jsonb, timestamptz, timestamptz)"),
    ("effects", "attempts", "target_guards", "session_owners", "instance_config"),
    (("verifications", "verifications_immutable"), ("attempt_evidence", "attempt_evidence_immutable"),
     ("owner_containment", "owner_containment_immutable"),
     ("reconciliation_reads", "reconciliation_reads_immutable"), ("reconciliations", "reconciliations_immutable"),
     ("settlements", "settlements_immutable"), ("provider_sessions", "provider_sessions_immutable"),
     # T04 S3c: recovery records the sender's reads and the gate rely on
     ("recovery_transitions", "recovery_transitions_immutable"), ("recovery_adoptions", "recovery_adoptions_immutable"),
     ("recovered_effects", "recovered_effects_immutable"), ("recovery_reads", "recovery_reads_immutable"),
     ("recovery_reconciliations", "recovery_reconciliations_immutable"),
     ("recovery_cleanups", "recovery_cleanups_immutable"),
     # T05b S1: the observation records the sender's own reads rely on
     ("observation_chains", "observation_chains_immutable"), ("observation_reads", "observation_reads_immutable"),
     ("observation_completions", "observation_completions_immutable"),
     ("source_observations", "source_observations_immutable"),
     ("observation_evidence", "observation_evidence_immutable")),
    (("effects", "effect_key", True), ("effects", "action_id", True), ("attempts", "attempt_id", True),
     ("target_guards", "attempt_id", True), ("session_owners", "instance_id", True),
     ("target_guards", "instance_id,target_kind,target_id", True),      # the physical guard
     ("effects", "in_flight_attempt", False),                            # one unsettled attempt per effect
     ("instance_config", "credential_ref", True),                         # one owner per credential
     ("reconciliations", "read_id", True),                                # one record per reserved read
     ("settlements", "decision_id", True), ("settlements", "attempt_id", True),   # one decision per attempt
     ("provider_sessions", "session_ref", True),
     ("recovery_reconciliations", "read_id", True),                      # T04 S3c: one record per recovery read
     # T05b S1: one reservation per observation id and per sequence value, at most one completion and one
     # stored row per reservation, one anchor per chain
     ("observation_reads", "obs_id", True), ("observation_reads", "reservation_seq", True),
     ("observation_completions", "obs_id", True), ("source_observations", "obs_id", True),
     ("source_observations", "reservation_seq", True),
     ("observation_chains", "instance_id,target_kind,target_id,alert_id,binding_id,binding_revision", True)),
    (),
    (("recovered_holds", "recovered_holds_release_only", "recovered_hold_release_only()"),),
    # T04 S4: the outcome events of the sender's own writes
    (verifier.EVENT_EFFECTS_STATE, verifier.EVENT_SETTLEMENTS),
    # T05b S1: the observer flag fence (a flag change must bump config_revision)
    (("instance_config", "instance_config_observer_bump", "_observer_flag_bump()"),))


class OwnerStopped(RuntimeError):
    """This owner has stopped issuing requests (fenced, suspended, database lost or unknown COMMIT)."""


class UnknownCommit(RuntimeError):
    """The outcome of a COMMIT is unknown to this process."""


class ConnectFailed(OSError):
    """The explicit connect step of a dedicated ACK connection failed with no socket: no ACK byte
    was written (S3a no-write boundary)."""


class NotAuthorizedAfterConnect(RuntimeError):
    """The final authority refused after a successful connect; the connection was closed unwritten."""


class FakeOneTransport:
    """HTTP client for the fake ONE contract ``fake-one/v1`` (loopback only). Counts its own writes."""

    def __init__(self, base_url: str, timeout: float = 10.0):
        parts = urlsplit(base_url)
        if parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("the fake transport is loopback-only")
        self.host, self.port, self.timeout = parts.hostname, parts.port, timeout
        self.counts = {"ack_writes": 0, "logins": 0, "reads": 0, "revokes": 0}   # ack_writes: write-phase entries
        self.phase_counts = {"ack_connects": 0, "ack_connect_failures": 0}

    def _call(self, method: str, path: str, body: Optional[bytes] = None, token: Optional[str] = None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["X-Session"] = token
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read()
            return response.status, (json.loads(payload) if payload else None)
        finally:
            conn.close()

    def login(self, credential_ref: str) -> str:
        self.counts["logins"] += 1
        status, payload = self._call("POST", "/login", json.dumps({"credential": credential_ref}).encode())
        if status != 200:
            raise OSError(f"fake login failed ({status})")
        return payload["token"]

    def ack(self, token: str, request_bytes: bytes, after_connect: Optional[Callable[[Any], Optional[str]]] = None):
        """One ACK on a dedicated connection: explicit connect (no implicit reopen, no tunnel), then
        the caller's final authority, then the single write. Returns (status, payload)."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        conn.auto_open = 0                           # never reconnect implicitly
        self.phase_counts["ack_connects"] += 1
        try:
            try:
                conn.connect()
            except OSError as exc:
                if conn.sock is None:                # positively observed: no socket, no byte written
                    self.phase_counts["ack_connect_failures"] += 1
                    failed = ConnectFailed(type(exc).__name__)
                    failed.native = {"class": type(exc).__name__,
                                     "errno": errno_codes.errorcode.get(exc.errno) if exc.errno else None,
                                     "socket_after_connect": None}
                    raise failed from exc
                raise
            reason = after_connect(conn) if after_connect is not None else None
            if reason is not None:
                raise NotAuthorizedAfterConnect(reason)
            self.counts["ack_writes"] += 1           # entering the header/body write phase
            conn.request("POST", "/ack", body=request_bytes,
                         headers={"Content-Type": "application/json", "X-Session": token})
            response = conn.getresponse()
            payload = response.read()
            return response.status, (json.loads(payload) if payload else None)
        finally:
            conn.close()

    def read_alarm(self, token: str, target_id: str):
        self.counts["reads"] += 1
        return self._call("GET", f"/alarms/{target_id}", None, token)

    def revoke(self, token: str) -> None:
        self.counts["revokes"] += 1
        self._call("POST", "/revoke", b"{}", token)


class OwnerSession:
    """The single owner of one ONE instance for one process incarnation."""

    def __init__(self, dsn: str, instance_id: str, owner_id: str, transport: FakeOneTransport,
                 handoff_bound: float = HANDOFF_BOUND_SECONDS,
                 hooks: Optional[Mapping[str, Callable[..., Any]]] = None, *, anchor: recovery.Anchor,
                 mode: str = "ordinary"):
        self.dsn, self.instance_id, self.owner_id, self.transport = dsn, instance_id, owner_id, transport
        self.anchor = anchor                         # T04 S3c: read-only view of the recovery anchor
        if mode not in ("ordinary", "maintenance"):
            raise ValueError("unknown owner mode")
        self.mode = mode                             # maintenance: recovery reads only (recovering phase)
        self.head: Optional[tuple] = None            # the exact anchor head (seq, sha256) acquired under
        self.journal: dict = {}                      # attempt_id -> expected facts (volatile, C6)
        self.handoff_bound = handoff_bound
        self.hooks = dict(hooks or {})
        self.incarnation = str(uuid.uuid4())       # a restarted process is a new incarnation
        self.generation: Optional[int] = None
        self.credential_ref: Optional[str] = None
        self.token: Optional[str] = None
        self.stopped: Optional[str] = None
        self.counts = {"dispatch_entries": 0}
        self._lock = threading.Lock()
        self._conn = None

    # -- database ---------------------------------------------------------------------------

    def _db(self):
        if self._conn is None or self._conn.closed:
            self._conn = _connect(self.dsn)
        return self._conn

    def _cursor(self):
        return self._db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def _commit(self, stage: str) -> None:
        hook = self.hooks.get(f"commit:{stage}")
        try:
            if hook is not None:
                hook(self._conn)                     # lab fault injection (scripted, labelled)
            else:
                self._conn.commit()
        except (psycopg2.OperationalError, psycopg2.InterfaceError, UnknownCommit) as exc:
            self._drop_connection()
            raise UnknownCommit(stage) from exc

    def _drop_connection(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        except psycopg2.Error:
            pass
        self._conn = None

    def _owner_call(self, sql: str, args: tuple):
        try:
            cur = self._cursor()
            cur.execute(sql, args)
            row = cur.fetchone()
            self._db().commit()
            return row
        except psycopg2.Error:
            self._drop_connection()
            self.stop("database_lost")
            raise OwnerStopped("database_lost") from None

    # -- ownership ----------------------------------------------------------------------------

    def acquire(self) -> int:
        if self.stopped or self.generation is not None:
            raise OwnerStopped(self.stopped or "already_acquired")   # a stop latch is never reset (R4)
        head = self.anchor.head()                    # AnchorInvalid: no acquisition
        required = "open" if self.mode == "ordinary" else "recovering"
        if head.phase != required:
            raise recovery.AnchorInvalid(f"anchor is {head.phase}, not {required}")
        conn = self._db()
        verifier.check_ready(conn, SENDER)
        cur = self._cursor()
        cur.execute("SELECT voalack.acquire_owner(%s, %s, %s, %s, %s, %s, %s) AS g",
                    (self.instance_id, self.owner_id, self.incarnation, head.epoch, head.seq, head.sha256,
                     self.mode))
        self.generation = cur.fetchone()["g"]
        # The configuration snapshot acquired with the owner row (same transaction, row still locked).
        cur.execute("SELECT bound_credential_ref, bound_config_revision, bound_provider_contract "
                    "FROM voalack.session_owners WHERE instance_id = %s", (self.instance_id,))
        snapshot = cur.fetchone()
        self.credential_ref = snapshot["bound_credential_ref"]
        self.config = (snapshot["bound_credential_ref"], snapshot["bound_config_revision"],
                       snapshot["bound_provider_contract"])
        conn.commit()
        self.head = (head.seq, head.sha256)
        return self.generation

    def _fence(self) -> None:
        """Local stop first; then the database fence and the journal (each may wait in PostgreSQL);
        then, last and with no database wait after it, the local stop latch and the exact anchor
        head (F1). The caller performs its provider operation immediately afterwards. Any failure
        stops this owner."""
        if self.stopped:
            raise OwnerStopped(self.stopped)
        row = self._owner_call("SELECT voalack.check_owner(%s, %s, %s) AS state",
                               (self.instance_id, self.generation, self.incarnation))
        if row["state"] != "active":
            reason = row["state"] if row["state"] in ("config_changed", "epoch_changed") else "fenced"
            self.stop(reason)
            raise OwnerStopped(reason)
        self._journal_check()
        self._final_check()

    def _final_check(self) -> None:
        """The last local boundary before a provider operation: the stop latch, then the anchor head."""
        if self.stopped:
            raise OwnerStopped(self.stopped)
        self._anchor_check()

    # -- T04 S3c: the anchor and the live journal ------------------------------------------------

    def _anchor_check(self) -> None:
        """The anchor head is exactly the one this owner acquired under. A new line of any phase, a
        shorter or unreadable file or any validation failure stops this owner first."""
        try:
            head = self.anchor.head()
            current = (head.seq, head.sha256)
        except recovery.AnchorInvalid:
            current = None
        if self.head is None or current != self.head:
            self.stop("anchor_changed")
            raise OwnerStopped("anchor_changed")

    def _journal_open(self, attempt_id: str, effect_id: int, request_sha256: str) -> None:
        """Before the consume statement: freeze what this owner knows about its started attempt
        (its original identities, physical key and configuration). Consume is a possible result,
        never authority to retry."""
        row = self._owner_call("SELECT action_id::text AS action_id, target_kind, target_id, credential_ref, "
                               "config_revision, provider_contract, state, permit_state FROM voalack.attempts "
                               "WHERE attempt_id = %s AND owner_generation = %s AND incarnation = %s",
                               (attempt_id, self.generation, self.incarnation))
        if row is None or (row["state"], row["permit_state"]) != ("started", "unconsumed") or (
                row["credential_ref"], row["config_revision"], row["provider_contract"]) != tuple(self.config):
            self.stop("journal_regression")
            raise OwnerStopped("journal_regression")
        self.journal[attempt_id] = {"progress": "consume_pending", "effect_id": effect_id,
                                    "action_id": row["action_id"], "request_sha256": request_sha256,
                                    "key": (self.instance_id, row["target_kind"], row["target_id"]),
                                    "config": tuple(self.config)}

    def _journal_advance(self, attempt_id: str, progress: str) -> None:
        """Only results known to be committed advance an entry; entries are never retired."""
        if attempt_id in self.journal:
            self.journal[attempt_id]["progress"] = progress

    def _journal_check(self) -> None:
        if not self.journal:
            return
        try:
            cur = self._cursor()
            cur.execute("SELECT * FROM voalack.journal_facts(%s, %s, %s, %s::uuid[])",
                        (self.instance_id, self.generation, self.incarnation, list(self.journal)))
            rows = {r["attempt_id"]: r for r in cur.fetchall()}
            self._db().commit()
        except psycopg2.Error:
            self._drop_connection()
            self.stop("database_lost")
            raise OwnerStopped("database_lost") from None
        for attempt_id, entry in self.journal.items():
            if not self._journal_consistent(attempt_id, entry, rows.get(attempt_id)):
                self.stop("journal_regression")
                raise OwnerStopped("journal_regression")

    def _journal_consistent(self, attempt_id: str, entry: dict, row) -> bool:
        """The complete partial order (R5): original identities, permit progress, guard and effect
        disposition, and a settlement only as an exact cover for this attempt."""
        if row is None:
            return False
        if ((row["owner_generation"], row["incarnation"], row["effect_id"], row["action_id"], row["request_sha256"],
             (row["instance_id"], row["target_kind"], row["target_id"]),
             (row["credential_ref"], row["config_revision"], row["provider_contract"]))
                != (self.generation, self.incarnation, entry["effect_id"], entry["action_id"], entry["request_sha256"],
                    entry["key"], entry["config"])):
            return False
        state, permit = row["state"], row["permit_state"]
        if (state, permit) not in JOURNAL_ALLOWED[entry["progress"]]:
            return False
        if state in ("dispatched", "confirmed", "not_sent") or (state == "uncertain" and permit == "consumed"):
            if not row["dispatched"]:
                return False
        own_guard = row["guard_attempt"] == attempt_id
        own_flight = row["in_flight"] == attempt_id
        if state in ("started", "dispatched"):
            return own_guard and own_flight and row["guard_state"] == "in_flight"
        if state == "uncertain" and not row["settled"]:
            return own_guard and own_flight and row["guard_state"] == "uncertain" and row["effect_state"] == "UNCERTAIN"
        if own_guard or own_flight:
            return False                                 # terminal or settled work holds nothing
        if state == "uncertain":
            return row["effect_state"] == row["settlement_effect_state"]
        if state == "confirmed":
            return row["effect_state"] == "REMOTE_CONFIRMED"
        return True                                      # not_sent / aborted: released, never resurrected

    def _recovery_reason(self) -> Optional[str]:
        """The journal, then the stop latch and anchor head last, as a refusal reason (a failure has
        already stopped this owner)."""
        try:
            self._journal_check()
            self._final_check()
        except OwnerStopped as exc:
            return str(exc)
        return None

    def stop(self, reason: str) -> None:
        """Stop issuing requests locally at once; persisting the suspension is best effort and its
        failure does not matter to the local stop."""
        if not self.stopped:
            self.stopped = reason
        try:
            with _connect(self.dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT voalack.suspend_owner(%s, %s, %s)", (self.instance_id, self.generation, self.incarnation))
        except psycopg2.Error:
            pass

    def login(self) -> None:
        with self._lock:
            self._fence()
            if self.token is None:
                self._open_session()

    def _open_session(self) -> None:
        """T04 S3b: log in and register the session by digest before any use of it (quiescence must
        cover every session an incarnation opened). An unregistered session is never used; a
        registration that does not succeed stops this owner."""
        token = self.transport.login(self.credential_ref)
        row = self._owner_call("SELECT voalack.register_session(%s, %s, %s, %s) AS o",
                               (hashlib.sha256(token.encode()).hexdigest(), self.instance_id, self.generation,
                                self.incarnation))
        if row["o"] != "registered":
            self.stop("session_unregistered")
            raise OwnerStopped("session_unregistered")
        self.token = token

    def revoke(self) -> None:
        with self._lock:
            self._fence()
            if self.token is not None:
                self.transport.revoke(self.token)
                self.token = None

    def release_stale_started(self) -> list:
        with self._lock:
            self._fence()
            try:
                cur = self._cursor()
                cur.execute("SELECT * FROM voalack.release_stale_started(%s, %s, %s)",
                            (self.instance_id, self.generation, self.incarnation))
                rows = [dict(r) for r in cur.fetchall()]
                self._db().commit()
                return rows
            except psycopg2.Error:
                self._drop_connection()
                self.stop("database_lost")
                raise OwnerStopped("database_lost") from None

    def _hold(self, attempt_id: str, reason: str) -> None:
        """Best-effort persistence of a hold. If it cannot be written, the whole owner stops locally
        at once (the attempt and its guard stay as the database has them)."""
        try:
            with _connect(self.dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT voalack.hold_attempt(%s, %s, %s, %s, %s)",
                            (attempt_id, self.instance_id, self.generation, self.incarnation, reason))
        except psycopg2.Error:
            if not self.stopped:
                self.stopped = "database_lost"
            self.stop("database_lost")

    def _lookup(self, attempt_id: str):
        try:
            with _connect(self.dsn) as conn:
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute("SELECT * FROM voalack.attempts WHERE attempt_id = %s", (attempt_id,))
                return cur.fetchone()
        except psycopg2.Error:
            return None

    # -- T04 S3b: read-only reconciliation -----------------------------------------------------

    def reconcile(self, attempt_id: str, settle: bool = True) -> dict:
        """One read of an uncertain attempt's original target, recorded under the original identities
        and this owner's; an attributable read is settled automatically (``settle``). Never writes an
        ACK. The owner mutex is held from the reservation through the record and any settlement, so
        no other operation of this owner interleaves. A configuration change, fence, lost database or
        unknown COMMIT stops this owner locally, with no later provider operation."""
        with self._lock:
            read_id = str(uuid.uuid4())
            result = {"read_id": read_id}
            try:
                return self._reconcile(attempt_id, read_id, settle, result)
            except OwnerStopped as exc:
                return {**result, "outcome": "held", "reason": str(exc)}

    def _reconcile(self, attempt_id: str, read_id: str, settle: bool, result: dict) -> dict:
        self._fence()
        row = self._owner_call("SELECT * FROM voalack.begin_reconciliation(%s, %s, %s, %s, %s)",
                               (read_id, attempt_id, self.instance_id, self.generation, self.incarnation))
        result["reservation"] = row["outcome"]
        if row["outcome"] != "reserved":                # committed refusal: no credential or network use
            if row["outcome"] in ("config_changed", "owner_fenced"):
                self.stop(row["outcome"])               # a fence or configuration refusal stops the owner
            return {**result, "outcome": "refused", "reason": row["outcome"]}
        self._hook("after_reservation", read_id)
        self._fence()                                   # fresh checks before login and before the read
        observation: dict = {"kind": "reconciliation_read", "target_id": row["r_target_id"]}
        login_error = None
        if self.token is None:
            try:
                self._open_session()
            except (OSError, http.client.HTTPException, ValueError) as exc:
                login_error = type(exc).__name__        # a provider login failure: no read, evidence only
            else:
                self._fence()
        if login_error is not None:
            observation.update(status=None, error=f"login_failed:{login_error}")
        else:
            observation["read_started_at"] = _utc_now()
            try:
                status, alarm = self.transport.read_alarm(self.token, row["r_target_id"])
                observation.update(status=status, alarm=alarm)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                observation.update(status=None, error=type(exc).__name__)
            observation["read_completed_at"] = _utc_now()
        self._hook("before_record", read_id)
        rec = self._owner_call("SELECT * FROM voalack.record_reconciliation(%s, %s, %s, %s, %s::jsonb)",
                               (read_id, self.instance_id, self.generation, self.incarnation,
                                json.dumps(observation)))
        result.update(recorded=rec["outcome"], reconciliation_id=rec["r_reconciliation_id"],
                      classification=rec["r_classification"])
        if rec["outcome"] in ("config_changed", "owner_fenced"):
            self.stop(rec["outcome"])
            return {**result, "outcome": "held", "reason": rec["outcome"]}
        if rec["outcome"] != "recorded" or not settle or rec["r_classification"] != "attributable":
            return {**result, "outcome": "recorded"}
        decision = str(uuid.uuid4())
        result["decision_id"] = decision
        self._hook("before_settle", decision)
        try:
            cur = self._cursor()
            cur.execute("SELECT voalack.settle_by_reconciliation(%s, %s, %s, %s, %s) AS o",
                        (decision, rec["r_reconciliation_id"], self.instance_id, self.generation, self.incarnation))
            done = cur.fetchone()
            self._commit("settle")
        except UnknownCommit:
            # Unknown settlement COMMIT: stop first; only the same decision may be looked up
            # (presence identifies the committed decision; absence is not proof of rollback).
            self.stop("unknown_settlement_commit")
            return {**result, "outcome": "held", "reason": "unknown_settlement_commit",
                    "lookup": settlement_lookup(self.dsn, decision)}
        except psycopg2.Error:
            self._drop_connection()
            self.stop("database_lost")
            raise OwnerStopped("database_lost") from None
        result["settlement"] = done["o"]
        if done["o"] in ("config_changed", "owner_fenced"):
            self.stop(done["o"])
            return {**result, "outcome": "held", "reason": done["o"]}
        return {**result, "outcome": "settled" if done["o"] == "settled" else "recorded"}

    # -- T04 S3c: recovery reads of a recovered hold's physical key ----------------------------------

    def recovery_read(self, hold_id: int) -> dict:
        """One read of a recovered hold's key (maintenance capability in the recovering phase, or an
        ordinary owner once open), recorded with an SQL classification against the hold's frozen
        members. Never writes an ACK; a fence or configuration change stops this owner."""
        with self._lock:
            read_id = str(uuid.uuid4())
            result = {"read_id": read_id, "hold_id": hold_id}
            try:
                self._fence()
                row = self._owner_call("SELECT * FROM voalack.begin_recovery_read(%s, %s, %s, %s, %s)",
                                       (read_id, hold_id, self.instance_id, self.generation, self.incarnation))
                result["reservation"] = row["outcome"]
                if row["outcome"] != "reserved":
                    if row["outcome"] in ("config_changed", "owner_fenced"):
                        self.stop(row["outcome"])
                    return {**result, "outcome": "refused", "reason": row["outcome"]}
                self._fence()
                observation: dict = {"kind": "recovery_read", "target_id": row["r_target_id"]}
                login_error = None
                if self.token is None:
                    try:
                        self._open_session()
                    except (OSError, http.client.HTTPException, ValueError) as exc:
                        login_error = type(exc).__name__
                    else:
                        self._fence()
                if login_error is not None:
                    observation.update(status=None, error=f"login_failed:{login_error}")
                else:
                    observation["read_started_at"] = _utc_now()
                    try:
                        status, alarm = self.transport.read_alarm(self.token, row["r_target_id"])
                        observation.update(status=status, alarm=alarm)
                    except (OSError, http.client.HTTPException, ValueError) as exc:
                        observation.update(status=None, error=type(exc).__name__)
                    observation["read_completed_at"] = _utc_now()
                self._hook("before_record", read_id)
                rec = self._owner_call("SELECT * FROM voalack.record_recovery_read(%s, %s, %s, %s, %s::jsonb)",
                                       (read_id, self.instance_id, self.generation, self.incarnation,
                                        json.dumps(observation)))
                result.update(recorded=rec["outcome"], recovery_reconciliation_id=rec["r_recovery_reconciliation_id"],
                              classification=rec["r_classification"])
                if rec["outcome"] in ("config_changed", "owner_fenced"):
                    self.stop(rec["outcome"])
                    return {**result, "outcome": "held", "reason": rec["outcome"]}
                return {**result, "outcome": "recorded" if rec["outcome"] in ("recorded", "already_recorded")
                        else "refused"}
            except OwnerStopped as exc:
                return {**result, "outcome": "held", "reason": str(exc)}

    # -- T05b: ledger-only source-state observation (off by default) ----------------------------

    def observe(self, alert_id: str) -> dict:
        """One read of a bound alert's ONE target, recorded in Voalack's own ledger only. Never writes an
        ACK, an Alerta note, a settlement or an intent. The instance's ``observer_enabled`` flag (default
        off) and every fence are checked by the database at reservation and again at record; a refusal
        uses no credential or network. A configuration change, fence, lost database or unknown COMMIT
        stops this owner locally, as for reconciliation."""
        with self._lock:
            obs_id = str(uuid.uuid4())
            result = {"obs_id": obs_id}
            try:
                return self._observe(alert_id, obs_id, result)
            except OwnerStopped as exc:
                return {**result, "outcome": "held", "reason": str(exc)}

    def _observe(self, alert_id: str, obs_id: str, result: dict) -> dict:
        from datetime import datetime, timezone
        self._fence()
        row = self._owner_call("SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)",
                               (obs_id, alert_id, self.instance_id, self.generation, self.incarnation))
        result["reservation"] = row["outcome"]
        if row["outcome"] != "reserved":                # committed refusal: no credential or network use
            if row["outcome"] in ("config_changed", "owner_fenced"):
                self.stop(row["outcome"])
            return {**result, "outcome": "refused", "reason": row["outcome"]}
        self._hook("after_observation_reservation", obs_id)
        self._fence()                                   # fresh checks before login and before the read
        status, alarm, read_error, started, completed = None, None, None, None, None
        if self.token is None:
            try:
                self._open_session()
            except (OSError, http.client.HTTPException, ValueError):
                read_error = "login"                    # no read happened: no client times
            else:
                self._fence()
        if read_error is None:
            started = datetime.now(timezone.utc)
            try:
                status, alarm = self.transport.read_alarm(self.token, row["r_target_id"])
            except (OSError, http.client.HTTPException, ValueError):
                read_error = "transport"
            completed = datetime.now(timezone.utc)
        summary = observation_summary(status, alarm, read_error)
        self._hook("before_observation_record", obs_id)
        # Times travel as ISO 8601 text with microseconds: a process-wide psycopg2 datetime adapter (Alerta
        # registers one with millisecond precision) must not change the replay identity.
        rec = self._owner_call("SELECT * FROM voalack.record_observation(%s, %s, %s, %s, %s::jsonb, "
                               "%s::timestamptz, %s::timestamptz)",
                               (obs_id, self.instance_id, self.generation, self.incarnation, json.dumps(summary),
                                started.isoformat() if started else None,
                                completed.isoformat() if completed else None))
        result.update(recorded=rec["outcome"], result=rec["r_result"], classification=rec["r_classification"])
        if rec["r_result"] in ("refused:config_changed", "refused:owner_fenced"):
            self.stop(rec["r_result"].split(":", 1)[1])
            return {**result, "outcome": "held", "reason": rec["r_result"]}
        return {**result, "outcome": "recorded"}

    def _hook(self, name: str, value: str) -> None:
        hook = self.hooks.get(name)
        if hook is not None:
            hook(value)                                 # lab: changes while an operation is outstanding

    # -- the only send path ---------------------------------------------------------------------

    def _preflight(self, attempt_id: str) -> Optional[dict]:
        target_id = self._owner_call("SELECT target_id FROM voalack.attempts WHERE attempt_id = %s",
                                     (attempt_id,))["target_id"]
        self._fence()
        observation: dict = {"kind": "preflight", "target_id": target_id}
        try:
            status, alarm = self.transport.read_alarm(self.token, target_id)
            observation.update(status=status, alarm=alarm)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            status, alarm = None, None
            observation.update(error=type(exc).__name__)
        known = status == 200 and isinstance(alarm, dict) and alarm.get("target_id") == target_id
        if known and "kind" in alarm and (alarm["kind"] != "triggered_alarm" or alarm.get("children")):
            row = self._owner_call("SELECT voalack.close_unsupported_target(%s, %s, %s, %s, %s::jsonb) AS o",
                                   (attempt_id, self.instance_id, self.generation, self.incarnation,
                                    json.dumps(observation)))
            if row["o"] == "config_changed":
                self.stop("config_changed")
                record_late_evidence(self.dsn, attempt_id, self.generation, self.incarnation,
                                     "late_preflight", observation)
                return {"outcome": "held", "reason": "config_changed"}
            return {"outcome": "refused", "reason": row["o"]}
        known = known and alarm.get("kind") == "triggered_alarm"   # the fake contract states the kind
        if known and alarm.get("acked") is False:
            return None
        if known and alarm.get("acked") is True:
            row = self._owner_call("SELECT voalack.close_already_acked(%s, %s, %s, %s, %s::jsonb) AS o",
                                   (attempt_id, self.instance_id, self.generation, self.incarnation,
                                    json.dumps(observation)))
            if row["o"] == "config_changed":
                # Observed under a configuration that no longer holds: no settlement; keep the
                # observation under the original identity and stop the whole owner.
                self.stop("config_changed")
                record_late_evidence(self.dsn, attempt_id, self.generation, self.incarnation,
                                     "late_preflight", observation)
                return {"outcome": "held", "reason": "config_changed"}
            return {"outcome": "refused", "reason": row["o"]}
        self._owner_call("SELECT voalack.record_evidence(%s, %s, %s, 'preflight_unavailable', %s::jsonb) AS o",
                         (attempt_id, self.generation, self.incarnation, json.dumps(observation)))
        row = self._owner_call("SELECT voalack.abort_attempt(%s, %s, %s, %s) AS o",
                               (attempt_id, self.instance_id, self.generation, self.incarnation))
        return {"outcome": "refused", "reason": "preflight_unavailable" if row["o"] == "aborted" else row["o"]}

    def _not_sent(self, attempt_id: str, request_sha256: str, error: str, ack_writes: int, result: dict,
                  native: Optional[dict] = None) -> dict:
        evidence = {"phase": "connect", "error": error, "connect": native, "ack_writes": ack_writes,
                    "request_sha256": request_sha256,
                    "attempt_id": attempt_id, "owner_generation": self.generation, "incarnation": self.incarnation,
                    "configuration": list(self.config), "transport": "dedicated-loopback-auto_open-0"}
        cur = self._cursor()
        cur.execute("SELECT voalack.record_not_sent(%s, %s, %s, %s, %s::jsonb) AS o",
                    (attempt_id, self.instance_id, self.generation, self.incarnation, json.dumps(evidence)))
        outcome = cur.fetchone()["o"]
        try:
            self._commit("not_sent")
        except UnknownCommit:
            self.stop("unknown_not_sent_commit")     # no retry from an unknown settlement
            return {**result, "outcome": "held", "reason": "unknown_not_sent_commit"}
        if outcome == "not_sent":
            self._journal_advance(attempt_id, "not_sent")
            return {**result, "outcome": "not_sent", "reason": error}
        self.stop("config_changed" if outcome == "config_changed" else "fenced")
        self._hold(attempt_id, f"not_sent_refused:{outcome}")
        return {**result, "outcome": "held", "reason": outcome}

    def apply_with_retry(self, effect_id: int, max_wait: float = 30.0) -> dict:
        """apply_once, retried only after a known-committed not_sent: sleeps (outside any
        transaction) until the effect's durable next_attempt_after; budget, backoff and the original
        deadline are enforced by start_attempt."""
        limit = time.monotonic() + max_wait
        while True:
            outcome = self.apply_once(effect_id)
            if outcome["outcome"] != "not_sent":
                return outcome
            hook = self.hooks.get("before_schedule")
            if hook is not None:
                hook(effect_id)                      # lab scheduling point (scripted)
            with self._lock:                         # the shared connection: never inside another transaction
                if self.stopped:
                    return {**outcome, "retry": "stopped", "effect_state": None}
                row = self._owner_call("SELECT state, greatest(0, extract(epoch FROM next_attempt_after - "
                                       "clock_timestamp()))::float AS wait FROM voalack.effects WHERE effect_id = %s",
                                       (effect_id,))
            if row["state"] != "QUEUED" or time.monotonic() + row["wait"] > limit:
                return {**outcome, "retry": "stopped", "effect_state": row["state"]}
            time.sleep(row["wait"])

    def apply_once(self, effect_id: int) -> dict:
        with self._lock:
            self._fence()                            # refuses at once if stopped, fenced or unreachable
            attempt_id = str(uuid.uuid4())
            result = {"effect_id": effect_id, "attempt_id": attempt_id}
            try:
                return self._apply(effect_id, attempt_id, result)
            except psycopg2.Error:
                # Any database failure mid-attempt: stop the whole owner locally first; the attempt
                # and its guard stay as the database has them; no retry, no reconnect authority.
                self._drop_connection()
                self.stop("database_lost")
                return {**result, "outcome": "held", "reason": "database_lost"}
            except OwnerStopped as exc:
                return {**result, "outcome": "held", "reason": str(exc)}

    def _apply(self, effect_id: int, attempt_id: str, result: dict) -> dict:
        # 1. A durable, eligible attempt before any credential or network use (S2-R3).
        cur = self._cursor()
        cur.execute("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                    (attempt_id, effect_id, self.instance_id, self.generation, self.incarnation))
        started = cur.fetchone()
        try:
            self._commit("start")
        except UnknownCommit:
            row = self._lookup(attempt_id)
            if not (row and row["state"] == "started" and row["permit_state"] == "unconsumed"
                    and row["owner_generation"] == self.generation and str(row["incarnation"]) == self.incarnation
                    and row["effect_id"] == effect_id):
                # Absence is not proof of no attempt: stop mutation for the whole owner.
                self.stop("unknown_start_commit")
                return {**result, "outcome": "held", "reason": "unknown_start_commit"}
            started = {"outcome": "started", "request_sha256": row["request_sha256"]}
        if started["outcome"] != "started":
            if started["outcome"] == "config_changed":
                self.stop("config_changed")
            return {**result, "outcome": "refused", "reason": started["outcome"]}
        expected_sha = started["request_sha256"]
        hook = self.hooks.get("after_start")
        if hook is not None:
            hook(attempt_id)                         # lab delay/fault point (scripted)

        # 2. Session for this attempt (fenced provider operation); a failure before consumption is
        #    a definitive no-dispatch.
        if self.token is None:
            self._fence()
            try:
                self._open_session()
            except (OSError, http.client.HTTPException, ValueError):
                self._owner_call("SELECT voalack.abort_attempt(%s, %s, %s, %s) AS o",
                                 (attempt_id, self.instance_id, self.generation, self.incarnation))
                return {**result, "outcome": "refused", "reason": "login_failed"}

        # 3. Preflight of the exact target (fenced): only an explicit, successful "not acknowledged"
        #    answer proceeds. Already acknowledged closes the attempt without dispatch; anything else
        #    is a definitive no-dispatch abort. Neither creates retry authority. Another actor may still
        #    acknowledge after this read (inherent; U1).
        outcome = self._preflight(attempt_id)
        if outcome is not None:
            return {**result, **outcome}
        hook = self.hooks.get("after_preflight")
        if hook is not None:
            hook(attempt_id)

        # 4. One-time permit consumption (re-checks owner, configuration, eligibility and deadline after
        #    the preflight). The hand-off clock starts before the consume call, so its waits, COMMIT and
        #    acknowledgement delay all count. T04 S3c: the journal entry is written before the statement.
        self._journal_open(attempt_id, effect_id, expected_sha)
        t_consumed = time.monotonic()
        cur = self._cursor()
        cur.execute("SELECT * FROM voalack.consume_dispatch(%s, %s, %s, %s)",
                    (attempt_id, self.instance_id, self.generation, self.incarnation))
        consumed = cur.fetchone()
        try:
            self._commit("consume")
        except UnknownCommit:
            # The permit may have been consumed: never send, hold, stop the owner.
            self.stop("unknown_consume_commit")
            self._hold(attempt_id, "unknown_consume_commit")
            return {**result, "outcome": "held", "reason": "unknown_consume_commit"}
        if consumed["outcome"] == "dispatched":
            self._journal_advance(attempt_id, "dispatched")
        elif consumed["outcome"].startswith("aborted:"):
            self._journal_advance(attempt_id, "aborted")
        if consumed["outcome"] != "dispatched":
            if consumed["outcome"] == "aborted:config_changed":
                self.stop("config_changed")
            return {**result, "outcome": "refused", "reason": consumed["outcome"]}
        request_bytes = bytes(consumed["request_bytes"])
        hook = self.hooks.get("before_send")
        if hook is not None:
            hook(attempt_id)

        # 5. Final authority in this invocation, after the known COMMIT (S2-R1): local stop, hand-off
        #    bound, digest, then the database's owner/eligibility/configuration/real-clock check. A
        #    failure holds the consumed attempt uncertain; it never aborts or releases it.
        reason = None
        if self.stopped:
            reason = "owner_stopped"
        elif time.monotonic() - t_consumed > self.handoff_bound:
            reason = "handoff_not_immediate"
        elif hashlib.sha256(request_bytes).hexdigest() != expected_sha:
            reason = "request_changed"
        else:
            # T04 S3c (F1): the database check and the journal (which may wait), then the local
            # stop latch and the anchor head last, with no database wait after them.
            reason = self._owner_call("SELECT voalack.check_dispatch(%s, %s, %s, %s) AS reason",
                                      (attempt_id, self.instance_id, self.generation, self.incarnation))["reason"]
            if reason is None:
                reason = self._recovery_reason()
            if reason is None and time.monotonic() - t_consumed > self.handoff_bound:
                reason = "handoff_not_immediate"
        if reason is not None:
            self._hold(attempt_id, reason)
            if reason in ("owner_fenced", "config_changed"):
                self.stop("fenced" if reason == "owner_fenced" else "config_changed")
            return {**result, "outcome": "held", "reason": reason}

        # 6. The transport (S3a): dedicated connection, explicit connect, the final authority again
        #    after the connect (database, committed before any byte), then the single write. A
        #    failed connect step with no socket is the only not_sent; any later failure is uncertain.
        self.counts["dispatch_entries"] += 1
        observation: dict = {"kind": "fake_ack"}
        writes_before = self.transport.counts["ack_writes"]

        def after_connect(conn):
            hook = self.hooks.get("after_connect")
            if hook is not None:
                hook(conn)                           # lab delay/fault point (scripted)
            if self.stopped:
                return "owner_stopped"
            if time.monotonic() - t_consumed > self.handoff_bound:
                return "handoff_not_immediate"
            again = self._owner_call("SELECT voalack.check_dispatch(%s, %s, %s, %s) AS reason",
                                     (attempt_id, self.instance_id, self.generation, self.incarnation))["reason"]
            if again is None:
                again = self._recovery_reason()
            if again is None and time.monotonic() - t_consumed > self.handoff_bound:
                again = "handoff_not_immediate"
            return again

        try:
            status, response = self.transport.ack(self.token, request_bytes, after_connect)
            observation.update(status=status, response=response)
        except ConnectFailed as exc:
            return self._not_sent(attempt_id, expected_sha, str(exc),
                                  self.transport.counts["ack_writes"] - writes_before, result,
                                  getattr(exc, "native", None))
        except NotAuthorizedAfterConnect as exc:
            reason = str(exc)
            self._hold(attempt_id, reason)
            if reason in ("owner_fenced", "config_changed"):
                self.stop("fenced" if reason == "owner_fenced" else "config_changed")
            return {**result, "outcome": "held", "reason": reason}
        except (OSError, http.client.HTTPException, ValueError) as exc:
            observation.update(kind="transport_error", error=type(exc).__name__)
        if observation["kind"] == "fake_ack":
            try:
                self._fence()
            except OwnerStopped:
                record_late_evidence(self.dsn, attempt_id, self.generation, self.incarnation, "late_result", observation)
                return {**result, "outcome": "held", "reason": "owner_fenced_after_send"}
            try:
                target_id = json.loads(request_bytes)["target"]["id"]
                read_status, read_back = self.transport.read_alarm(self.token, target_id)
                observation.update(read_status=read_status, read_back=read_back)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                observation.update(read_error=type(exc).__name__)
        hook = self.hooks.get("before_record")
        if hook is not None:
            hook(attempt_id)                         # lab fault point (scripted)
        row = self._owner_call("SELECT voalack.record_result(%s, %s, %s, %s, %s::jsonb) AS outcome",
                               (attempt_id, self.instance_id, self.generation, self.incarnation,
                                json.dumps(observation)))
        if row["outcome"] == "config_changed":
            # Configuration changed before settlement: the database kept the observation as late
            # evidence and holds the attempt uncertain; stop the whole owner (latched first).
            self.stop("config_changed")
            return {**result, "outcome": "held", "reason": "config_changed"}
        if row["outcome"] == "owner_fenced":
            # Fenced after dispatch: keep the observation as evidence only; the successor holds it.
            record_late_evidence(self.dsn, attempt_id, self.generation, self.incarnation, "late_result", observation)
            self.stop("fenced")
            return {**result, "outcome": "held", "reason": "owner_fenced_after_send"}
        if row["outcome"] in ("confirmed", "uncertain"):
            self._journal_advance(attempt_id, row["outcome"])
        return {**result, "outcome": row["outcome"], "reason": observation.get("kind")}


# T04 S3c: what the database may show for a journal entry, by the progress this owner knows committed.
# (state, permit) pairs the database may show for a journal entry, by the progress this owner knows
# committed (R5). Consume pending is only a possible result: the statement may or may not have run.
JOURNAL_ALLOWED = {
    "consume_pending": {("started", "unconsumed"), ("dispatched", "consumed"), ("uncertain", "consumed"),
                        ("uncertain", "revoked"), ("aborted_before_dispatch", "revoked")},
    "dispatched": {("dispatched", "consumed"), ("uncertain", "consumed"), ("confirmed", "consumed"),
                   ("not_sent", "consumed")},
    "uncertain": {("uncertain", "consumed")},
    "confirmed": {("confirmed", "consumed")},
    "not_sent": {("not_sent", "consumed")},
    "aborted": {("aborted_before_dispatch", "revoked")}}


_MARKER = re.compile(r"\[AlertaAck:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\]")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_KIND = re.compile(r"[a-z][a-z_]{0,63}")
_TARGET = re.compile(r"[1-9][0-9]{0,18}")


def observation_summary(status: Optional[int], alarm: Any, read_error: Optional[str]) -> dict:
    """T05b: the typed, minimised summary of one provider read (design r3 C2, r3a). Field states only:
    no comment text, no payload, no classification (the database classifies). Comment and operation
    are carried as SHA-256 digests; the marker as the action UUID it names."""
    def state(**kw):
        return dict(kw)

    s: dict = {"v": 1, "http_status": status if isinstance(status, int) and 100 <= status <= 599 else None,
               "read_error": read_error}
    a = alarm if isinstance(alarm, dict) and read_error is None else None
    if a is None:
        for k in ("acked", "comment", "operation", "operation_status", "children", "marker",
                  "response_target_kind", "response_target_id"):
            s[k] = state(state="absent")
        return s
    acked = a.get("acked", None) if "acked" in a else None
    s["acked"] = state(state="absent") if "acked" not in a else \
        state(state="true" if acked is True else "false" if acked is False else "invalid")
    c = a.get("comment")
    raw = None
    if isinstance(c, str):
        try:
            raw = c.encode("utf-8")
        except UnicodeEncodeError:          # not valid Unicode (e.g. a lone surrogate): invalid, never replaced,
            raw = None                      # hashed or kept as text
    if "comment" not in a or c is None:
        s["comment"], s["marker"] = state(state="absent"), state(state="absent")
    elif raw is None:                       # not a string, or not encodable
        s["comment"], s["marker"] = state(state="invalid"), state(state="absent")
    else:
        s["comment"] = state(state="string", sha256=hashlib.sha256(raw).hexdigest())
        if not c.startswith("[AlertaAck:"):
            s["marker"] = state(state="absent")
        else:
            m = _MARKER.match(c)
            s["marker"] = state(state="valid", action_id=m.group(1)) if m else state(state="malformed")
    op = a.get("acked_by_operation") if "acked_by_operation" in a else None
    if "acked_by_operation" not in a:
        s["operation"] = state(state="absent")
    elif op is None:
        s["operation"] = state(state="null")
    elif isinstance(op, str) and _HEX64.fullmatch(op):
        s["operation"] = state(state="valid", sha256=op)
    else:
        s["operation"] = state(state="malformed")
    st = a.get("operation_status")
    s["operation_status"] = state(state="absent") if "operation_status" not in a else \
        state(state="completed" if st == "completed" else "other")
    s["children"] = state(state="present" if "children" in a else "absent")
    k = a.get("kind")
    s["response_target_kind"] = state(state="absent") if "kind" not in a else \
        state(state="string", value=k) if isinstance(k, str) and _KIND.fullmatch(k) else state(state="invalid")
    t = a.get("target_id")
    s["response_target_id"] = state(state="absent") if "target_id" not in a else \
        state(state="string", value=t) if isinstance(t, str) and _TARGET.fullmatch(t) else state(state="invalid")
    return s


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def settlement_lookup(dsn: str, decision_id: str) -> str:
    """The same decision only: ``committed``, ``absent`` (not proof of rollback) or ``unknown``."""
    try:
        with _connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT r_outcome FROM voalack.settlement_status(%s)", (decision_id,))
            return "committed" if cur.fetchone() is not None else "absent"
    except psycopg2.Error:
        return "unknown"


def record_late_evidence(dsn: str, attempt_id: str, generation: int, incarnation: str, kind: str,
                         detail: Mapping[str, Any]) -> str:
    """Evidence that arrives after the original owner was fenced: append-only, no state change."""
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack.record_evidence(%s, %s, %s, %s, %s::jsonb)",
                    (attempt_id, generation, incarnation, kind, json.dumps(dict(detail))))
        return cur.fetchone()[0]
