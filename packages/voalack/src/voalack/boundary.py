"""The request transaction boundary for eligible ACKs (design amendments A1, A2, A3, A5).

Install with :func:`install` from an application factory, before the first request. For a
``PUT /alert/<id>/action`` with ``action=ack`` on an alert that has an active binding:

* ``before_request`` only recognises the candidate request syntax: any nonempty alert id, because
  Alerta also resolves an id prefix, an id in another letter case and an alert's
  ``last_receive_id`` (audit 2026-11-08, finding 2). Before authentication nothing queries the
  binding registry or takes a database lock (review finding B2, A2).
* the gate runs where the pinned Alerta 9.1.0 action view loads the alert
  (``Alert.find_by_id(alert_id, customers)``, ``alerta/views/alerts.py:159``): after the real
  permission decorator (``:147``) and with its customer filter, before ``process_action``
  (``:166``). It loads the alert as upstream does (not found: upstream ``404``); refuses
  non-human credentials (API key, Hawk, anonymous) with ``403`` for bound and unbound alerts
  alike, before any membership query; looks up the binding with bounded statements; for a
  bound alert refuses unreviewed response callbacks (R11: application, blueprint and
  request-local; reviewed ones are callable objects frozen at install, never matched by name)
  and foreign ``request_finished`` receivers (B1), defers Alerta's commits,
  locks the alert row with a bounded wait, re-checks the binding under ``FOR SHARE`` and
  reloads the complete alert under the lock with the same customer filter. An unbound alert,
  or one whose binding went away before the lock, continues upstream untouched. Right after
  the ``403`` check, a request whose id is not the loaded alert's own id is refused with ``400``,
  for bound and unbound alerts alike and before any membership query (audit finding 2).
* the route's view function is wrapped to record that it returned normally, and an
  application-scoped ``got_request_exception`` receiver marks the transaction failed when any
  later step raises (for example a response callback), so an error that an error handler turns
  into a 200 never counts as success;
* the terminal ``after_request`` callback (inserted first, so Flask runs it last) decides:
  only if the view returned normally, the response is 200, and the staged intent, its capture
  and the alert's final head history all match does it finalize the intent to that history and
  approve a commit; anything else rolls back;
* a session-interface wrapper records that Flask saved the session; if saving fails, the
  exception marks the request failed and the transaction rolls back;
* the single real commit is made when the application's ``finalize_request`` returns, i.e.
  after response processing, session saving and every ``request_finished`` receiver (in any
  order). Voalack's own receiver only records that the signal was sent. Because receiver order
  is not guaranteed, any other ``request_finished`` receiver for the application is an
  unsupported configuration and eligible ACKs roll back. Otherwise it re-checks the 200 status
  and the exact final history; an eligible request that was not
  committed never leaves with a success status other than the action view's own unchanged
  ``202`` (ForwardingLoop, A5), whatever a callback, receiver or error handler set; genuine
  error statuses are kept. After ``finalize_request`` Flask only sends the
  response and tears down the request, which cannot change the HTTP status;
* ``install`` refuses an application whose audit webhook would report ACKs (``AUDIT_URL`` with
  ``write`` in ``AUDIT_TRAIL``): it fires inside the view, before the commit; or whose local
  write audit log would record ACK notes and actor data (``AUDIT_LOG`` with ``write``) (A4); and
  one with
  an enabled plugin implementing action hooks that is not Voalack's own or listed in
  ``VOALACK_REVIEWED_ACTION_PLUGINS`` (A1).
* ``teardown_request`` rolls back if the request ended without reaching the boundary.

Requests for other alerts and other routes are untouched.
"""
from __future__ import annotations

import functools
import json
import logging
import uuid

import psycopg2

from types import MappingProxyType

from flask import (Response, current_app, g, got_request_exception, has_request_context, jsonify, request,
                   request_finished, session)
from flask.sessions import SessionInterface

from alerta_ack_core import utc_timestamp

from . import envelope as v2
from . import intent
from .txn import DeferredCommitConnection

LOG = logging.getLogger("voalack.boundary")
LOOKUP_LOCK_TIMEOUT = "1s"     # binding lookup (after authentication)
LOCK_TIMEOUT = "2s"            # alert row lock
STATEMENT_TIMEOUT = "15s"
PINNED_ALERTA = "9.1.0"        # the gate's placement is proven for this version only
# Native response callbacks are recognised only on the versions whose source was reviewed.
NATIVE_CALLBACK_PINS = {"flask-cors": "6.0.5", "Flask-Compress": "1.25"}
_original_find_by_id = None


def _begin():
    if request.method != "PUT" or request.endpoint != "api.action_alert":
        return None
    payload = request.get_json(silent=True)
    alert_id = (request.view_args or {}).get("alert_id")
    if not isinstance(payload, dict) or payload.get("action") != "ack" or not isinstance(alert_id, str) \
            or not alert_id:
        return None
    g.voalack_candidate = alert_id         # syntax only: no registry query, no lock (B2)
    return None


def _lookup_binding(cur, alert_id: str, lock: bool = False):
    """The only query of the protected binding registry; returns (binding_id, revision) or None."""
    if lock:   # row locks need UPDATE privilege; the owner function takes them (binding, generation)
        cur.execute("SELECT * FROM voalack.lock_binding(%s)", (alert_id,))
        row = cur.fetchone()
        return {c.name: v for c, v in zip(cur.description, row)} if row else None
    else:
        cur.execute("SELECT binding_id, binding_revision FROM voalack.bindings WHERE alert_id = %s AND active",
                    (alert_id,))
    row = cur.fetchone()
    return (row[0], row[1]) if row else None


def _gated_find_by_id(id, customers=None):
    """Replaces Alert.find_by_id; acts only on the action route's own load of the candidate."""
    if not has_request_context() or g.get("voalack_candidate") != id or g.get("voalack_gate_ran"):
        return _original_find_by_id(id, customers)
    g.voalack_gate_ran = True
    return _gate(id, customers)


_gated_find_by_id._voalack_gate = True


def _refuse(state, message: str, code: int):
    """Roll back whatever the gate started and refuse; nothing is staged.

    The refusal is recorded on the request itself, independent of any transaction state, so the
    final boundary keeps it an error whatever a handler or receiver sets (review finding R9).
    """
    from alerta.exceptions import ApiError
    g.voalack_refused = True
    if state is not None:
        state["failed"] = True
        state["rolled_back"] = True
        try:
            state["conn"].rollback()
        except Exception:
            pass
    return ApiError(message, code)


def _gate(alert_id: str, customers):
    from alerta.app import db
    alert = _original_find_by_id(alert_id, customers)     # upstream load, customer-filtered
    if alert is None:
        return None                                       # upstream 404; registry never consulted
    if intent.alert_class(alert.event, alert.resource) != intent.ONE_CLASS:
        # Coexistence 3a (r8 section 2): an alert outside the public Veeam ONE class is not
        # Voalack's. Upstream behaviour, untouched: no Voalack state, registry, lock or refusal.
        return alert
    login = g.get("login")
    if not g.get("user_id") or not isinstance(login, str) or not login:
        # Uniform for bound and unbound alerts of the public ONE class: membership is not
        # looked up (B2 as amended by coexistence 3a r8).
        raise _refuse(None, "ACK requires an authenticated user, not an API key", 403)
    if alert.id != alert_id:
        # Audit finding 2: Alerta resolved an alias (an id prefix, another letter case or the
        # last_receive_id). Only the alert's own id may acknowledge a ONE-class alert; membership is
        # not looked up, so bound and unbound alerts are refused alike.
        raise _refuse(None, "ACK requires the alert's full id", 400)
    conn = db.get_db()
    cur = conn.cursor()
    try:
        cur.execute(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute(f"SET LOCAL lock_timeout = '{LOOKUP_LOCK_TIMEOUT}'")
        cur.execute("SHOW transaction_isolation")
        isolation = cur.fetchone()[0]
        binding = _lookup_binding(cur, alert.id)
    except psycopg2.Error as exc:
        conn.rollback()
        LOG.error("capture registry unavailable (%s)", type(exc).__name__)
        raise _refuse(None, "ACK not processed: capture registry unavailable", 503)
    if binding is None:
        conn.rollback()                                   # unbound: upstream, untouched
        return alert
    wrapped = DeferredCommitConnection(conn)
    g.db = wrapped
    state = {"alert_id": alert.id, "conn": wrapped, "done": False, "view_returned": False, "failed": False,
             "commit_approved": False, "committed": False}
    g.voalack = state
    if isolation != "read committed":
        LOG.error("unsupported transaction isolation %r; capture refused", isolation)
        raise _refuse(state, "ACK not processed: unsupported database isolation", 503)
    unreviewed = _unreviewed_response_callbacks()
    if unreviewed:
        # R11: a response callback runs before the commit decision and could announce an ACK
        # that later rolls back; refuse before anything is staged.
        LOG.error("unreviewed response callbacks present (%s); ACK refused", ", ".join(unreviewed))
        raise _refuse(state, "ACK not processed: unreviewed response callbacks", 503)
    if _foreign_receivers():
        # B1: refused before anything is staged, so receivers only ever see this error.
        state["foreign_receivers"] = True
        LOG.error("unsupported request_finished receivers present; ACK refused")
        raise _refuse(state, "ACK not processed: unsupported request_finished receivers", 503)
    try:
        cur.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
        cur.execute("SELECT 1 FROM alerts WHERE id = %s FOR UPDATE", (alert.id,))
        cur.execute(f"SET LOCAL lock_timeout = '{LOOKUP_LOCK_TIMEOUT}'")
        binding = _lookup_binding(cur, alert.id, lock=True)
    except psycopg2.Error as exc:
        LOG.error("alert or binding busy (%s); ACK refused", type(exc).__name__)
        raise _refuse(state, "ACK not processed: alert busy, try again", 503)
    if binding is None:
        # The binding went away before the lock: continue upstream, untouched.
        conn.rollback()
        g.db = conn
        g.pop("voalack")
        return _original_find_by_id(alert_id, customers)
    fresh = _original_find_by_id(alert_id, customers)    # complete reload under the lock
    if fresh is None or fresh.id != alert.id:
        state["failed"] = True                            # out of scope now: upstream 404, rolled back
        return None
    if intent.alert_class(fresh.event, fresh.resource) != intent.ONE_CLASS:
        # The class changed before the lock: refuse and let the client retry; never switch lanes.
        raise _refuse(state, "ACK not processed: alert changed, try again", 503)
    if not binding.get("protections_intact"):
        # Coexistence 3a S2: a missing, disabled, re-pointed or extra public-table protection refuses before any
        # gate fact processing, signing or staging.
        LOG.error("public-table protections not intact; ACK refused")
        raise _refuse(state, "ACK not processed: protections not intact", 503)
    if not binding.get("lifetime_current"):
        # Coexistence 3a S2: a binding enrolled for another lifetime of this id (or a legacy one) never captures.
        LOG.error("binding lifetime is not the alert's open lifetime; ACK refused")
        raise _refuse(state, "ACK not processed: binding needs re-enrolment", 503)
    _freeze_gate_facts(state, cur, fresh, binding, customers)
    state["binding"] = (binding["binding_id"], binding["binding_revision"])
    state["customer"] = fresh.customer
    state["gate_passed"] = True
    return fresh


def _freeze_gate_facts(state, cur, alert, revision, customers) -> None:
    """Validate the locked, reloaded alert against its binding revision, the verified login, the
    policy grant and the signing configuration; then freeze the facts the envelope must carry
    (amendments 1-3). Any failure refuses the ACK before anything is staged."""
    signing = current_app.extensions.get("voalack_signing")
    if signing is None:
        raise _refuse(state, "ACK not processed: signing is not configured", 503)
    reason = intent.source_mismatch(alert, revision)
    if reason is not None:
        LOG.error("source does not match its binding revision (%s); ACK refused", reason)
        raise _refuse(state, "ACK not processed: the alert no longer matches its approved binding", 503)
    user_id, login = g.get("user_id"), g.get("login")
    auth_type = intent.verified_auth_type(str(user_id), login, signing.ctx)
    if auth_type is None:
        raise _refuse(state, "ACK requires a verified login (Basic or an allowed bearer token)", 403)
    try:
        cur.execute("SELECT voalack.lock_grant(%s, %s)", (str(user_id), alert.customer))
        policy_revision = cur.fetchone()[0]
    except psycopg2.Error as exc:
        LOG.error("authorization policy unavailable (%s); ACK refused", type(exc).__name__)
        raise _refuse(state, "ACK not processed: alert busy, try again", 503)
    if policy_revision is None:
        raise _refuse(state, "Not authorised to acknowledge alerts of this customer", 403)
    cur.execute("SELECT clock_timestamp()")
    issued = cur.fetchone()[0]
    frozen = {
        "alert_id": alert.id, "action_id": str(uuid.uuid4()), "request_id": str(uuid.uuid4()),
        "user_id": str(user_id), "login": login, "auth_type": auth_type, "customer": alert.customer,
        "binding_id": revision["binding_id"], "binding_revision": revision["binding_revision"],
        "policy_revision": policy_revision, "kid": signing.kid,
        "message_policy_revision": signing.message_policy_revision,
        "issued_at": utc_timestamp(issued),
        "capture_expires_at": utc_timestamp(issued + signing.capture_window),
        "execution_expires_at": utc_timestamp(issued + signing.execution_window),
        "issued": issued, "capture_deadline": issued + signing.capture_window,
        "execution_deadline_delta": signing.execution_window,
    }
    # Originals in request-private storage (review R22); g only gets a copy, compared later.
    priv = intent.private()
    priv["frozen"] = MappingProxyType(dict(frozen))
    priv["revision"] = MappingProxyType(dict(revision))
    priv["signing"] = signing
    priv["customers"] = list(customers) if customers else None     # psycopg2 adapts a list as an array
    state["frozen"] = dict(frozen)


def _label(func) -> str:
    return f"{getattr(func, '__module__', '?')}.{getattr(func, '__qualname__', type(func).__name__)}"


def _unreviewed_response_callbacks() -> list:
    """Every response callback this request will run before the commit decision (R11).

    Request-local (after_this_request), the request's blueprint chain and the application's
    callbacks. Each must be Voalack's own or a reviewed callable object frozen at install;
    Alerta's request logger only while it cannot emit its provisional INFO record.
    """
    from flask.globals import request_ctx
    app = current_app._get_current_object()
    frozen = app.extensions.get("voalack_reviewed_callbacks", ())
    funcs = list(getattr(request_ctx._get_current_object(), "_after_request_functions", ()))
    for scope in (*request.blueprints, None):
        funcs.extend(app.after_request_funcs.get(scope, ()))
    bad = []
    for func in funcs:
        if func is _finish or any(func is reviewed for reviewed in frozen):
            continue
        if func is app.extensions.get("voalack_request_logger") and not app.logger.isEnabledFor(logging.INFO):
            continue                      # its INFO record (with the provisional status) is not emitted
        bad.append(_label(func))
    return bad


def _native_response_callbacks(app) -> tuple:
    """Identify the pinned factory's own response callbacks by code and binding, not by name."""
    import types
    from importlib.metadata import version

    import alerta.app
    from alerta.utils.logging import Logger
    from alerta.utils.tracing import Tracing
    reviewed, logger, cors = [], None, []
    pinned = all(version(dist) == want for dist, want in NATIVE_CALLBACK_PINS.items())
    cors_code = compress_func = cors_globals = None
    if pinned:
        import flask_cors.extension
        from flask_compress.flask_compress import Compress
        from flask_cors.extension import make_after_request_function
        cors_globals = vars(flask_cors.extension)  # the real module's helpers, not a substitute
        inner = [c for c in make_after_request_function.__code__.co_consts
                 if isinstance(c, types.CodeType) and c.co_name == "cors_after_request"]
        cors_code = inner[0] if len(inner) == 1 else None
        compress_func = Compress.after_request
    for func in app.after_request_funcs.get(None, ()):
        if func is Tracing.set_request_id:
            reviewed.append(func)         # adds the X-Request-ID header only
        elif func is Logger.log_response:
            logger = func                 # conditional policy, see _unreviewed_response_callbacks
        elif (cors_code is not None and getattr(func, "__code__", None) is cors_code
              and getattr(func, "__globals__", None) is cors_globals):
            cors.append(func)             # the factory's own CORS closure: headers only
        elif (compress_func is not None and getattr(func, "__func__", None) is compress_func
              and getattr(func, "__self__", None) is alerta.app.compress
              and getattr(alerta.app.compress, "cache", None) is None):
            reviewed.append(func)         # Alerta's own Compress instance without a cache backend:
                                          # response encoding only (a cache would store the body)
    if len(cors) == 1:                    # cors.init_app registers exactly one; more is not native
        reviewed.extend(cors)
    return reviewed, logger


def _operator_reviewed_callbacks(app, selectors) -> list:
    """Resolve VOALACK_REVIEWED_RESPONSE_CALLBACKS ("module:qualname") to registered objects."""
    import importlib
    registered = [f for funcs in app.after_request_funcs.values() for f in funcs]
    resolved = []
    for selector in selectors:
        module_name, _, qualname = selector.partition(":")
        try:
            target = importlib.import_module(module_name)
            for part in qualname.split("."):
                target = getattr(target, part)
        except (ImportError, AttributeError, ValueError) as exc:
            raise RuntimeError(f"voalack: reviewed response callback {selector!r} not found") from exc
        matches = [f for f in registered if f is target
                   or (getattr(f, "__func__", None) is getattr(target, "__func__", object())
                       and getattr(f, "__self__", None) is getattr(target, "__self__", object()))]
        if len(matches) != 1:
            raise RuntimeError(f"voalack: reviewed response callback {selector!r} matches "
                               f"{len(matches)} registered callbacks; exactly one is required")
        resolved.append(matches[0])
    return resolved


def _freeze_response_callbacks(app) -> None:
    native, logger = _native_response_callbacks(app)
    operator = _operator_reviewed_callbacks(app, app.config.get("VOALACK_REVIEWED_RESPONSE_CALLBACKS") or [])
    app.extensions["voalack_reviewed_callbacks"] = tuple(native + operator)
    app.extensions["voalack_request_logger"] = logger


def _foreign_receivers() -> bool:
    return any(r is not _on_request_finished
               for r in request_finished.receivers_for(current_app._get_current_object()))


# Every column is aliased: Alerta's connection uses psycopg2's NamedTupleCursor, which
# rejects duplicate column names.
FINAL_CHECK = '''
SELECT c.history_user AS c_user, c.history_time AS c_time, c.history_text AS c_text,
       c.history_type AS c_type, c.history_status AS c_status,
       (a.history[1])."user" AS h_user, (a.history[1]).update_time AS h_time, (a.history[1]).text AS h_text,
       (a.history[1]).type AS h_type, (a.history[1]).status AS h_status, a.status AS alert_status,
       (SELECT count(*) FROM voalack.captures WHERE alert_id = a.id AND txid = txid_current()) AS n_captures,
       (SELECT count(*) FROM voalack.prepared_intents WHERE alert_id = a.id AND txid = txid_current()) AS n_intents,
       a.customer AS alert_customer, p.payload->>'binding_id' AS p_binding_id,
       p.payload->>'binding_revision' AS p_binding_revision,
       p.payload->>'action_id' AS p_action_id, p.payload->>'alert_id' AS p_alert_id,
       p.payload->>'actor' AS p_actor, p.actor_login AS p_actor_login,
       EXISTS (SELECT 1 FROM voalack.bindings b
                WHERE b.alert_id = a.id AND b.active AND b.binding_id = p.payload->>'binding_id'
                  AND b.binding_revision::text = p.payload->>'binding_revision') AS binding_active,
       p.generation AS p_generation, c.generation AS c_generation, p.request_id::text AS p_request_id,
       p.customer AS p_customer, p.binding_id AS p_binding_id_col, p.binding_revision AS p_binding_revision_col,
       p.envelope_canonical AS p_canonical, p.envelope_sha256 AS p_sha256, p.kid AS p_kid, p.mac AS p_mac,
       c.envelope_sha256 AS c_sha256
  FROM voalack.prepared_intents p
  JOIN voalack.captures c ON c.action_id = p.action_id AND c.txid = p.txid AND c.alert_id = p.alert_id
  JOIN public.alerts a ON a.id = p.alert_id
 WHERE p.action_id = %s AND p.alert_id = %s AND p.txid = txid_current()
'''


def _matches_final_history(state, require_finalized_note: bool = False) -> bool:
    """Fresh join of the staged action, its capture and the alert's current head history."""
    action_id = state.get("action_id")
    if not action_id:
        return False
    cur = state["conn"].cursor()
    cur.execute(FINAL_CHECK, (action_id, state["alert_id"]))
    rows = cur.fetchall()
    if len(rows) != 1:
        return False
    (c_user, c_time, c_text, c_type, c_status, h_user, h_time, h_text, h_type, h_status,
     alert_status, n_captures, n_intents, alert_customer, p_binding_id, p_binding_revision,
     p_action_id, p_alert_id, p_actor, p_actor_login, binding_active,
     p_generation, c_generation, p_request_id, p_customer, p_binding_id_col, p_binding_revision_col,
     p_canonical, p_sha256, p_kid, p_mac, c_sha256) = rows[0]
    priv = intent.private()
    frozen = priv.get("frozen")
    if frozen is None or state.get("frozen") != dict(frozen):
        return False                      # the public copy was changed (review R22)
    login = frozen["login"]               # the private original, not g (amendment 3)
    # Every identity the intent carries is the staged one (the payload is what will be delivered).
    if (p_action_id, p_alert_id, p_actor, p_actor_login) != (action_id, state["alert_id"], login, login):
        return False
    # The generation allocated once at staging, on both rows; the original request and binding.
    if (p_generation is None or p_generation != priv.get("generation") or c_generation != p_generation
            or state.get("generation") != p_generation):
        return False
    if (p_request_id, p_customer, p_binding_id_col, p_binding_revision_col) != (
            frozen["request_id"], frozen["customer"], frozen["binding_id"], frozen["binding_revision"]):
        return False
    # The gated source snapshot still holds (automated review of 5d80169): same customer scope,
    # and the intent carries the binding the gate locked, which is still active.
    if alert_customer != state.get("customer") or not binding_active:
        return False
    if (p_binding_id, p_binding_revision) != (state["binding"][0], str(state["binding"][1])):
        return False
    if (c_user, c_time, c_text, c_type, c_status) != (h_user, h_time, h_text, h_type, h_status):
        return False
    if h_user != login or h_type != "ack" or h_status != "ack" or alert_status != "ack":
        return False
    if n_captures != 1 or n_intents != 1:
        return False
    if require_finalized_note:
        cur.execute("SELECT payload->>'note' AS note FROM voalack.prepared_intents WHERE action_id = %s",
                    (action_id,))
        if cur.fetchone()[0] != (h_text or ""):
            return False
        if not _signed_envelope_holds(state, cur, h_text, p_canonical, p_sha256, p_kid, p_mac, c_sha256):
            return False
    state["final_history"] = (h_text, h_time)
    return True


def _source_holds(state, revision) -> bool:
    """The current complete alert, reloaded in this transaction, still matches the revision
    exactly as at the gate (review R20): the full MVP predicate and the snapshot digest."""
    alert = _original_find_by_id(state["alert_id"], intent.private().get("customers"))
    if alert is None or alert.id != state["alert_id"]:
        return False
    reason = intent.source_mismatch(alert, revision)
    if reason is not None:
        LOG.error("source changed after the gate (%s); not committed", reason)
        return False
    return True


def _signed_envelope_holds(state, cur, note, canonical, sha256, kid, mac, capture_sha256) -> bool:
    """At the commit point: the stored bytes verify, are linked to the capture, and equal the
    envelope rebuilt from the frozen gate facts, the current revision and the final note; the
    policy grant still holds; and the capture deadline has not passed (database clock)."""
    import hashlib
    priv = intent.private()
    signing, frozen = priv.get("signing"), priv.get("frozen")
    if signing is None or frozen is None or canonical is None or kid != frozen["kid"]:
        return False
    canonical = bytes(canonical)
    if hashlib.sha256(canonical).hexdigest() != sha256 or capture_sha256 != sha256:
        return False
    try:
        verified = v2.verify(canonical, mac, signing.ctx, signing.keys)
    except (v2.EnvelopeError, v2.KeyUnavailable, v2.ProofError):
        return False
    # The revision's own columns plus the pointer's alert_id and active flag (both tables carry alert_lifetime_id).
    cur.execute("SELECT r.*, b.alert_id, b.active FROM voalack.binding_revisions r JOIN voalack.bindings b "
                "USING (binding_id, binding_revision) WHERE b.alert_id = %s AND b.active", (state["alert_id"],))
    row = cur.fetchone()
    if row is None:
        return False
    revision = {c.name: v for c, v in zip(cur.description, row)}
    if not _source_holds(state, revision):
        return False
    try:
        expected = intent.build(signing, frozen, revision, priv["generation"], note)
    except v2.EnvelopeError:
        return False
    if verified != expected or v2.canonical_json(expected, 16384) != canonical:
        return False
    cur.execute("SELECT voalack.lock_grant(%s, %s)", (frozen["user_id"], frozen["customer"]))
    if cur.fetchone()[0] != frozen["policy_revision"]:
        return False
    return _within_capture_window(cur, frozen["issued_at"], frozen["capture_expires_at"])


def _within_capture_window(cur, issued_at: str, capture_expires_at: str, at: str = None) -> bool:
    """issued_at <= now < capture_expires_at on the live database clock (exclusive expiry).

    The bounds are the exact signed UTC strings, cast in SQL: Alerta registers a global psycopg2
    datetime adapter that keeps only milliseconds (T04 S1 finding). ``at`` replaces the clock with
    an exact instant for boundary tests only.
    """
    cur.execute("SELECT %s::timestamptz <= COALESCE(%s::timestamptz, clock_timestamp()) "
                "AND COALESCE(%s::timestamptz, clock_timestamp()) < %s::timestamptz",
                (issued_at, at, at, capture_expires_at))
    return cur.fetchone()[0] is True


def _finalize(state) -> bool:
    """Join the staged action, its capture and the final head history; then bind the intent to it.

    Requires exactly one intent and one capture in this transaction, the capture's history entry
    to equal the alert's current head entry (nothing rewrote it later), and that entry to be this
    user's ACK. The intent's note becomes the final ACK text (review finding R1).
    """
    if not _matches_final_history(state):
        return False
    action_id = state["action_id"]
    h_text, h_time = state["final_history"]
    priv = intent.private()
    signing = priv.get("signing")
    if not _source_holds(state, priv["revision"]):
        return False
    try:
        envelope = intent.build(signing, priv["frozen"], priv["revision"], priv["generation"], h_text)
        signed = v2.sign(envelope, signing.ctx, signing.keys)
    except (v2.EnvelopeError, v2.KeyUnavailable, v2.ProofError, AttributeError) as exc:
        LOG.error("intent could not be signed (%s)", type(exc).__name__)
        return False
    final = {"note": h_text or "", "history_time": h_time.isoformat()}
    cur = state["conn"].cursor()
    # Approval (owner function): stores the canonical bytes, digest, kid and MAC on this
    # transaction's intent and links the digest to its capture.
    cur.execute("SELECT voalack.approve_intent(%s, %s, %s, %s, %s, %s::jsonb)",
                (action_id, psycopg2.Binary(signed.canonical), signed.sha256, signed.kid, signed.mac,
                 json.dumps(final, sort_keys=True)))
    return True


REPRESENTATION_HEADERS = ("Content-Encoding", "Content-Length", "Content-Range", "Content-MD5", "ETag",
                          "Last-Modified", "Transfer-Encoding")


def _as_error(response: Response, message: str, code: int = 500, **fields) -> Response:
    """Turn ``response`` itself into a 500 error (in place).

    A reviewed callback may already have transformed the provisional body (for example
    compressed it), so representation headers describing that body are removed with it.
    """
    error = _error(message, code, **fields)
    for header in REPRESENTATION_HEADERS:
        response.headers.pop(header, None)
    response.status_code = code
    response.set_data(error.get_data())
    response.mimetype = error.mimetype
    return response


def _error(message: str, code: int = 500, **fields) -> Response:
    response = jsonify(status="error", message=message, code=code, **fields)
    response.status_code = code
    return response


def _finish(response: Response) -> Response:
    state = g.get("voalack")
    if not state:
        return response
    if state["done"]:
        # A response processed again after a failure (for example an error handler's response):
        # a rolled-back eligible ACK must never be reported as success (review finding R6).
        if state.get("rolled_back") and not state["committed"] and response.status_code < 400:
            # Rewrite in place: if processing raises again, Flask keeps this same object.
            return _as_error(response, "ACK not saved: request failed")
        return response
    state["done"] = True
    conn = state["conn"]
    try:
        if state["view_returned"] and not state["failed"] and response.status_code == 200 and _finalize(state):
            state["commit_approved"] = True              # committed when finalize_request returns
            state["needs_session_save"] = not current_app.session_interface.is_null_session(session)
            return response
        conn.rollback()
        if response.status_code == 200:
            LOG.error("capture postcondition failed; local ACK rolled back")
            state["rolled_back"] = True
            response = _error("ACK not saved: capture could not be recorded")
        state["decided_status"] = response.status_code
        return response
    except Exception as exc:  # commit or postcondition query failed: nothing may be reported as saved
        LOG.error("capture boundary failed (%s); rolled back", type(exc).__name__)
        try:
            conn.rollback()
        except Exception:
            pass
        state["rolled_back"] = True
        response = _error("ACK not saved: transaction failed")
        state["decided_status"] = response.status_code
        return response


def _commit(state, response: Response) -> Response:
    """The single real commit, at the last point before the response leaves the application.

    Re-checks what the approval relied on (review finding R5): the response must still be 200
    and the staged intent, its capture, the finalized note and the alert's head history must
    still match. Otherwise, or if the commit fails, roll back and turn the response into a 500.
    """
    approved = state.get("commit_approved") and not state["failed"]
    state["commit_approved"] = False
    message = "ACK not saved: transaction failed"
    try:
        if approved and response.status_code == 200 and _matches_final_history(state, require_finalized_note=True):
            try:
                state["conn"].commit_now()
            except psycopg2.Error as exc:
                if exc.pgcode is None:
                    # No server verdict (connection lost): the COMMIT may have completed.
                    return _commit_outcome_unknown(state, response, exc)
                raise
            state["committed"] = True
            return response
        message = "ACK not saved: response or history changed before commit"
        LOG.error("capture approval no longer holds at commit; rolled back")
    except Exception as exc:
        LOG.error("capture commit failed (%s); rolled back", type(exc).__name__)
    try:
        state["conn"].rollback()
    except Exception:
        pass
    state["rolled_back"] = True
    return _as_error(response, message)


def _commit_outcome_unknown(state, response: Response, exc) -> Response:
    """Reconcile an interrupted COMMIT on a fresh connection (automated review of 5d80169).

    The capture row commits together with the ACK, so finding it by action ID proves the ACK was
    saved. Not finding it does not prove a rollback (the server may still be finishing), so that
    and an unreachable database are reported as an unknown outcome, never as saved or not saved.
    """
    from alerta.app import db
    LOG.error("capture COMMIT interrupted (%s); reconciling", type(exc).__name__)
    found, fresh = False, None
    try:
        fresh = psycopg2.connect(dsn=db.uri, dbname=db.dbname, connect_timeout=5)
        with fresh, fresh.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '5s'")
            cur.execute("SELECT 1 FROM voalack.captures WHERE action_id = %s", (state["action_id"],))
            found = cur.fetchone() is not None
    except psycopg2.Error:
        found = False
    finally:
        if fresh is not None:
            fresh.close()
    if found:
        state["committed"] = True
        return response
    try:
        state["conn"].rollback()          # release locks if the connection still exists
    except Exception:
        pass
    state["rolled_back"] = True           # internal: not committed by this request; not a claim of rollback
    return _as_error(response, "ACK outcome unknown: check the alert before retrying", 503,
                     outcome="unknown", action_id=state["action_id"])


class CommitAfterSessionSave(SessionInterface):
    """Delegates to the application's session interface and records a successful save.

    The commit itself waits for request_finished, which Flask sends after the session is saved.
    """

    def __init__(self, inner: SessionInterface):
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def open_session(self, app, request):
        return self.inner.open_session(app, request)

    def make_null_session(self, app):
        return self.inner.make_null_session(app)

    def is_null_session(self, obj):
        return self.inner.is_null_session(obj)

    def save_session(self, app, session, response):
        self.inner.save_session(app, session, response)
        state = g.get("voalack")
        if state:
            state["session_saved"] = True


def _on_request_finished(sender, response=None, **extra):
    """Records that Flask sent request_finished for this request (receiver order is arbitrary)."""
    state = g.get("voalack")
    if state:
        state["request_finished_sent"] = True


def _complete(response: Response) -> Response:
    """Runs when finalize_request returns: after every request_finished receiver (review R7)."""
    state = g.get("voalack")
    if not state:
        if g.get("voalack_refused") and response.status_code < 400:
            return _as_error(response, "ACK not processed: request refused")
        return response
    if state["committed"]:
        return response
    if state.get("commit_approved"):
        if not state.get("request_finished_sent"):
            state["failed"] = True
        if state.get("foreign_receivers") or _foreign_receivers():
            LOG.error("unsupported request_finished receivers present; capture not committed")
            state["failed"] = True
        if state.get("needs_session_save") and not state.get("session_saved"):
            state["failed"] = True
        return _commit(state, response)
    if response.status_code < 400 and not _allowed_uncommitted_success(state, response):
        # Not committed: no callback, receiver or handler may turn this into success (A5).
        return _as_error(response, "ACK not saved: request failed")
    return response


def _allowed_uncommitted_success(state, response: Response) -> bool:
    """The one success status an uncommitted eligible ACK may keep (review finding R8).

    Alerta's action view itself returns 202 when it catches ForwardingLoop; A5 rolls that back
    and keeps the 202. Only that genuine view result is allowed, unchanged through response
    processing: not a 202 set by a callback, receiver or error handler, and not after a failure
    rollback (automated review of dfef40d).
    """
    return (response.status_code == 202 and state.get("decided_status") == 202
            and state.get("view_returned") and state.get("view_status") == 202
            and not state.get("rolled_back"))


def _wrap_finalize_request(app) -> None:
    original = app.finalize_request

    def finalize_request(rv, from_error_handler=False):
        return _complete(original(rv, from_error_handler=from_error_handler))

    app.finalize_request = finalize_request


def _check_audit_webhook(config) -> None:
    """A4: Alerta emits write audit events (alert-actioned) inside the view, before the commit.

    The webhook reports ACKs that may still roll back. The local log formatter writes the request
    data, the ACK note and the user's customers and scopes; until a reviewed allowlisted formatter
    exists, that configuration stays ineligible too (DESIGN_AMENDMENTS A4).
    """
    if "write" not in (config.get("AUDIT_TRAIL") or []):
        return
    if config.get("AUDIT_URL"):
        raise RuntimeError("voalack: the write audit webhook (AUDIT_URL with 'write' in AUDIT_TRAIL) "
                           "reports ACKs before they commit; disable it for this application (A4)")
    if config.get("AUDIT_LOG"):
        raise RuntimeError("voalack: write audit logging (AUDIT_LOG with 'write' in AUDIT_TRAIL) writes ACK "
                           "notes and actor data to the log; disable it for this application (A4)")


def _abort(exc):
    state = g.get("voalack")
    if state and (not state["done"] or (state["commit_approved"] and not state["committed"])):
        state["done"] = True
        state["commit_approved"] = False
        try:
            state["conn"].rollback()
        except Exception:
            pass


def _record_view_return(view):
    """Wrap the action route so normal completion is recorded (review finding R2)."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        result = view(*args, **kwargs)
        state = g.get("voalack")
        if state:
            state["view_returned"] = True
            state["view_status"] = _returned_status(result)
        return result
    return wrapper


def _returned_status(result):
    """The status a view return value carries (Flask's (body, status) form or a Response)."""
    if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[1], int):
        return result[1]
    return getattr(result, "status_code", 200)


def _on_exception(sender, exception=None, **extra):
    """Any unhandled exception in this request, including response processing and session
    saving, is a failure (review finding R4); the error response can never commit."""
    state = g.get("voalack")
    if state and not state.get("committed"):
        state["failed"] = True
        state["commit_approved"] = False
        state["rolled_back"] = True
        try:
            state["conn"].rollback()
        except Exception:
            pass


def _check_alerta_version() -> None:
    from alerta.version import __version__
    if __version__ != PINNED_ALERTA:
        raise RuntimeError(f"voalack: the capture gate is proven for Alerta {PINNED_ALERTA}, not {__version__}")


def _install_gate() -> None:
    global _original_find_by_id
    from alerta.models.alert import Alert
    if getattr(Alert.find_by_id, "_voalack_gate", False):
        return                                            # already installed in this process
    _original_find_by_id = Alert.find_by_id
    Alert.find_by_id = staticmethod(_gated_find_by_id)


ACTION_HOOKS = ("status_change", "take_action", "post_action")


def _check_action_plugins(config, loaded) -> None:
    """A1: action hooks run inside the ACK transaction, before the commit decision.

    Only Voalack's own plugin (the exact class, not a subclass) and plugins the operator lists in
    VOALACK_REVIEWED_ACTION_PLUGINS (reviewed: local, transactional, no external effects) may
    implement status_change, take_action or post_action.
    """
    from alerta.plugins import PluginBase

    from .plugin import VoalackCapture
    def own_capture(plugin):
        # Exact type only (R10), and no hook replaced on the instance (automated review of bd35994).
        return type(plugin) is VoalackCapture and not any(h in vars(plugin) for h in ACTION_HOOKS)

    if not any(own_capture(p) for p in loaded.values()):
        raise RuntimeError("voalack: the 'voalack' plugin must be enabled in PLUGINS")
    reviewed = set(config.get("VOALACK_REVIEWED_ACTION_PLUGINS") or [])
    for name, plugin in loaded.items():
        if own_capture(plugin) or name in reviewed:
            continue
        # The hook Alerta will call is the one resolved on the instance, which an instance
        # attribute can replace while the class still inherits PluginBase's.
        hooks = [h for h in ACTION_HOOKS
                 if getattr(getattr(plugin, h, None), "__func__", None) is not getattr(PluginBase, h)]
        if hooks:
            raise RuntimeError(f"voalack: plugin {name!r} implements {', '.join(hooks)}, which run inside the "
                               "ACK transaction; list it in VOALACK_REVIEWED_ACTION_PLUGINS only if those hooks "
                               "are local and transactional (A1)")


IDENTITY_CHECK = """
SELECT session_user = current_user AS same_user,
       r.rolsuper OR r.rolcreaterole OR r.rolbypassrls AS privileged,
       EXISTS (SELECT 1 FROM pg_roles a WHERE a.rolname = 'voalack_admin'
                 AND (pg_has_role(current_user, a.oid, 'MEMBER')
                      OR EXISTS (SELECT 1 FROM pg_auth_members m
                                  WHERE m.roleid = a.oid AND m.admin_option
                                    AND pg_has_role(current_user, m.member, 'MEMBER')))) AS admin_path,
       (SELECT d.datdba = r.oid FROM pg_database d WHERE d.datname = current_database()) AS db_owner,
       EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = 'voalack'
                 AND (n.nspowner = r.oid OR has_schema_privilege(r.oid, n.oid, 'CREATE'))) AS schema_power,
       EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'voalack'
                  AND (c.relowner = r.oid
                       OR (c.relkind = 'r' AND has_table_privilege(r.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')))
              ) AS table_power,
       EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'voalack' AND p.proowner = r.oid) AS function_owner
  FROM pg_roles r WHERE r.rolname = current_user
"""


def _check_database_identity(config) -> None:
    """The runtime role must be a plain login with no path to Voalack's protected objects: no
    superuser/CREATEROLE/BYPASSRLS, no membership or ADMIN path to voalack_admin, not the
    database owner, and no ownership of, CREATE on, or write privilege on schema voalack."""
    dsn = config.get("DATABASE_URL")
    if not isinstance(dsn, str) or not dsn.startswith(("postgres://", "postgresql://")):
        raise RuntimeError("voalack: requires Alerta's PostgreSQL backend")
    try:
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(IDENTITY_CHECK)
            same_user, *powers = cur.fetchone()
        conn.close()
    except psycopg2.Error as exc:
        raise RuntimeError(f"voalack: cannot verify the database role ({type(exc).__name__})") from None
    if not same_user or any(powers):
        raise RuntimeError("voalack: the runtime database role must not be a superuser or database owner, nor "
                           "own, administer or write Voalack's protected objects")


def _enable_voalack_loggers() -> None:
    """Alerta's startup logging.config.dictConfig disables every logger created before it
    (disable_existing_loggers), which silenced Voalack's refusal diagnostics (M3 finding).
    install() runs after Alerta's factory, so re-enable Voalack's own loggers here."""
    for name, logger in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger) and (name == "voalack" or name.startswith("voalack.")):
            logger.disabled = False


def install(app) -> None:
    _enable_voalack_loggers()
    _check_alerta_version()
    _check_audit_webhook(app.config)
    _check_database_identity(app.config)
    intent.install_auth_recorders()
    app.extensions["voalack_signing"] = intent.load_signing(app.config)
    from alerta.app import plugins
    _check_action_plugins(app.config, plugins.plugins)
    _install_gate()
    _wrap_finalize_request(app)
    app.session_interface = CommitAfterSessionSave(app.session_interface)
    got_request_exception.connect(_on_exception, app, weak=False)
    request_finished.connect(_on_request_finished, app, weak=False)
    app.view_functions["api.action_alert"] = _record_view_return(app.view_functions["api.action_alert"])
    app.before_request(_begin)
    # Flask runs app-level after_request callbacks in reverse order; first in the list = last run.
    app.after_request_funcs.setdefault(None, []).insert(0, _finish)
    app.teardown_request(_abort)
    _freeze_response_callbacks(app)


def create_app(config_override=None, environment=None):
    """WSGI factory: Alerta's application with the Voalack transaction boundary installed."""
    from alerta.app import create_app as alerta_create_app
    app = alerta_create_app(config_override, environment)
    install(app)
    return app
