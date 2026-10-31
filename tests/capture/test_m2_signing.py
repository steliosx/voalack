"""M2: signed intent v2 inside the capture transaction, under the restricted database role."""
import dataclasses
import json
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta

import psycopg2
import pytest
from flask import g, request

from conftest import (APP_DSN, DSN, OPERATOR, ack, basic, bind, captures, intents, new_alert, sql, status,
                      user_id)
from test_c3_transaction import _Hook, _raise
from voalack import envelope as v2


def _intent(alert_id):
    rows = sql("SELECT envelope_canonical, envelope_sha256, kid, mac, generation, request_id::text, action_id::text "
               "FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))
    return rows[0] if rows else None


def _capture_sha(alert_id):
    return sql("SELECT envelope_sha256, generation FROM voalack.captures WHERE alert_id = %s", (alert_id,))[0]


def _refused(response, alert_id, code):
    assert response.status_code == code, response.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


@contextmanager
def _signing(app, **changes):
    original = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = dataclasses.replace(original, **changes) if changes else None
    try:
        yield
    finally:
        app.extensions["voalack_signing"] = original


@contextmanager
def _before_request(app, func):
    app.before_request_funcs.setdefault(None, []).append(func)
    try:
        yield
    finally:
        app.before_request_funcs[None].remove(func)


# --- positive -----------------------------------------------------------------------------

def test_ack_stores_a_verifiable_complete_envelope(client, app):
    alert_id = new_alert(client)
    r = ack(client, alert_id, text="line one\nline two")
    assert r.status_code == 200, r.get_data(as_text=True)
    canonical, sha, kid, mac, generation, request_id, action_id = _intent(alert_id)
    signing = app.extensions["voalack_signing"]
    env = v2.verify(bytes(canonical), mac, signing.ctx, signing.keys)
    assert (kid, generation) == ("lab-k1", 1) and _capture_sha(alert_id) == (sha, 1)
    assert env["alert_id"] == alert_id and env["action_id"] == action_id and env["request_id"] == request_id
    assert env["customer"] == "lab-customer" and env["binding_id"] == f"lab-{alert_id}"
    assert env["actor"] == {"user_id": user_id(OPERATOR[0]), "login": OPERATOR[0], "auth_type": "basic",
                            "authorization_policy_revision": 1, "authorized_customer": "lab-customer"}
    assert env["source"]["target_kind"] == "triggered_alarm" and env["source"]["target_id"] == "4711"
    assert env["message"].endswith("note=line one line two")
    assert status(alert_id)[0] == "ack"


def test_bearer_token_from_basic_login_is_labelled(client, app):
    alert_id = new_alert(client)
    token = client.post("/auth/login", json={"username": OPERATOR[0], "password": OPERATOR[1]}).get_json()["token"]
    r = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"},
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.get_data(as_text=True)
    signing = app.extensions["voalack_signing"]
    env = v2.verify(bytes(_intent(alert_id)[0]), _intent(alert_id)[3], signing.ctx, signing.keys)
    assert env["actor"]["auth_type"] == "bearer:basic"


# --- authentication evidence --------------------------------------------------------------

def test_bearer_provider_not_allowed_is_refused(client, app):
    alert_id = new_alert(client)
    token = client.post("/auth/login", json={"username": OPERATOR[0], "password": OPERATOR[1]}).get_json()["token"]
    signing = app.extensions["voalack_signing"]
    with _signing(app, ctx=v2.Context(deployment_id=signing.ctx.deployment_id)):
        r = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"},
                       headers={"Authorization": f"Bearer {token}"})
    _refused(r, alert_id, 403)


def test_auth_proxy_is_refused_even_with_basic_credentials(client, app):
    alert_id = new_alert(client)
    app.config["AUTH_PROXY"] = True
    try:
        r = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"},
                       headers={**basic(OPERATOR), "X-Proxy-User": OPERATOR[0], "X-Proxy-Roles": "user"})
    finally:
        app.config["AUTH_PROXY"] = False
    _refused(r, alert_id, 403)


def test_verification_calls_outside_the_permission_check_do_not_count(client, app):
    alert_id = new_alert(client)
    token = client.post("/auth/login", json={"username": OPERATOR[0], "password": OPERATOR[1]}).get_json()["token"]

    def helper_calls():
        if request.endpoint == "api.action_alert":
            from alerta.models.token import Jwt
            from alerta.models.user import User
            User.check_credentials(*OPERATOR)
            Jwt.parse(token)
            Jwt.parse(token, verify=False)
    with _before_request(app, helper_calls):
        r = ack(client, alert_id)
    assert r.status_code == 200, r.get_data(as_text=True)    # only the decorator's call was recorded


def test_evidence_planted_in_g_is_ignored(client, app):
    # Amended (review R21): evidence is request-private; g is never read, so a planted record
    # neither adds a duplicate (was: 403) nor qualifies anything. The real Basic call still counts.
    alert_id = new_alert(client)

    def forge():
        if request.endpoint == "api.action_alert":
            g.voalack_auth_records = [("basic", user_id(OPERATOR[0]), OPERATOR[0])]
    with _before_request(app, forge):
        r = ack(client, alert_id)
    assert r.status_code == 200, r.get_data(as_text=True)


def test_replaced_verification_helper_is_refused(client):
    from alerta.models.user import User
    alert_id = new_alert(client)
    installed = User.__dict__["check_credentials"]
    User.check_credentials = staticmethod(installed.__func__)        # same behaviour, not the wrapper
    try:
        r = ack(client, alert_id)
    finally:
        User.check_credentials = installed
    _refused(r, alert_id, 403)


def test_replaced_password_check_after_install_is_refused(client):
    # Review R21: the helpers the Basic wrapper depends on must still be the qualified originals.
    from alerta.models.user import User
    alert_id = new_alert(client)
    original = User.__dict__["verify_password"]
    User.verify_password = lambda self, password: True
    try:
        r = ack(client, alert_id)
    finally:
        User.verify_password = original
    _refused(r, alert_id, 403)


def test_install_refuses_an_unqualified_verifier():
    from alerta.models.user import User
    from voalack import intent
    assert all(intent._is_pinned(f, *k) for k, f in intent._qualified.items())    # the qualified originals
    wrapped = User.__dict__["check_credentials"].__func__                  # the installed wrapper
    assert not intent._is_pinned(wrapped, "alerta.models.user", "User.check_credentials")
    assert not intent._is_pinned(lambda u, p: None, "alerta.models.user", "User.check_credentials")


def test_evidence_does_not_carry_across_requests(client, app):
    first, second = new_alert(client), new_alert(client)
    assert ack(client, first).status_code == 200
    app.config["AUTH_PROXY"] = True
    try:
        r = client.put(f"/alert/{second}/action", json={"action": "ack", "text": "x"},
                       headers={"X-Proxy-User": OPERATOR[0], "X-Proxy-Roles": "user"})
    finally:
        app.config["AUTH_PROXY"] = False
    _refused(r, second, 403)


def test_source_changed_at_session_save_rolls_back(client, app):
    alert_id = new_alert(client)
    wrapper = app.session_interface
    original = wrapper.inner

    class Rewrite:
        def __getattr__(self, name):
            return getattr(original, name)

        def save_session(self, app_, session, response):
            g.db.cursor().execute("UPDATE public.alerts SET value = 'Info' WHERE id = %s", (alert_id,))
            original.save_session(app_, session, response)
    wrapper.inner = Rewrite()
    try:
        r = ack(client, alert_id)
    finally:
        wrapper.inner = original
    _refused(r, alert_id, 500)


def test_login_changed_after_the_gate_rolls_back(client, faults):
    alert_id = new_alert(client)

    def relabel(alert, action, text):
        g.login = "someone-else@example.test"
    faults("relabel", _Hook("relabel", take_action=relabel))
    _refused(ack(client, alert_id), alert_id, 500)


# --- trusted material and source --------------------------------------------------------

def test_missing_signing_configuration_is_refused(client, app):
    alert_id = new_alert(client)
    with _signing(app):
        r = ack(client, alert_id)
    _refused(r, alert_id, 503)


def test_customer_without_policy_grant_is_refused(client):
    alert_id = new_alert(client, customer="lab-no-grant")
    _refused(ack(client, alert_id), alert_id, 403)


@pytest.mark.parametrize("change", [
    "UPDATE alerts SET attributes = attributes || '{\"captureId\": \"other\"}' WHERE id = %s",
    "UPDATE alerts SET attributes = attributes || '{\"veeamAlarmCombinationId\": \"other\"}' WHERE id = %s",
    "UPDATE alerts SET value = 'Info' WHERE id = %s",
    "UPDATE alerts SET severity = 'minor' WHERE id = %s",
    "UPDATE alerts SET origin = 'other-origin' WHERE id = %s",
    "UPDATE alerts SET environment = 'Production' WHERE id = %s",
])
def test_source_differing_from_its_revision_is_refused(client, change):
    alert_id = new_alert(client)
    sql(change, (alert_id,), fetch=False)
    _refused(ack(client, alert_id), alert_id, 503)


def test_generation_is_allocated_once_and_rolls_back(client, faults):
    alert_id = new_alert(client)
    binding = f"lab-{alert_id}"
    faults("fail", _Hook("fail", post_action=_raise(RuntimeError("after staging"))))
    assert ack(client, alert_id).status_code == 500
    faults("fail", _Hook("fail"))                                # replace with a no-op hook

    def generation():                                            # no row: created and rolled back
        rows = sql("SELECT generation FROM voalack.binding_generations WHERE binding_id = %s", (binding,))
        return rows[0][0] if rows else 0
    assert generation() == 0
    assert ack(client, alert_id).status_code == 200
    assert generation() == 1
    assert _intent(alert_id)[4] == 1


def test_capture_deadline_uses_the_live_database_clock(client, app, faults):
    alert_id = new_alert(client)
    faults("slow", _Hook("slow", post_action=lambda alert, action, text: time.sleep(1.5)))
    with _signing(app, capture_window=timedelta(seconds=1)):
        r = ack(client, alert_id)
    _refused(r, alert_id, 500)


# --- tampering and privileges --------------------------------------------------------------

@contextmanager
def _lab_grant(statement):
    """Lab-only: temporarily give the runtime role a write it never has, to reach a later check."""
    sql(f"GRANT {statement} TO voalack_app", fetch=False)
    try:
        yield
    finally:
        sql(f"REVOKE {statement} FROM voalack_app", fetch=False)


@pytest.mark.parametrize("statement", [
    "UPDATE voalack.prepared_intents SET mac = repeat('0', 64) WHERE action_id = %s",
    "UPDATE voalack.prepared_intents SET kid = 'lab-k2' WHERE action_id = %s",
    "UPDATE voalack.prepared_intents SET envelope_canonical = envelope_canonical || 'x'::bytea WHERE action_id = %s",
    "UPDATE voalack.captures SET envelope_sha256 = repeat('0', 64) WHERE action_id = %s",
    "UPDATE voalack.prepared_intents SET generation = generation + 1 WHERE action_id = %s",
])
def test_approval_tampered_before_commit_rolls_back(client, app, statement):
    alert_id = new_alert(client)
    wrapper = app.session_interface
    original = wrapper.inner

    class Tamper:
        def __getattr__(self, name):
            return getattr(original, name)

        def save_session(self, app_, session, response):
            g.db.cursor().execute(statement, (g.voalack["action_id"],))
            original.save_session(app_, session, response)
    wrapper.inner = Tamper()
    try:
        with _lab_grant("UPDATE ON voalack.prepared_intents, voalack.captures"):
            r = ack(client, alert_id)
    finally:
        wrapper.inner = original
    _refused(r, alert_id, 500)


@pytest.mark.parametrize("field,value", [("actor", "someone-else"), ("action_id", "other-action"),
                                         ("alert_id", "other-alert"), ("binding_id", "other-binding"),
                                         ("binding_revision", 2)])
def test_payload_identity_check_is_reachable_with_a_lab_grant(client, faults, field, value):
    alert_id = new_alert(client)

    def rewrite(alert, action, text):
        g.db.cursor().execute("UPDATE voalack.prepared_intents SET payload = payload || %s::jsonb WHERE action_id = %s",
                              (json.dumps({field: value}), g.voalack["action_id"]))
    faults("rewrite", _Hook("rewrite", post_action=rewrite))
    with _lab_grant("UPDATE (payload) ON voalack.prepared_intents"):
        r = ack(client, alert_id)
    _refused(r, alert_id, 500)


@pytest.mark.parametrize("statement", [
    "INSERT INTO voalack.captures (action_id, alert_id, txid, history_user, history_time) "
    "VALUES (gen_random_uuid(), 'x', 1, 'u', now())",
    "INSERT INTO voalack.prepared_intents (action_id, alert_id, txid, actor_login, payload) "
    "VALUES (gen_random_uuid(), 'x', 1, 'u', '{}')",
    "UPDATE voalack.bindings SET active = false",
    "INSERT INTO voalack.binding_revisions (binding_id) VALUES ('x')",
    "UPDATE voalack.authorization_policy_active SET policy_revision = 2",
    "INSERT INTO voalack.authorization_policy VALUES (9, 'u', 'c')",
    "UPDATE voalack.binding_generations SET generation = 0",
    "DELETE FROM voalack.captures",
    "SELECT voalack.capture_ack()",
    "SELECT voalack.refuse_change()",
])
def test_runtime_role_is_denied_direct_writes(app, statement):
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(statement)


def test_owner_functions_refuse_misuse(client, app):
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.RaiseException, match="no unapproved intent"):
            cur.execute("SELECT voalack.approve_intent(%s, %s, encode(sha256(%s), 'hex'), 'lab-k1', repeat('0', 64), '{}')",
                        (str(uuid.uuid4()), b"x", b"x"))
    unbound = new_alert(client, bound=False)
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.RaiseException, match="binding is not active"):
            cur.execute("SELECT voalack.stage_intent(%s, %s, %s, 'u', '{}', 'c', 'b', 1, now(), now(), now())",
                        (str(uuid.uuid4()), unbound, str(uuid.uuid4())))


def test_revisions_and_policy_are_immutable(client):
    alert_id = new_alert(client)
    for statement in ("UPDATE voalack.binding_revisions SET customer = 'x' WHERE binding_id = %s",
                      "DELETE FROM voalack.binding_revisions WHERE binding_id = %s"):
        with pytest.raises(psycopg2.errors.RaiseException, match="immutable"):
            sql(statement, (f"lab-{alert_id}",), fetch=False)


def test_install_refuses_a_privileged_runtime_role():
    from voalack.boundary import _check_database_identity
    _check_database_identity({"DATABASE_URL": APP_DSN})
    with pytest.raises(RuntimeError, match="must not be a superuser"):
        _check_database_identity({"DATABASE_URL": DSN})


# --- capture trigger and identity (review: M2 role topology) -----------------------------

TRIGGER = ("CREATE TRIGGER voalack_capture_ack AFTER UPDATE ON public.alerts FOR EACH ROW "
           "WHEN (OLD.history[1] IS DISTINCT FROM NEW.history[1] AND (NEW.history[1]).type = 'ack' "
           "AND NEW.status = 'ack') EXECUTE FUNCTION voalack.capture_ack()")


def test_trigger_dropped_by_the_runtime_owner_fails_closed(client):
    # Coexistence 3a S3a (amended openly): Alerta's table owner can no longer drop the capture trigger at all; the
    # enabled DDL protector refuses it and nothing changes. (Before S3a the drop succeeded and the ACK then failed
    # closed: 500, later 503 at the S2 gate.) An ACK afterwards is captured normally.
    alert_id = new_alert(client)
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.Error) as exc:
            cur.execute("DROP TRIGGER voalack_capture_ack ON public.alerts")    # Alerta's table owner may try
    assert "protected inventory" in str(exc.value), exc.value
    assert sql("SELECT count(*) FROM pg_trigger WHERE tgname = 'voalack_capture_ack' AND tgenabled = 'O'")[0][0] == 1
    assert ack(client, alert_id).status_code == 200
    assert captures(alert_id) == 1


def test_runtime_role_cannot_attach_the_capture_function(app):
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(TRIGGER.replace("voalack_capture_ack", "lab_extra_capture"))


def test_install_refuses_a_login_with_a_path_to_voalack_admin(app):
    from voalack.boundary import _check_database_identity
    sql("CREATE ROLE lab_admin_member LOGIN PASSWORD 'lab-only-member' IN ROLE voalack_admin", fetch=False)
    try:
        with pytest.raises(RuntimeError, match="must not be a superuser"):
            _check_database_identity(
                {"DATABASE_URL": "postgres://lab_admin_member:lab-only-member@localhost/alerta"})
    finally:
        sql("DROP ROLE lab_admin_member", fetch=False)


TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
EXPECTED_TABLES = {                      # the runtime role's complete privilege matrix on schema voalack
    "bindings": {"SELECT"}, "binding_revisions": {"SELECT"}, "binding_generations": set(),
    "authorization_policy": {"SELECT"}, "authorization_policy_active": {"SELECT"},
    "prepared_intents": {"SELECT"}, "captures": {"SELECT"},
    # T04 S1 ledger: the capture runtime role has no access (amended matrix, disclosed)
    "verification_claims": set(), "verifications": set(), "effects": set(),
    # T04 S2 delivery ledger and owner tables: no access for the capture runtime role
    "instance_config": set(), "accepted_kids": set(), "accepted_verifier_versions": set(),
    "session_owners": set(), "owner_containment": set(), "attempts": set(), "target_guards": set(),
    "attempt_evidence": set(),
    # T04 S3b reconciliation and settlement ledger: no access for the capture runtime role
    "reconciliation_reads": set(), "reconciliations": set(), "quiescence": set(), "settlements": set(),
    "provider_sessions": set(),
    # T04 S3c recovery epoch and audit: no access for the capture runtime role
    "recovery_epoch": set(), "recovery_transitions": set(), "recovery_adoptions": set(), "recovered_effects": set(),
    "recovered_holds": set(), "recovery_reads": set(), "recovery_reconciliations": set(), "recovery_settlements": set(),
    "recovery_cleanups": set(),
    # T04 S4 outcome events and projection (amended matrix, disclosed): no access for the capture runtime role
    "projection_actions": set(), "projection_positions": set(), "outcome_events": set(), "projections": set(),
    # T05b S1 observer ledger (amended matrix, disclosed): no access for the capture runtime role
    "observation_chains": set(), "observation_reads": set(), "observation_completions": set(),
    "source_observations": set(), "observation_evidence": set(),
}
EXPECTED_FUNCTIONS = {"lock_binding": True, "lock_grant": True, "stage_intent": True, "approve_intent": True,
                      "capture_ack": False, "refuse_change": False,
                      # T04 S1 verifier functions: not executable by the capture runtime role
                      "capture_fingerprint": False, "claim_verification": False, "_require_current_claim": False,
                      "_lock_original": False,
                      # T04 S2 owner, attempt and encoder functions: not executable by voalack_app
                      "encode_ack_request": False, "_owner_fenced": False, "_dispatch_eligibility": False,
                      "acquire_owner": False, "check_owner": False, "suspend_owner": False,
                      "record_containment": False, "_release_no_dispatch": False, "_hold_uncertain": False,
                      "start_attempt": False, "consume_dispatch": False, "abort_attempt": False,
                      "check_dispatch": False,
                      "close_already_acked": False, "_owner_config_matches": False,
                      "record_not_sent": False, "close_unsupported_target": False,
                      "hold_attempt": False, "record_result": False, "record_evidence": False,
                      "release_stale_started": False,
                      # T04 S3b reconciliation and settlement functions: not executable by voalack_app
                      "_target_holders": False, "begin_reconciliation": False, "record_reconciliation": False,
                      "_settle": False, "_decision_replay": False, "settle_by_reconciliation": False,
                      "settle_uncertain": False, "settlement_status": False, "record_quiescence": False,
                      "register_session": False, "_lock_attempt": False, "_reader_current": False,
                      "_classify": False, "_decision_input": False,
                      # T04 S3c recovery functions: not executable by voalack_app
                      "_epoch_pin": False, "initialize_recovery": False, "close_recovery": False,
                      "journal_facts": False, "recovered_hold_release_only": False, "_request_comment": False,
                      "_effect_facts": False, "_attempt_member": False, "recovery_inventory": False,
                      "adopt_recovery": False, "open_recovery": False, "_recovery_reader": False,
                      "_recovery_reader_current": False, "begin_recovery_read": False, "_classify_hold": False,
                      "record_recovery_read": False, "settle_recovered_hold": False,
                      "recovery_settlement_status": False, "record_recovery_cleanup": False,
                      "_recovered_protected": False, "_inventory_valid": False,
                      "record_verification": False, "promote_effect": False,
                      # T04 S4 event and projection functions (amended, disclosed): not executable by voalack_app
                      "_canonical": False, "_utc": False, "_utc_wall": False, "_note_id": False,
                      "_note_row_sha256": False, "_state_outcome": False, "_outcome_sentence": False,
                      "_lock_projection_actions": False, "_pin_epoch": False, "_append_event": False, "_outcome_event": False,
                      "_event_coverage_ready": False, "project_next": False, "projection_status": False,
                      "projection_resolve": False,
                      "backfill_projection_snapshot": False,
                      # T05b S1 observer functions (amended, disclosed): not executable by voalack_app
                      "_observer_flag_bump": False, "_observation_invalid": False, "_observation_lines": False,
                      "_utc_micro": False, "_sha256_text": False, "_observation_class": False,
                      "_observation_refusal": False, "begin_observation": False, "record_observation": False,
                      "observation_status": False,
                      # Coexistence 3a S1 ownership classifier (amended, disclosed): not executable by voalack_app
                      "alert_class": False,
                      # Coexistence 3a S2 lifetime functions (amended, disclosed): not executable by voalack_app
                      "alert_id_reserved": False, "_require_fresh_snapshot": False, "alert_lifetime": False,
                      "alert_ownership": False, "alert_no_truncate": False, "alert_open_lifetime": False,
                      "bindings_guard": False, "enroll_binding": False, "_event_lifetime_state": False,
                      "protections_intact": False, "audit_ownership": False, "attest_legacy_revision": False}


def test_runtime_privilege_matrix_is_exact(app):
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'voalack' AND c.relkind = 'r'")
        assert {r[0] for r in cur.fetchall()} == set(EXPECTED_TABLES)
        for table, expected in EXPECTED_TABLES.items():
            held = set()
            for privilege in TABLE_PRIVILEGES:
                cur.execute("SELECT has_table_privilege(%s, %s)", (f"voalack.{table}", privilege))
                if cur.fetchone()[0]:
                    held.add(privilege)
            assert held == expected, (table, held)
        # lab_* functions are test fixtures created by the lab superuser (e.g. lab_fail_at_commit)
        cur.execute("SELECT p.proname, has_function_privilege(p.oid, 'EXECUTE') FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'voalack' AND p.proname NOT LIKE 'lab\\_%'")
        assert dict(cur.fetchall()) == EXPECTED_FUNCTIONS
        cur.execute("SELECT has_schema_privilege('voalack', 'USAGE'), has_schema_privilege('voalack', 'CREATE')")
        assert cur.fetchone() == (True, False)
        cur.execute("SELECT p.proname, p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'voalack' AND p.proname NOT LIKE 'lab\\_%'")
        for name, definer, config, owner in cur.fetchall():
            assert owner == "voalack_admin", name
            assert config and config[-1].endswith("pg_temp"), (name, config)   # pg_temp last
            assert definer == (name not in ("refuse_change",)), name
