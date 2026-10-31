"""Coexistence 3a S3a: the DDL protector, permits (detach/recreate) and bootstrap (r8 sections 3 and 10; plan r2;
design review).

The enabled guard refuses inventory-breaking DDL from every session_user, superusers included. The trusted-superuser
bypass (disabling the event triggers) is disclosed, exercised here only through the labelled lab fixture
conftest.guard_bypassed. S3a never opens a real permit: open_permit() refuses until the S3b containment exists; the
permit predicates are exercised with a lab permit row written directly (labelled, never a production path).
S3b: a permit is bound to a recovery window and its registered coordinator backend; the lab permit plants a window,
registration, journal intent and permit for one dedicated lab connection, and the DDL under it runs on that connection.
The real window/permit lifecycle is exercised in test_coexist_s3_recovery.py."""
import uuid
from contextlib import contextmanager

import psycopg2
import pytest

from conftest import APP_DSN, DSN, FOUR, GUARD_EVENT_TRIGGERS, _exec_raw, ack, guard_bypassed, inventory_problems, new_alert, sql, status  # noqa: E501


def raises(statement, args=(), dsn=DSN):
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(statement, args)
        conn.commit()
        return None
    except psycopg2.Error as exc:
        conn.rollback()
        return str(exc).strip().splitlines()[0]
    finally:
        conn.close()


@contextmanager
def admin_member():
    """A non-superuser login holding voalack_admin (the protected functions' owner role)."""
    name = f"lab_admin_m_{uuid.uuid4().hex[:6]}"
    sql(f"CREATE ROLE {name} LOGIN PASSWORD 'lab-only-member' IN ROLE voalack_admin", fetch=False)
    try:
        yield f"postgres://{name}:lab-only-member@localhost/alerta"
    finally:
        sql(f"DROP ROLE {name}", fetch=False)


def refused(err):
    return bool(err) and ("protected inventory" in err or "permission denied" in err or "must be owner" in err)


# --- outside a permit: inventory-breaking DDL refused for every session_user ---------------------------------------

DDL = {
    "drop": "DROP TRIGGER voalack_alert_ownership ON public.alerts",
    "disable": "ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack",
    "rename": "ALTER TRIGGER voalack_alert_lifetime ON public.alerts RENAME TO lab_renamed",
    "extra": "CREATE TRIGGER lab_extra AFTER INSERT ON public.alerts FOR EACH ROW EXECUTE FUNCTION voalack.alert_lifetime()",
    "body": "CREATE OR REPLACE FUNCTION voalack.alert_no_truncate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER "
            "SET search_path = pg_catalog, voalack, pg_temp AS $$ BEGIN RETURN NULL; END $$",
    # F6: the two lifetime trigger functions are protected bodies too
    "lifetime-refuse-body": "CREATE OR REPLACE FUNCTION voalack_lifetime.refuse_change() RETURNS trigger "
                            "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    "lifetime-close-body": "CREATE OR REPLACE FUNCTION voalack_lifetime.only_close() RETURNS trigger "
                           "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    # Amendment A1: the two protected attachments and voalack.refuse_change()
    "a1-drop-bindings-guard": "DROP TRIGGER bindings_guard ON voalack.bindings",
    "a1-disable-revisions-immutable": "ALTER TABLE voalack.binding_revisions DISABLE TRIGGER binding_revisions_immutable",
    "a1-refuse-body": "CREATE OR REPLACE FUNCTION voalack.refuse_change() RETURNS trigger "
                      "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    # A protected relation's raw ACL
    "relacl": "GRANT SELECT ON voalack_lifetime.alert_lifetimes TO PUBLIC",
    # An explicit empty ACL ({}): the owner revoking its own privileges; raw, it differs from both NULL and the default
    "relacl_empty": "REVOKE ALL ON voalack_lifetime.alert_lifetimes FROM voalack_admin",
}


TRIGGERS_RAW = ("SELECT tgname, tgenabled::text, pg_get_triggerdef(oid) FROM pg_trigger "
                "WHERE tgrelid = 'public.alerts'::regclass AND NOT tgisinternal ORDER BY 1")
FUNCTION_RAW = ("SELECT pg_get_functiondef(p.oid), pg_get_userbyid(p.proowner), p.proacl::text FROM pg_proc p "
                "WHERE p.oid = to_regprocedure('{}')")
A1_RAW = ("SELECT tgrelid::regclass::text, tgname, tgenabled::text, pg_get_triggerdef(oid) FROM pg_trigger "
          "WHERE tgrelid IN ('voalack.bindings'::regclass, 'voalack.binding_revisions'::regclass) "
          "AND tgname IN ('bindings_guard', 'binding_revisions_immutable') ORDER BY 1, 2")
RELACL_RAW = "SELECT relowner::regrole::text, relacl::text FROM pg_class WHERE oid = 'voalack_lifetime.alert_lifetimes'::regclass"


@contextmanager
def restored(raw_query, undo):
    """[lab] Unconditional cleanup for an inventory-breaking DDL case: snapshot the raw catalog fact the statement could
    change (read from the catalog, never through the inventory a mutant may blind); in finally, only if it changed,
    apply the exact undo and assert raw equality with the snapshot. Under the real guard nothing changes. A failed
    undo stays a visible failure, never suppressed."""
    before = sql(raw_query)
    try:
        yield before
    finally:
        if sql(raw_query) != before:
            undo(before)
            assert sql(raw_query) == before, (raw_query, before, sql(raw_query))


def _undo_matrix(change):
    def recreate_four(_):
        with lab_permit("recreate", '{"drop": []}') as lab:
            _recreate_missing(lab)
    def body(before):
        _exec_raw(before[0][0])
    return {"drop": recreate_four, "lifetime-refuse-body": body, "lifetime-close-body": body, "a1-refuse-body": body,
            "a1-drop-bindings-guard": lambda _: _exec_raw(
                "CREATE TRIGGER bindings_guard BEFORE INSERT OR UPDATE ON voalack.bindings "
                "FOR EACH ROW EXECUTE FUNCTION voalack.bindings_guard()"),
            "a1-disable-revisions-immutable": lambda _: _exec_raw(
                "ALTER TABLE voalack.binding_revisions ENABLE TRIGGER binding_revisions_immutable"),
            "disable": lambda _: _exec_raw("ALTER TABLE public.alerts ENABLE TRIGGER voalack_capture_ack"),
            "rename": lambda _: _exec_raw("ALTER TRIGGER lab_renamed ON public.alerts RENAME TO voalack_alert_lifetime"),
            "extra": lambda _: _exec_raw("DROP TRIGGER IF EXISTS lab_extra ON public.alerts"),
            "body": body,
            "relacl": lambda _: _exec_raw("REVOKE SELECT ON voalack_lifetime.alert_lifetimes FROM PUBLIC"),
            "relacl_empty": lambda _: _exec_raw("GRANT ALL ON voalack_lifetime.alert_lifetimes TO voalack_admin")}[change]


@pytest.mark.parametrize("change", list(DDL))
@pytest.mark.parametrize("who", ["table-owner", "admin-member", "superuser"])
def test_inventory_breaking_ddl_is_refused_for_every_session_user(client, app, change, who):
    before = inventory_problems()
    assert before == []
    raw = {"body": FUNCTION_RAW.format("voalack.alert_no_truncate()"),
           "lifetime-refuse-body": FUNCTION_RAW.format("voalack_lifetime.refuse_change()"),
           "lifetime-close-body": FUNCTION_RAW.format("voalack_lifetime.only_close()"),
           "a1-refuse-body": FUNCTION_RAW.format("voalack.refuse_change()"),
           "a1-drop-bindings-guard": A1_RAW, "a1-disable-revisions-immutable": A1_RAW,
           "relacl": RELACL_RAW, "relacl_empty": RELACL_RAW}.get(change, TRIGGERS_RAW)
    with restored(raw, _undo_matrix(change)):
        if who == "admin-member":
            with admin_member() as dsn:
                err = raises(DDL[change], dsn=dsn)
        else:
            err = raises(DDL[change], dsn=APP_DSN if who == "table-owner" else DSN)
        assert refused(err), (who, change, err)
    assert inventory_problems() == []                          # nothing changed


def test_a_protected_functions_owner_change_is_refused(client, app):
    err = raises("ALTER FUNCTION voalack.alert_ownership() OWNER TO voalack_app")
    assert refused(err), err
    assert sql("SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'voalack.alert_ownership()'::regprocedure"
               )[0][0] == "voalack_admin"


def test_public_execute_on_a_protected_function_is_refused(client, app):
    err = raises("GRANT EXECUTE ON FUNCTION voalack.audit_ownership() TO PUBLIC")
    assert refused(err), err
    assert inventory_problems() == []


# The complete protected-function set (guard_pre.sql protected_functions()), by exact signature.
PROTECTED_FUNCTIONS = (
    "voalack.capture_ack()", "voalack.alert_class(text,text)", "voalack.alert_ownership()", "voalack.alert_lifetime()",
    "voalack.alert_id_reserved(text)", "voalack._require_fresh_snapshot()", "voalack.alert_no_truncate()",
    "voalack.alert_open_lifetime(text)", "voalack.bindings_guard()", "voalack.enroll_binding(text,text,integer)",
    "voalack.audit_ownership()", "voalack.protections_intact()",
    "voalack.attest_legacy_revision(text,integer,bigint,text,text)", "voalack_lifetime.refuse_change()",
    "voalack_lifetime.only_close()", "voalack.refuse_change()", "voalack_guard.protect()",
    "voalack_guard.inventory_problems()", "voalack_guard.current_inventory()", "voalack_guard.public_trigger_defs()",
    "voalack_guard.protected_functions()",
    # S3b: recovery windows, registration, journal, receipts, permit lifecycle (trigger-enforced write paths)
    "voalack_guard.refuse_rewrite()", "voalack_guard.writer_logins()", "voalack_guard.connect_logins()",
    "voalack_guard.outside_digest(oid[])", "voalack_guard.lifetime_digest()", "voalack_guard.containment_snapshot()",
    "voalack_guard.caller_backend_start()", "voalack_guard.window_active(bigint)", "voalack_guard.current_registration(bigint)",
    "voalack_guard.preload_deny_v1()", "voalack_guard.window_snapshot(bigint)", "voalack_guard.cold_problems(bigint)",
    "voalack_guard.client_problems(bigint)", "voalack_guard.trusted_superusers(bigint)", "voalack_guard.role_problems(bigint,text)",
    "voalack_guard.window_problems(bigint,text)", "voalack_guard.effect_problems(bigint,text,jsonb)", "voalack_guard.step_phase(text)",
    "voalack_guard.open_intent(bigint)", "voalack_guard.next_step(bigint)", "voalack_guard.lock_window(bigint)",
    "voalack_guard.require_coordinator(bigint)", "voalack_guard.receipt_binding(bigint,bigint)", "voalack_guard.validation_problems(bigint)",
    "voalack_guard.run_probe()", "voalack_guard.windows_insert_guard()", "voalack_guard.windows_after_insert()",
    "voalack_guard.backends_insert_guard()", "voalack_guard.backends_after_insert()", "voalack_guard.journal_insert_guard()",
    "voalack_guard.journal_after_insert()", "voalack_guard.effects_insert_guard()", "voalack_guard.permits_guard()",
    "voalack_guard.open_window(text,jsonb)", "voalack_guard.register_backend(bigint,text)", "voalack_guard.begin_step(bigint,text)",
    "voalack_guard.record_effect(bigint,bigint)", "voalack_guard.seal_step(bigint,bigint)", "voalack_guard.lab_gap(bigint)",
    "voalack_guard.open_permit(bigint,bigint)", "voalack_guard.transition_permit(bigint,bigint,text,text)", "voalack_guard.close_permit(bigint,bigint)",
    "voalack_guard.close_window(bigint)", "voalack_guard.record_disposition(bigint,text,text,text)")


def test_the_inventory_records_each_protected_functions_owner_and_its_acl_names_it(client, app):
    """Owner coverage as recorded content (r6/c1 remaining-gap disposition): the frozen inventory holds exactly the
    complete protected-function set, and each row's owner component equals the function's raw catalog owner. Every raw
    ACL is explicit and names that owner (by role OID, as grantee or grantor), which is why an owner change is also an
    ACL change. Read from the catalog, never through current_inventory(), which shares the frozen row's construction."""
    rows = dict(sql("SELECT name, attrs FROM voalack_guard.frozen_inventory WHERE kind = 'function'"))
    assert sorted(rows) == sorted(PROTECTED_FUNCTIONS), sorted(set(rows) ^ set(PROTECTED_FUNCTIONS))
    for name in PROTECTED_FUNCTIONS:
        raw_owner, owner_oid, acl_null = sql(
            "SELECT pg_get_userbyid(p.proowner), p.proowner, p.proacl IS NULL FROM pg_proc p "
            "WHERE p.oid = to_regprocedure(%s)", (name,))[0]
        frozen_owner = rows[name].split("|")[2]
        assert frozen_owner == raw_owner, (name, frozen_owner, raw_owner)
        assert acl_null is False, (name, "default (NULL) ACL")
        names_owner = sql("SELECT bool_or(a.grantee = %s OR a.grantor = %s) FROM pg_proc p, aclexplode(p.proacl) a "
                          "WHERE p.oid = to_regprocedure(%s)", (owner_oid, owner_oid, name))[0][0]
        assert names_owner is True, (name, "ACL does not name the owner")


def test_unrelated_ddl_still_passes_and_leaves_the_inventory_intact(client, app):
    name = f"lab_t_{uuid.uuid4().hex[:6]}"
    assert raises(f"CREATE TABLE public.{name} (x int)") is None
    assert raises(f"DROP TABLE public.{name}") is None
    assert inventory_problems() == []


# --- bootstrap and reapply ------------------------------------------------------------------------------------------

def _reapply():
    from voalack import schema
    conn = psycopg2.connect(DSN)
    try:
        schema.apply(conn)
    finally:
        conn.close()


def test_reapply_of_an_intact_installation_is_a_no_op(client, app):
    frozen = sql("SELECT md5(string_agg(kind || name || attrs, '|' ORDER BY kind, name)) FROM voalack_guard.frozen_inventory")
    _reapply()
    assert sql("SELECT md5(string_agg(kind || name || attrs, '|' ORDER BY kind, name)) "
               "FROM voalack_guard.frozen_inventory") == frozen
    assert inventory_problems() == []


def test_reapply_refuses_a_drifted_installation_and_never_repairs_it(client, app):
    with guard_bypassed("create drift to witness the reapply refusal"):
        sql("ALTER TABLE public.alerts DISABLE TRIGGER voalack_alert_ownership", fetch=False)
        with pytest.raises(psycopg2.Error) as exc:
            _reapply()
        assert "drifted; reapply refused" in str(exc.value), exc.value
        assert sql("SELECT tgenabled FROM pg_trigger WHERE tgname = 'voalack_alert_ownership'")[0][0] == "D"
        sql("ALTER TABLE public.alerts ENABLE TRIGGER voalack_alert_ownership", fetch=False)


def test_the_guard_owner_prerequisite_is_verified(client, app):
    sql("GRANT voalack_guard_owner TO voalack_app", fetch=False)
    try:
        with pytest.raises(psycopg2.Error) as exc:
            _reapply()
        assert "voalack_guard_owner must have no members" in str(exc.value), exc.value
    finally:
        sql("REVOKE voalack_guard_owner FROM voalack_app", fetch=False)
    assert inventory_problems() == []


# --- admission while the guard is bypassed ---------------------------------------------------------------------------

def test_admission_refuses_while_the_event_triggers_are_disabled(client, app):
    alert_id = new_alert(client)
    with guard_bypassed("event triggers disabled: the 4+2 profile is incomplete"):
        assert sql("SELECT voalack.protections_intact()")[0][0] is False
        response = ack(client, alert_id)
        assert response.status_code == 503 and "protections not intact" in response.get_data(as_text=True)
    assert status(alert_id)[0] == "open"
    assert ack(client, alert_id).status_code == 200            # restored and re-enabled: admitted again


def test_disabled_event_triggers_make_the_inventory_not_intact(client, app):
    """The event triggers' enabled state is part of the shared inventory. Read directly, not through guard_bypassed:
    both disabled (catalog-checked) -> protections_intact() is False; re-enabled unconditionally, catalog-checked."""
    state = "SELECT evtname, evtenabled::text FROM pg_event_trigger WHERE evtname = ANY(%s) ORDER BY 1"
    names = sorted(GUARD_EVENT_TRIGGERS)
    assert inventory_problems() == [] and sql(state, (names,)) == [(n, "O") for n in names]
    intact, during = "not run", "not run"
    try:
        for name in GUARD_EVENT_TRIGGERS:
            sql(f"ALTER EVENT TRIGGER {name} DISABLE", fetch=False)
        during = sql(state, (names,))
        intact = sql("SELECT voalack.protections_intact()")[0][0]
    finally:
        for name in GUARD_EVENT_TRIGGERS:
            sql(f"ALTER EVENT TRIGGER {name} ENABLE", fetch=False)
    assert sql(state, (names,)) == [(n, "O") for n in names] and during == [(n, "D") for n in names], during
    assert inventory_problems() == []
    assert intact is False, intact


# --- permits: predicates via a labelled lab permit row (the real lifecycle is in test_coexist_s3_recovery.py) ------

@pytest.mark.parametrize("who", ["superuser", "table-owner"])
def test_open_permit_refuses_outside_a_window_detach_intent(client, app, who):
    """S3b: open_permit binds an active window's current detach intent and its registered coordinator; with no window
    it refuses for a superuser, and the table owner cannot call it at all (EXECUTE revoked from PUBLIC)."""
    err = raises("SELECT voalack_guard.open_permit(0, 0)", dsn=DSN if who == "superuser" else APP_DSN)
    assert err and ("recovery window 0 does not exist" in err or "permission denied" in err), err
    assert sql("SELECT count(*) FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL")[0][0] == 0


class LabConnection:
    """[lab] One dedicated superuser connection, planted as the registered coordinator of a planted window."""

    def __init__(self, conn):
        self.conn = conn

    def raises(self, statement, args=()):
        try:
            with self.conn.cursor() as cur:
                cur.execute("SET lock_timeout = '10s'")
                cur.execute(statement, args)
            self.conn.commit()
            return None
        except psycopg2.Error as exc:
            self.conn.rollback()
            return str(exc).strip().splitlines()[0]

    def exec_raw(self, statement):
        with self.conn.cursor() as cur:
            cur.execute(statement)
        self.conn.commit()


@contextmanager
def lab_permit(phase, intent='{}', executor=None):
    """[lab] A permit row written directly by the lab superuser to exercise protect()'s predicates; never a production
    path. S3b binds a permit to a window and its registered coordinator: this plants, with session_replication_role =
    replica (row triggers and FK checks off; DML only, no DDL runs in that mode), a window, a registration of the lab
    connection, its open/register/intent journal rows and the permit. The DDL under the permit runs on that
    connection. In finally the permit is closed and the planted window closed (a planted close row)."""
    conn = psycopg2.connect(DSN)
    planted = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT a.pid, a.backend_start, session_user FROM pg_stat_activity a WHERE a.pid = pg_backend_pid()")
            pid, start, user = cur.fetchone()
            cur.execute("SET session_replication_role = replica")
            cur.execute("INSERT INTO voalack_guard.recovery_windows (database, system_identifier, source_sha256, "
                        "executor_role, created_pid, created_backend_start, attestation, preload) "
                        "SELECT current_database(), system_identifier, repeat('0', 64), %s, %s, %s, "
                        "'{\"lab\": \"planted\"}'::jsonb, current_setting('shared_preload_libraries') "
                        "FROM pg_control_system() RETURNING window_id", (user, pid, start))
            window = cur.fetchone()[0]
            # backend_start from the catalog in SQL (a round trip through Python truncates it below a millisecond)
            cur.execute("INSERT INTO voalack_guard.executor_backends (window_id, role, pid, backend_start, database, "
                        "session_user_name, source_sha256) SELECT %s, 'coordinator', a.pid, a.backend_start, "
                        "current_database(), session_user, repeat('0', 64) "
                        "FROM pg_stat_activity a WHERE a.pid = pg_backend_pid() "
                        "RETURNING registration_id", (window,))
            reg = cur.fetchone()[0]
            cur.execute("INSERT INTO voalack_guard.recovery_journal (window_id, seq, kind, step, registration_id, pid, "
                        "backend_start) SELECT %s, s.seq, s.kind, s.step, s.reg, a.pid, a.backend_start "
                        "FROM pg_stat_activity a, (VALUES (1, 'open', NULL, NULL::bigint), (2, 'register', NULL, %s), "
                        "(3, 'intent', 'detach', %s)) s (seq, kind, step, reg) WHERE a.pid = pg_backend_pid()",
                        (window, reg, reg))
            cur.execute("INSERT INTO voalack_guard.maintenance_permits (executor, phase, intent, window_id, intent_seq) "
                        "VALUES (%s, %s, %s::jsonb, %s, 3) RETURNING permit_id", (executor or user, phase, intent, window))
            permit = cur.fetchone()[0]
            cur.execute("SET session_replication_role = origin")
            cur.execute("SELECT b.backend_start, a.backend_start, pg_has_role('voalack_guard_owner', 'pg_read_all_stats', "
                        "'USAGE'), voalack_guard.current_registration(%s), %s FROM voalack_guard.executor_backends b "
                        "JOIN pg_stat_activity a ON a.pid = b.pid WHERE b.window_id = %s", (window, reg, window))
            ident = cur.fetchone()
            assert ident[0] == ident[1] and ident[2] and ident[3] == ident[4], ident      # [lab] planted identity
        conn.commit()
        planted = True
        yield LabConnection(conn)
    finally:
        conn.rollback()
        if not planted:
            conn.close()
            return
        with conn.cursor() as cur:
            cur.execute("SET session_replication_role = replica")
            cur.execute("UPDATE voalack_guard.maintenance_permits SET closed_at = clock_timestamp() "
                        "WHERE window_id = %s AND closed_at IS NULL", (window,))
            cur.execute("INSERT INTO voalack_guard.recovery_journal (window_id, seq, kind, pid, backend_start) "
                        "SELECT %s, max(j.seq) + 1, 'close', a.pid, a.backend_start FROM voalack_guard.recovery_journal j, "
                        "pg_stat_activity a WHERE j.window_id = %s AND a.pid = pg_backend_pid() GROUP BY a.pid, a.backend_start",
                        (window, window))
            cur.execute("SET session_replication_role = origin")
        conn.commit()
        conn.close()


@contextmanager
def four_restored():
    """[lab] Unconditional cleanup for permit tests: whatever the body does (including a failed assertion), any of the
    four left missing is recreated in frozen form under a labelled lab recreate permit, then the inventory is asserted
    intact. A failed restoration stays a visible failure."""
    try:
        yield
    finally:
        with lab_permit("recreate", '{"drop": []}') as lab:
            _recreate_missing(lab)
        assert inventory_problems() == [], inventory_problems()
        assert sql("SELECT count(*) FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL")[0][0] == 0


def _recreate_missing(lab):
    from voalack import recovery
    for statement in [recovery.approved_trigger_ddl()] + recovery.approved_protection_ddl():
        name = statement.split()[2]
        if not sql("SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.alerts'::regclass AND tgname = %s", (name,)):
            lab.exec_raw(statement)


def test_a_detach_permit_allows_dropping_the_four_and_nothing_else(client, app):
    with four_restored(), lab_permit("detach") as lab:
        assert lab.raises("DROP TRIGGER voalack_alert_ownership ON public.alerts") is None
        err = lab.raises("ALTER FUNCTION voalack.alert_class(text, text) OWNER TO voalack_app")
        assert err and "does not allow ALTER FUNCTION" in err, err
        err = lab.raises("CREATE TABLE public.lab_detach_extra (x int)")
        assert err and "does not allow CREATE TABLE" in err, err
        from voalack import recovery
        ownership = [d for d in recovery.approved_protection_ddl() if d.split()[2] == "voalack_alert_ownership"][0]
        err = lab.raises(ownership)                                    # a detach never creates, even the frozen form
        assert err and "does not allow CREATE TRIGGER" in err, err


def test_a_detach_permit_refuses_dropping_any_other_trigger(client, app):
    """The sql_drop check: under a detach permit, a trigger that is not one of the four (here an unprotected lab trigger
    on public.notes, outside the inventory) cannot be dropped; ddl_command_end alone would admit it."""
    sql("CREATE OR REPLACE FUNCTION public.lab_noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        fetch=False)
    sql("CREATE TRIGGER lab_notes_noop BEFORE INSERT ON public.notes FOR EACH ROW EXECUTE FUNCTION public.lab_noop()",
        fetch=False)
    try:
        with lab_permit("detach") as lab:
            err = lab.raises("DROP TRIGGER lab_notes_noop ON public.notes")
            assert err and "does not allow dropping trigger lab_notes_noop on public.notes" in err, err
    finally:
        sql("DROP TRIGGER IF EXISTS lab_notes_noop ON public.notes; DROP FUNCTION IF EXISTS public.lab_noop()",
            fetch=False)
    assert inventory_problems() == []


def test_a_permit_for_another_executor_refuses(client, app):
    with four_restored(), lab_permit("detach", executor="someone_else") as lab:
        err = lab.raises("DROP TRIGGER voalack_alert_ownership ON public.alerts")
        assert err and "open for another executor" in err, err
    assert inventory_problems() == []


def test_recreate_drops_only_a_trigger_named_in_the_intent_and_creates_only_frozen_forms(client, app):
    with four_restored(), lab_permit("recreate", '{"drop": ["voalack_alert_lifetime"]}') as lab:
        err = lab.raises("DROP TRIGGER voalack_alert_ownership ON public.alerts")          # present, not in the intent
        assert err and "not named in the recreate step's intent" in err, err
        assert lab.raises("DROP TRIGGER voalack_alert_lifetime ON public.alerts") is None
        err = lab.raises("CREATE TRIGGER voalack_alert_lifetime AFTER INSERT ON public.alerts FOR EACH ROW "
                     "WHEN (NEW.id IS NOT NULL) EXECUTE FUNCTION voalack.alert_lifetime()")      # not the frozen form
        assert err and "DDL refused under permit" in err, err
        _recreate_missing(lab)
    assert inventory_problems() == []


def test_a_closed_permit_exempts_nothing(client, app):
    with lab_permit("detach") as lab:
        pass
    with four_restored():
        err = raises("DROP TRIGGER voalack_alert_ownership ON public.alerts")
        assert refused(err), err


# --- F1: under a recreate permit, only the four can be created ---------------------------------------------------------

def test_a_recreate_permit_refuses_creating_any_other_trigger(client, app):
    """Every object a command creates under a permit must be one of the four public triggers; a trigger on public.notes
    calling an unrelated function (outside every inventory branch, no sql_drop) is refused, the after-state unchanged.
    The frozen recreation itself is the recreate test above; unrelated DDL outside a permit is its own control."""
    sql("CREATE OR REPLACE FUNCTION public.lab_noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        fetch=False)
    present = "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.notes'::regclass AND tgname = 'lab_notes_x'"
    try:
        assert inventory_problems() == [] and sql(present)[0][0] == 0
        with lab_permit("recreate", '{"drop": []}') as lab:
            err = lab.raises("CREATE TRIGGER lab_notes_x BEFORE INSERT ON public.notes FOR EACH ROW "
                         "EXECUTE FUNCTION public.lab_noop()")
            assert err and "does not allow creating trigger lab_notes_x on public.notes" in err, err
        assert sql(present)[0][0] == 0
    finally:
        sql("DROP TRIGGER IF EXISTS lab_notes_x ON public.notes; DROP FUNCTION IF EXISTS public.lab_noop()",
            fetch=False)
    assert inventory_problems() == []


# --- F4: a recreate permit's drop intent must be a JSON array; membership is affirmative ------------------------------

@pytest.mark.parametrize("intent", ["{}", '{"drop": null}', '{"drop": "voalack_alert_ownership"}'],
                         ids=["missing-key", "json-null", "wrong-type"])
def test_a_recreate_permit_with_malformed_intent_refuses_all_ddl(client, app, intent):
    with four_restored():
        with lab_permit("recreate", intent) as lab:
            err = lab.raises("DROP TRIGGER voalack_alert_ownership ON public.alerts")
            assert err and "has no valid drop intent" in err, err
            err = lab.raises("CREATE TABLE public.lab_intent_x (x int)")
            assert err and "has no valid drop intent" in err, err
        assert sql("SELECT count(*) FROM pg_trigger WHERE tgname = 'voalack_alert_ownership'")[0][0] == 1


@pytest.mark.parametrize("intent", ["{}", '{"drop": null}', '{"drop": "voalack_alert_ownership"}'],
                         ids=["missing-key", "json-null", "wrong-type"])
def test_a_recreate_permit_with_malformed_intent_refuses_frozen_creation(client, app, intent):
    """r3 review (sensitive coverage per malformed shape): a CREATE of an approved frozen trigger form consults no drop
    membership, so only the intent-shape check can refuse it. The trigger is dropped under a detach permit, then its
    exact frozen form is refused under a recreate permit whose drop intent is malformed, and stays absent until the
    unconditional restoration. The admitted control is the empty-list test below (a valid array allows it)."""
    from voalack import recovery
    statement = next(s for s in recovery.approved_protection_ddl() if s.split()[2] == "voalack_alert_ownership")
    with four_restored():
        with lab_permit("detach") as lab:
            assert lab.raises("DROP TRIGGER voalack_alert_ownership ON public.alerts") is None
        with lab_permit("recreate", intent) as lab:
            err = lab.raises(statement)
            assert err and "has no valid drop intent" in err, err
        assert sql("SELECT count(*) FROM pg_trigger WHERE tgname = 'voalack_alert_ownership'")[0][0] == 0


def test_a_recreate_permit_with_an_empty_drop_list_refuses_drops_and_allows_frozen_creation(client, app):
    with four_restored():
        with lab_permit("recreate", '{"drop": []}') as lab:
            err = lab.raises("DROP TRIGGER voalack_alert_ownership ON public.alerts")
            assert err and "not named in the recreate step's intent" in err, err
        with lab_permit("detach") as lab:
            assert lab.raises("DROP TRIGGER voalack_alert_ownership ON public.alerts") is None
        with lab_permit("recreate", '{"drop": []}') as lab:
            _recreate_missing(lab)                                    # the frozen form, no drop needed
        assert sql("SELECT count(*) FROM pg_trigger WHERE tgname = 'voalack_alert_ownership'")[0][0] == 1


# --- F3/F2: protected schemas (owner, ACL) and relation structure (columns, constraints, indexes) ---------------------

NAMESPACE_DDL = {
    "guard-owner": "ALTER SCHEMA voalack_guard OWNER TO voalack_admin",
    "guard-grant-create": "GRANT CREATE ON SCHEMA voalack_guard TO voalack_admin",
    "guard-grant-usage": "GRANT USAGE ON SCHEMA voalack_guard TO PUBLIC",
    "lifetime-owner": "ALTER SCHEMA voalack_lifetime OWNER TO voalack_app",
    "lifetime-grant-create": "GRANT CREATE ON SCHEMA voalack_lifetime TO voalack_app",
}
STRUCTURE_DDL = {
    "guard-add-column": "ALTER TABLE voalack_guard.maintenance_permits ADD COLUMN lab_extra int",
    "guard-set-default": "ALTER TABLE voalack_guard.maintenance_permits ALTER COLUMN executor SET DEFAULT 'lab'",
    "lifetime-add-column": "ALTER TABLE voalack_lifetime.alert_lifetimes ADD COLUMN lab_extra int",
    "lifetime-check-constraint": "ALTER TABLE voalack_lifetime.alert_lifetimes ADD CONSTRAINT lab_check CHECK (true)",
    "lifetime-index": "CREATE INDEX lab_idx ON voalack_lifetime.alert_lifetimes (opened_at)",
    "guard-sequence-increment": "ALTER SEQUENCE voalack_guard.maintenance_permits_permit_id_seq INCREMENT BY 2",
}
STATE = ("SELECT kind, name, attrs FROM voalack_guard.current_inventory() WHERE kind IN "
         "('namespace', 'relation', 'relation_column', 'relation_constraint', 'index') ORDER BY 1, 2")


NAMESPACE_RAW = ("SELECT nspname, nspowner::regrole::text, nspacl::text FROM pg_namespace "
                 "WHERE nspname IN ('voalack_guard', 'voalack_lifetime') ORDER BY 1")
NAMESPACE_UNDO = {
    "guard-owner": "ALTER SCHEMA voalack_guard OWNER TO voalack_guard_owner",
    "guard-grant-create": "REVOKE CREATE ON SCHEMA voalack_guard FROM voalack_admin",
    "guard-grant-usage": "REVOKE USAGE ON SCHEMA voalack_guard FROM PUBLIC",
    "lifetime-owner": "ALTER SCHEMA voalack_lifetime OWNER TO voalack_admin",
    "lifetime-grant-create": "REVOKE CREATE ON SCHEMA voalack_lifetime FROM voalack_app",
}
STRUCTURE_RAW = (
    "SELECT 'col', a.attrelid::regclass::text, a.attname::text, coalesce(pg_get_expr(d.adbin, d.adrelid), '-') "
    "FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
    "WHERE a.attrelid IN ('voalack_guard.maintenance_permits'::regclass, 'voalack_lifetime.alert_lifetimes'::regclass) "
    "AND a.attnum > 0 AND NOT a.attisdropped "
    "UNION ALL SELECT 'con', conrelid::regclass::text, conname::text, pg_get_constraintdef(oid) FROM pg_constraint "
    "WHERE conrelid IN ('voalack_guard.maintenance_permits'::regclass, 'voalack_lifetime.alert_lifetimes'::regclass) "
    "UNION ALL SELECT 'idx', indrelid::regclass::text, indexrelid::regclass::text, pg_get_indexdef(indexrelid) "
    "FROM pg_index WHERE indrelid IN ('voalack_guard.maintenance_permits'::regclass, "
    "'voalack_lifetime.alert_lifetimes'::regclass) "
    "UNION ALL SELECT 'seq', seqrelid::regclass::text, seqincrement::text, seqmin::text || '/' || seqmax::text "
    "FROM pg_sequence WHERE seqrelid = 'voalack_guard.maintenance_permits_permit_id_seq'::regclass ORDER BY 1, 2, 3")
STRUCTURE_UNDO = {
    "guard-add-column": "ALTER TABLE voalack_guard.maintenance_permits DROP COLUMN lab_extra",
    "guard-set-default": "ALTER TABLE voalack_guard.maintenance_permits ALTER COLUMN executor DROP DEFAULT",
    "lifetime-add-column": "ALTER TABLE voalack_lifetime.alert_lifetimes DROP COLUMN lab_extra",
    "lifetime-check-constraint": "ALTER TABLE voalack_lifetime.alert_lifetimes DROP CONSTRAINT lab_check",
    "lifetime-index": "DROP INDEX voalack_lifetime.lab_idx",
    "guard-sequence-increment": "ALTER SEQUENCE voalack_guard.maintenance_permits_permit_id_seq INCREMENT BY 1",
}


@pytest.mark.parametrize("change", list(NAMESPACE_DDL))
def test_protected_schema_owner_and_acl_changes_are_refused(client, app, change):
    assert inventory_problems() == []
    before = sql(STATE)
    with restored(NAMESPACE_RAW, lambda _: _exec_raw(NAMESPACE_UNDO[change])):
        err = raises(NAMESPACE_DDL[change])                    # the superuser
        _namespace_oracle(change, err)
    assert sql(STATE) == before and inventory_problems() == []


def _namespace_oracle(change, err):
    if change == "guard-owner":
        # Moving voalack_guard away from voalack_guard_owner removes the guard definer's own schema access, so
        # protect() fails closed before it can compare the inventory: refused, but not by the namespace comparison.
        # A control, not a namespace witness (lifetime-owner is the owner witness).
        assert err and "permission denied for schema voalack_guard" in err, err
    else:
        assert err and "protected inventory" in err, err


@pytest.mark.parametrize("change", list(STRUCTURE_DDL))
def test_protected_relation_structure_changes_are_refused(client, app, change):
    assert inventory_problems() == []
    before = sql(STATE)
    with restored(STRUCTURE_RAW, lambda _: _exec_raw(STRUCTURE_UNDO[change])):
        err = raises(STRUCTURE_DDL[change])                    # the superuser
        assert err and "protected inventory" in err, err
    assert sql(STATE) == before and inventory_problems() == []


def test_an_ordinary_nextval_leaves_the_inventory_intact(client, app):
    """Control for the sequence kind: evolving values (last_value) are not frozen; only definitions are."""
    assert inventory_problems() == []
    sql("SELECT nextval('voalack_guard.maintenance_permits_permit_id_seq')")
    assert inventory_problems() == []


CONSTRUCTED = {
    "namespace": ("GRANT CREATE ON SCHEMA voalack_lifetime TO voalack_app",
                  "REVOKE CREATE ON SCHEMA voalack_lifetime FROM voalack_app", "differs namespace voalack_lifetime"),
    "column": ("ALTER TABLE voalack_lifetime.alert_lifetimes ADD COLUMN lab_extra int",
               "ALTER TABLE voalack_lifetime.alert_lifetimes DROP COLUMN lab_extra",
               "extra relation_column voalack_lifetime.alert_lifetimes.lab_extra"),
    "constraint": ("ALTER TABLE voalack_lifetime.alert_lifetimes ADD CONSTRAINT lab_check CHECK (true)",
                   "ALTER TABLE voalack_lifetime.alert_lifetimes DROP CONSTRAINT lab_check",
                   "extra relation_constraint voalack_lifetime.alert_lifetimes.lab_check"),
    "sequence": ("ALTER SEQUENCE voalack_guard.maintenance_permits_permit_id_seq INCREMENT BY 2",
                 "ALTER SEQUENCE voalack_guard.maintenance_permits_permit_id_seq INCREMENT BY 1",
                 "differs sequence voalack_guard.maintenance_permits_permit_id_seq"),
    "attachment": ("ALTER TABLE voalack.bindings DISABLE TRIGGER bindings_guard",
                   "ALTER TABLE voalack.bindings ENABLE TRIGGER bindings_guard",
                   "differs attachment voalack.bindings.bindings_guard"),
}


# r3 review: the raw catalog fact of each constructed drift, asserted present before the inventory is consulted, so an
# empty inventory there means the drift exists but is not seen (never that it was not constructed)
CONSTRUCTED_RAW = {
    "namespace": "SELECT has_schema_privilege('voalack_app', 'voalack_lifetime', 'CREATE')",
    "column": "SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'voalack_lifetime.alert_lifetimes'::regclass "
              "AND attname = 'lab_extra' AND NOT attisdropped)",
    "constraint": "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'voalack_lifetime.alert_lifetimes'::regclass "
                  "AND conname = 'lab_check')",
    "sequence": "SELECT seqincrement = 2 FROM pg_sequence "
                "WHERE seqrelid = 'voalack_guard.maintenance_permits_permit_id_seq'::regclass",
    "attachment": "SELECT tgenabled = 'D' FROM pg_trigger WHERE tgrelid = 'voalack.bindings'::regclass "
                  "AND tgname = 'bindings_guard'",
}
assert set(CONSTRUCTED_RAW) == set(CONSTRUCTED)


@pytest.mark.parametrize("kind", list(CONSTRUCTED))
def test_constructed_drift_is_reported_refused_at_admission_and_by_reapply(client, app, kind):
    """[lab, DISCLOSED BYPASS on the lab database] The event triggers are disabled only to construct the drift and to
    undo it; while the drift is checked they are enabled, so the shared inventory reports exactly this one item, the
    gate refuses the ACK and an installed reapply refuses (never repairs). Re-enabling and the undo run unconditionally."""
    alert_id = new_alert(client)
    make, undo, item = CONSTRUCTED[kind]

    def guard(state):
        for name in GUARD_EVENT_TRIGGERS:
            sql(f"ALTER EVENT TRIGGER {name} {state}", fetch=False)
    assert inventory_problems() == []
    try:
        guard("DISABLE")
        sql(make, fetch=False)
        guard("ENABLE")
        assert sql(CONSTRUCTED_RAW[kind])[0][0] is True, kind                 # the raw drift is present
        assert inventory_problems() == [item]
        assert sql("SELECT voalack.protections_intact()")[0][0] is False
        response = ack(client, alert_id)
        assert response.status_code == 503 and "protections not intact" in response.get_data(as_text=True)
        with pytest.raises(psycopg2.Error) as exc:
            _reapply()
        assert "drifted; reapply refused" in str(exc.value), exc.value
        assert inventory_problems() == [item]                  # not repaired
    finally:
        try:
            guard("DISABLE")
            sql(undo, fetch=False)
        finally:
            guard("ENABLE")
    assert inventory_problems() == []
    assert status(alert_id)[0] == "open"


# --- Alerta 9.1.0 startup with the protector active ------------------------------------------------------------------

def test_alerta_starts_against_an_installed_database_with_the_protector_active(app):
    # Voalack's create_app wraps Alerta's factory (Alerta's own startup DDL runs under the guard), then installs the
    # boundary and re-enables Voalack's loggers, which Alerta's logging dictConfig disables for every later test.
    from conftest import CONFIG
    from voalack.boundary import create_app
    assert sql("SELECT count(*) FROM pg_event_trigger WHERE evtname = ANY(%s) AND evtenabled = 'O'",
               (list(GUARD_EVENT_TRIGGERS),))[0][0] == 2
    assert inventory_problems() == []                          # the guard is enabled and intact before startup
    started = create_app(config_override=CONFIG)                # Alerta's pinned factory and its DDL, under the guard
    assert started is not None
    assert inventory_problems() == []
    import logging
    assert not logging.getLogger("voalack.boundary").disabled  # logger canary: later tests keep their records
