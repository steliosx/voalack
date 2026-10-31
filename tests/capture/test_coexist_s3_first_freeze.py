"""Coexistence 3a S3a F7: the first guard freeze takes its expectations from the packaged source expectation
(guard_expected.sql), never from the installed state.

A populated accepted-S2 installation (the 8a86377a schema, vendored unchanged as
fixtures/schema_coexist_s2_8a86377a.sql, over the minimal Alerta stub) upgrades to S3a and freezes exactly the packaged
expectation. The same upgrade with one installed lifetime fact changed beforehand (a disabled or same-name changed
lifetime trigger, or a pre-existing runtime grant on a lifetime function or table) is refused in the one apply
transaction: no voalack_guard schema afterwards, the changed fact and every row unchanged, nothing repaired."""
import hashlib
import json
import os
import uuid

import psycopg2
import pytest

from conftest import DSN
from test_t04_s3a_upgrade import STUB_ALERTA
from voalack import schema

S2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "schema_coexist_s2_8a86377a.sql")
S2_SHA256 = "e02a283e2f445b5b2bc00ec148dc0c15a0e09a5e3e26a594cf65285fd3259b79"
REFUSED = "match no approved predecessor phase; first install refused before any change"
PARTIAL = "pre-existing or partial guard state on first install; refused before any change"
RELEASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "schema_release_4d70e69c.sql")
RELEASE_SHA256 = "51f21eb9c65aa673a0ab4b79a45ffdf37760ad97b42430d5b5665697bd16a338"
OLD_T04 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "schema_s2_73ed54e.sql")


def _q(dsn, statement, args=None, fetch=True):
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(statement, args) if args is not None else cur.execute(statement)
        return cur.fetchall() if fetch else None


@pytest.fixture
def phase_db():
    """Factory: a fresh database with the Alerta stub and a vendored predecessor schema (sha256 checked), populated
    with three alerts; dropped afterwards."""
    made = []
    admin = psycopg2.connect(DSN)
    admin.autocommit = True

    def make(path, digest=None):
        source = open(path, "rb").read()
        if digest:
            assert hashlib.sha256(source).hexdigest() == digest
        name = f"voalack_phase_{uuid.uuid4().hex[:8]}"
        admin.cursor().execute(f"CREATE DATABASE {name}")
        made.append(name)
        dsn = DSN.rsplit("/", 1)[0] + "/" + name
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(STUB_ALERTA)
            cur.execute(source.decode("utf-8"))
            for i in range(3):
                cur.execute("INSERT INTO public.alerts (id, status, resource, event, environment, origin, create_time) "
                            "VALUES (%s, 'open', %s, 'lab-event', 'Production', 'lab', now())",
                            (f"phase-alert-{i}", f"lab-resource-{i}"))
        return dsn
    try:
        yield make
    finally:
        for name in made:
            admin.cursor().execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.close()


@pytest.fixture
def s2_db():
    with open(S2, "rb") as handle:
        source = handle.read()
    assert hashlib.sha256(source).hexdigest() == S2_SHA256
    name = f"voalack_s2up_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    dsn = DSN.rsplit("/", 1)[0] + "/" + name
    try:
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(STUB_ALERTA)
            cur.execute(source.decode("utf-8"))                              # the accepted S2 installation
            cur.execute("INSERT INTO voalack.instance_config VALUES ('s2up-inst', 's2up-cred', 'fake-one/v1', 1)")
            for i in range(3):                                                # populated: alerts under the S2 triggers
                cur.execute("INSERT INTO public.alerts (id, status, resource, event, environment, origin, create_time) "
                            "VALUES (%s, 'open', %s, 'lab-event', 'Production', 'lab', now())",
                            (f"s2up-alert-{i}", f"lab-resource-{i}"))
        yield dsn
    finally:
        admin.cursor().execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.close()


def _apply(dsn):
    conn = psycopg2.connect(dsn)
    try:
        schema.apply(conn)
        conn.commit()
    except Exception as exc:
        # q4: an inert snapshot of the SAME exception's diagnostics, taken before rollback/close (read by
        # _bootstrap_problems only); the exception itself is re-raised unchanged.
        exc.voalack_snapshot = {"primary": getattr(getattr(exc, "diag", None), "message_primary", None),
                                "pgerror": getattr(exc, "pgerror", None), "text": str(exc)}
        conn.rollback()
        raise
    finally:
        conn.close()


def _apply_phase(dsn):
    """schema.apply's steps in one transaction, reading the admitted predecessor phase (a transaction-local outcome
    recorded by guard_admit.sql) before the commit."""
    schema.verify_packaged_expectations()
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute(schema.full_sql())
            cur.execute("SELECT current_setting('voalack.predecessor_phase', true)")
            phase = cur.fetchone()[0]
        conn.commit()
        return phase
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


STATE = ("SELECT to_regnamespace('voalack_guard') IS NOT NULL, "
         "(SELECT count(*) FROM public.alerts), (SELECT count(*) FROM voalack_lifetime.alert_lifetimes), "
         "(SELECT count(*) FROM voalack_lifetime.migrations), "
         "(SELECT array_agg(tgname || ':' || tgenabled::text || ':' || pg_get_triggerdef(oid) ORDER BY tgname) FROM pg_trigger "
         " WHERE tgrelid = 'voalack_lifetime.alert_lifetimes'::regclass AND NOT tgisinternal), "
         "(SELECT proacl::text FROM pg_proc WHERE oid = 'voalack_lifetime.only_close()'::regprocedure), "
         "(SELECT relacl::text FROM pg_class WHERE oid = 'voalack_lifetime.alert_lifetimes'::regclass)")


def test_a_pristine_populated_s2_installation_upgrades_and_freezes_the_packaged_expectation(s2_db):
    assert _q(s2_db, STATE)[0][0] is False and _q(s2_db, STATE)[0][1] == 3        # no guard; three alerts
    assert _apply_phase(s2_db) == "8a86377a"
    assert list(_q(s2_db, "SELECT voalack_guard.inventory_problems()")[0][0]) == []
    # the frozen rows of the literal kinds are exactly the packaged expectation (loaded again, compared, rolled back)
    from importlib.resources import files
    expected_sql = files("voalack").joinpath("sql", "guard_expected.sql").read_text(encoding="utf-8")
    conn = psycopg2.connect(s2_db)
    try:
        with conn.cursor() as cur:
            cur.execute(expected_sql)
            cur.execute("SELECT count(*) FROM pg_temp.voalack_expected_inventory")
            n = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM ((SELECT kind, name, attrs FROM pg_temp.voalack_expected_inventory "
                        "EXCEPT SELECT kind, name, attrs FROM voalack_guard.frozen_inventory) UNION ALL "
                        "(SELECT kind, name, attrs FROM voalack_guard.frozen_inventory WHERE kind IN "
                        "(SELECT DISTINCT kind FROM pg_temp.voalack_expected_inventory) EXCEPT "
                        "SELECT kind, name, attrs FROM pg_temp.voalack_expected_inventory)) d")
            assert n > 0 and cur.fetchone()[0] == 0
    finally:
        conn.rollback()
        conn.close()


DRIFT = {
    "disabled-close-trigger": "ALTER TABLE voalack_lifetime.alert_lifetimes DISABLE TRIGGER alert_lifetimes_only_close",
    "changed-close-trigger": "DROP TRIGGER alert_lifetimes_only_close ON voalack_lifetime.alert_lifetimes; "
                             "CREATE TRIGGER alert_lifetimes_only_close BEFORE UPDATE ON voalack_lifetime.alert_lifetimes "
                             "FOR EACH ROW WHEN (false) EXECUTE FUNCTION voalack_lifetime.only_close()",
    "lifetime-function-grant": "GRANT EXECUTE ON FUNCTION voalack_lifetime.only_close() TO voalack_app",
    "lifetime-table-grant": "GRANT SELECT ON voalack_lifetime.alert_lifetimes TO voalack_app",
    # a missing required predecessor object is refused, never created by the schema's initial-create SQL
    "missing-close-trigger": "DROP TRIGGER alert_lifetimes_only_close ON voalack_lifetime.alert_lifetimes",
    "missing-a1-bindings-guard": "DROP TRIGGER bindings_guard ON voalack.bindings",
}


@pytest.mark.parametrize("change", list(DRIFT))
def test_a_drifted_s2_installation_is_refused_at_first_freeze(s2_db, change):
    _q(s2_db, DRIFT[change], fetch=False)                                     # the installed fact, changed before 3a
    before = _q(s2_db, STATE)
    assert before[0][0] is False
    with pytest.raises(psycopg2.Error) as exc:
        _apply(s2_db)
    assert REFUSED in str(exc.value), exc.value
    assert _q(s2_db, STATE) == before                                         # no guard, nothing repaired or changed


def test_the_packaged_expectation_was_generated_from_this_exact_source():
    """A stale literal fails here, before any database: the sha256 recorded in guard_expected.sql's header for each
    source file it was derived from must equal the packaged file."""
    import re
    from importlib.resources import files
    sql_dir = files("voalack").joinpath("sql")
    text = sql_dir.joinpath("guard_expected.sql").read_text(encoding="utf-8")
    for name in ("guard_pre.sql", "schema.sql", "guard_post.sql"):
        recorded = re.search(rf"^-- derived-from {re.escape(name)} sha256 ([0-9a-f]{{64}})$", text, re.M)
        assert recorded, name
        assert recorded.group(1) == hashlib.sha256(sql_dir.joinpath(name).read_bytes()).hexdigest(), name


def test_the_packaged_phases_were_generated_from_this_exact_source_and_preparation():
    """guard_phases.sql records guard_pre.sql's and the packaged preparation step's exact bytes, and the three
    approved phases (the prepared phase's sources are the release fixture then lifetime_prepare.sql)."""
    import re
    from importlib.resources import files
    sql_dir = files("voalack").joinpath("sql")
    text = sql_dir.joinpath("guard_phases.sql").read_text(encoding="utf-8")
    for name in ("guard_pre.sql", "lifetime_prepare.sql"):
        recorded = re.search(rf"^-- derived-from {re.escape(name)} sha256 ([0-9a-f]{{64}})$", text, re.M)
        assert recorded, name
        assert recorded.group(1) == hashlib.sha256(sql_dir.joinpath(name).read_bytes()).hexdigest(), name
    phases = dict(re.findall(r"^-- phase (\S+) sources (.*) \(rows \d+\)$", text, re.M))
    assert sorted(phases) == ["4d70e69c", "4d70e69c-prepared", "8a86377a"]
    assert f"schema_release_4d70e69c.sql sha256 {RELEASE_SHA256}" in phases["4d70e69c"]
    assert f"schema_coexist_s2_8a86377a.sql sha256 {S2_SHA256}" in phases["8a86377a"]
    prepared = phases["4d70e69c-prepared"].split(", ")
    assert prepared[0] == f"schema_release_4d70e69c.sql sha256 {RELEASE_SHA256}"
    prep = hashlib.sha256(sql_dir.joinpath("lifetime_prepare.sql").read_bytes()).hexdigest()
    assert prepared[1] == f"lifetime_prepare.sql sha256 {prep}"



GUARD_STATE = ("SELECT to_regnamespace('voalack_guard') IS NOT NULL, "
               "(SELECT nspowner::regrole::text || '|' || coalesce(nspacl::text, 'default') FROM pg_namespace "
               " WHERE nspname = 'voalack_guard'), "
               "(SELECT count(*) FROM pg_class WHERE relnamespace = to_regnamespace('voalack_guard')), "
               "(SELECT count(*) FROM public.alerts)")
# A before/after fingerprint of these measured guard-namespace facets (not every catalog attribute): schema owner/ACL,
# every relation (kind, owner, raw ACL),
# columns (type, NOT NULL, default), constraints, indexes, sequences, and the alert count.
GUARD_FINGERPRINT = (
    "SELECT (SELECT nspowner::regrole::text || '|' || coalesce(nspacl::text, 'default') FROM pg_namespace "
    "        WHERE nspname = 'voalack_guard'), "
    "(SELECT string_agg(c.relname || ':' || c.relkind::text || ':' || c.relowner::regrole::text || ':' "
    "        || coalesce(c.relacl::text, 'default'), ',' ORDER BY c.relname) "
    "   FROM pg_class c WHERE c.relnamespace = to_regnamespace('voalack_guard')), "
    "(SELECT string_agg(c.relname || '.' || a.attname || ':' || format_type(a.atttypid, a.atttypmod) || ':' "
    "        || a.attnotnull::text || ':' || coalesce(pg_get_expr(d.adbin, d.adrelid), 'nodefault'), ',' "
    "        ORDER BY c.relname, a.attnum) "
    "   FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
    "   LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
    "  WHERE c.relnamespace = to_regnamespace('voalack_guard') AND c.relkind = 'r' AND a.attnum > 0 "
    "    AND NOT a.attisdropped), "
    "(SELECT string_agg(co.conname || ':' || pg_get_constraintdef(co.oid), ',' ORDER BY co.conname) "
    "   FROM pg_constraint co WHERE co.connamespace = to_regnamespace('voalack_guard')), "
    "(SELECT string_agg(pg_get_indexdef(i.indexrelid), ',' ORDER BY i.indexrelid::regclass::text) "
    "   FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid WHERE c.relnamespace = to_regnamespace('voalack_guard')), "
    "(SELECT string_agg(sq.seqrelid::regclass::text || ':' || sq.seqincrement || ':' || sq.seqstart, ',' "
    "        ORDER BY sq.seqrelid::regclass::text) "
    "   FROM pg_sequence sq JOIN pg_class c ON c.oid = sq.seqrelid "
    "  WHERE c.relnamespace = to_regnamespace('voalack_guard')), "
    "(SELECT count(*) FROM public.alerts)")


def test_a_pristine_release_installation_upgrades(phase_db):
    """The real predecessor: the 4d70e69c release (no lifetime, no guard) is admitted and freezes the expectation."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    assert _apply_phase(dsn) == "4d70e69c"
    assert list(_q(dsn, "SELECT voalack_guard.inventory_problems()")[0][0]) == []


def _prepare(dsn):
    """The documented lifetime preparation step (contract r8 section 7), committed on its own before the upgrade."""
    conn = psycopg2.connect(dsn)
    try:
        schema.prepare_lifetime_migration(conn)
    finally:
        conn.close()


def test_a_release_after_the_lifetime_preparation_step_is_admitted_as_the_prepared_phase(phase_db):
    """An operator ran the separately committed preparation step on the release (to record collision dispositions):
    its exact objects are the approved phase 4d70e69c-prepared, not partial state."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    _prepare(dsn)
    assert _q(dsn, "SELECT to_regclass('voalack_lifetime.migration_dispositions') IS NOT NULL")[0][0] is True
    assert _apply_phase(dsn) == "4d70e69c-prepared"
    assert list(_q(dsn, "SELECT voalack_guard.inventory_problems()")[0][0]) == []


PREPARE_REFUSED = "the lifetime preparation step runs only on a pre-lifetime installation; refused before any change"
PREPARED_STATE = (
    "SELECT to_regnamespace('voalack_guard') IS NOT NULL, "
    "(SELECT pg_get_userbyid(nspowner) || '|' || coalesce(nspacl::text, 'NULL') FROM pg_namespace "
    " WHERE nspname = 'voalack_lifetime'), "
    "(SELECT array_agg(p.oid::regprocedure::text || ':' || md5(p.prosrc) || ':' || pg_get_userbyid(p.proowner) || ':' "
    " || coalesce(p.proacl::text, 'NULL') || ':' || p.prosecdef::text || ':' || coalesce(p.proconfig::text, 'NULL') "
    " ORDER BY p.oid::regprocedure::text) FROM pg_proc p WHERE p.pronamespace IN (to_regnamespace('voalack_lifetime'), "
    " to_regnamespace('voalack'))), "
    "(SELECT array_agg(c.relname || ':' || c.relkind::text || ':' || pg_get_userbyid(c.relowner) || ':' "
    " || coalesce(c.relacl::text, 'NULL') ORDER BY c.relname) FROM pg_class c "
    " WHERE c.relnamespace = to_regnamespace('voalack_lifetime')), "
    "(SELECT array_agg(t.tgrelid::regclass::text || ':' || t.tgname || ':' || t.tgenabled::text || ':' "
    " || pg_get_triggerdef(t.oid) ORDER BY t.tgrelid::regclass::text, t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
    " WHERE NOT t.tgisinternal AND c.relnamespace IN (to_regnamespace('voalack_lifetime'), to_regnamespace('voalack'))), "
    "(SELECT CASE WHEN to_regclass('voalack_lifetime.migration_dispositions') IS NULL THEN 'absent' ELSE "
    " (xpath('/row/x/text()', query_to_xml('SELECT string_agg(d::text, ''|'' ORDER BY d::text) AS x "
    "  FROM voalack_lifetime.migration_dispositions d', false, true, '')))[1]::text END), "
    "(SELECT count(*) FROM public.alerts)")


def _prepared_release(phase_db):
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    _prepare(dsn)
    _q(dsn, "INSERT INTO voalack_lifetime.migration_dispositions (alert_id, disposition, actor, basis) "
            "VALUES ('lab-collision', 'reserve_collision', 'lab-operator', 'lab: prepared phase')", fetch=False)
    return dsn


def test_a_prepared_release_keeps_its_operator_dispositions_through_the_upgrade(phase_db):
    """The disposition rows are data, not part of the protected profile: they survive admission and the freeze."""
    dsn = _prepared_release(phase_db)
    rows = _q(dsn, "SELECT d::text FROM voalack_lifetime.migration_dispositions d")
    assert _apply_phase(dsn) == "4d70e69c-prepared"
    assert _q(dsn, "SELECT d::text FROM voalack_lifetime.migration_dispositions d") == rows


@pytest.mark.parametrize("stage", ["fresh", "s2", "prepared-again"])
def test_the_preparation_step_refuses_anywhere_but_a_pre_lifetime_installation(phase_db, stage):
    """Fresh (no voalack schema), the S2 stage (lifetime already installed) and a repeated preparation are refused
    before any change: the step never normalises lifetime state that admission then compares."""
    if stage == "fresh":
        name = f"voalack_phase_{uuid.uuid4().hex[:8]}"
        admin = psycopg2.connect(DSN)
        admin.autocommit = True
        admin.cursor().execute(f"CREATE DATABASE {name}")
        dsn = DSN.rsplit("/", 1)[0] + "/" + name
        try:
            with pytest.raises(psycopg2.Error) as exc:
                _prepare(dsn)
            assert PREPARE_REFUSED in str(exc.value), exc.value
            assert _q(dsn, "SELECT to_regnamespace('voalack_lifetime') IS NULL")[0][0] is True
        finally:
            admin.cursor().execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
            admin.close()
        return
    dsn = phase_db(S2, S2_SHA256) if stage == "s2" else _prepared_release(phase_db)
    before = _q(dsn, PREPARED_STATE)
    with pytest.raises(psycopg2.Error) as exc:
        _prepare(dsn)
    assert PREPARE_REFUSED in str(exc.value), exc.value
    assert _q(dsn, PREPARED_STATE) == before
    assert _apply_phase(dsn) == ("8a86377a" if stage == "s2" else "4d70e69c-prepared")


PREPARED_DRIFT = {
    "missing-hook": "DROP TRIGGER migration_dispositions_no_truncate ON voalack_lifetime.migration_dispositions",
    "disabled-hook": "ALTER TABLE voalack_lifetime.migration_dispositions "
                     "DISABLE TRIGGER migration_dispositions_immutable",
    "repointed-hook": "DROP TRIGGER migration_dispositions_immutable ON voalack_lifetime.migration_dispositions; "
                      "CREATE TRIGGER migration_dispositions_immutable BEFORE UPDATE OR DELETE "
                      "ON voalack_lifetime.migration_dispositions FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change()",
    "function-body": "CREATE OR REPLACE FUNCTION voalack_lifetime.refuse_change() RETURNS trigger LANGUAGE plpgsql "
                     "SET search_path = pg_catalog, pg_temp AS $$ BEGIN RETURN NEW; END; $$",
    "function-owner": "ALTER FUNCTION voalack_lifetime.refuse_change() OWNER TO voalack_app",
    "table-owner": "ALTER TABLE voalack_lifetime.migration_dispositions OWNER TO voalack_app",
    "public-grant": "GRANT EXECUTE ON FUNCTION voalack_lifetime.refuse_change() TO PUBLIC",
    "runtime-grant": "GRANT INSERT ON voalack_lifetime.migration_dispositions TO voalack_app",
    "schema-grant": "GRANT CREATE ON SCHEMA voalack_lifetime TO voalack_app",
    "extra-object": "CREATE TABLE voalack_lifetime.lab_extra (x int); "
                    "ALTER TABLE voalack_lifetime.lab_extra OWNER TO voalack_admin",
    "partial": "DROP TABLE voalack_lifetime.migration_dispositions",
}


@pytest.mark.parametrize("change", list(PREPARED_DRIFT))
def test_a_drifted_prepared_release_is_refused_before_any_change(phase_db, change):
    """A prepared release whose preparation objects then drifted (or are partial or have extras) matches no approved
    phase: admission refuses before normalisation, and the raw state is unchanged afterwards."""
    dsn = _prepared_release(phase_db)
    _q(dsn, PREPARED_DRIFT[change], fetch=False)
    before = _q(dsn, PREPARED_STATE)
    with pytest.raises(psycopg2.Error) as exc:
        _apply(dsn)
    assert REFUSED in str(exc.value), exc.value
    assert _q(dsn, PREPARED_STATE) == before


def test_the_preparation_step_refuses_a_stale_package_before_any_sql(monkeypatch, phase_db):
    """The preparation step runs the packaged integrity check (binding lifetime_prepare.sql's bytes) before its SQL:
    with a stale package it raises before opening a cursor or committing (a lab connection records every call), and
    the database it would have prepared is unchanged."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    facts = ("SELECT to_regnamespace('voalack_lifetime') IS NULL, (SELECT count(*) FROM pg_proc p JOIN pg_namespace n "
             "ON n.oid = p.pronamespace WHERE n.nspname LIKE 'voalack%'), (SELECT count(*) FROM pg_class c "
             "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname LIKE 'voalack%')")
    before = _q(dsn, facts)
    calls = []

    class Conn:
        def cursor(self):
            calls.append("cursor")
            raise AssertionError("no SQL may be issued")

        def commit(self):
            calls.append("commit")
            raise AssertionError("nothing may be committed")

    def stale():
        raise schema.PackageIntegrityError("lab: stale")
    monkeypatch.setattr(schema, "verify_packaged_expectations", stale)
    with pytest.raises(schema.PackageIntegrityError):
        schema.prepare_lifetime_migration(Conn())
    assert calls == []
    assert _q(dsn, facts) == before and before[0][0] is True


RELEASE_DRIFT = {
    "capture-body": "CREATE OR REPLACE FUNCTION voalack.capture_ack() RETURNS trigger LANGUAGE plpgsql "
                    "SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$ BEGIN RETURN NEW; END $$",
    "capture-owner": "ALTER FUNCTION voalack.capture_ack() OWNER TO voalack_app",
    "capture-public-execute": "GRANT EXECUTE ON FUNCTION voalack.capture_ack() TO PUBLIC",
}
RELEASE_FACTS = ("SELECT md5(prosrc), pg_get_userbyid(proowner), coalesce(proacl::text, 'default') FROM pg_proc "
                 "WHERE oid = 'voalack.capture_ack()'::regprocedure")


@pytest.mark.parametrize("change", list(RELEASE_DRIFT))
def test_a_drifted_release_installation_is_refused_before_any_change(phase_db, change):
    """The old apply would have normalized each of these (replaced the body, reset the owner, revoked PUBLIC); the
    admission refuses first, so the drifted fact is still there afterwards and no guard exists."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    _q(dsn, RELEASE_DRIFT[change], fetch=False)
    before = (_q(dsn, RELEASE_FACTS), _q(dsn, GUARD_STATE))
    with pytest.raises(psycopg2.Error) as exc:
        _apply(dsn)
    assert REFUSED in str(exc.value), exc.value
    assert (_q(dsn, RELEASE_FACTS), _q(dsn, GUARD_STATE)) == before


PLANT_TABLES = ("recovery_windows", "executor_backends", "recovery_journal", "maintenance_permits")
BOOTSTRAP_PROBLEMS_PREFIX = ("voalack: installed protected objects do not match the approved source expectation; "
                             "bootstrap refused, no freeze committed: ")   # q4: distinct from the S3a r7 BOOTSTRAP_REFUSED below


def _permits_plant():
    """guard_pre.sql's own CREATE TABLE statements for maintenance_permits and its foreign-key closure, in source
    order, plus the one-open index, executed verbatim. Fail-closed at this source: each statement is found exactly
    once, every REFERENCES target is inside the planted set, and guard_pre.sql has no other statement that changes
    these tables' shape (only OWNER TO, and no other index). It does not prove a future source keeps that property."""
    import re
    from importlib.resources import files
    text = files("voalack").joinpath("sql", "guard_pre.sql").read_text(encoding="utf-8")
    parts = []
    for table in PLANT_TABLES:
        found = re.findall(rf"^CREATE TABLE IF NOT EXISTS voalack_guard\.{table} \(\n.*?^\);$", text, re.M | re.S)
        assert len(found) == 1, (table, len(found))
        refs = set(re.findall(r"REFERENCES voalack_guard\.(\w+)", found[0]))
        assert refs <= set(PLANT_TABLES), (table, refs)
        parts.append(found[0])
    found = re.findall(r"^CREATE UNIQUE INDEX IF NOT EXISTS maintenance_permits_one_open .*?;$", text, re.M | re.S)
    assert len(found) == 1, len(found)
    names = "|".join(PLANT_TABLES)
    indexes = re.findall(rf"^CREATE (?:UNIQUE )?INDEX\b[^;]*\bON voalack_guard\.(?:{names})\b", text, re.M)
    assert len(indexes) == 1, indexes
    alters = re.findall(rf"^ALTER TABLE voalack_guard\.(?:{names})\b[^;]*;", text, re.M)
    assert alters and all(re.fullmatch(r"ALTER TABLE voalack_guard\.\w+ OWNER TO voalack_guard_owner;", a)
                          for a in alters), alters
    return "\n".join(parts + found) + "\n"


def _bootstrap_problems(error):
    """The complete problem list of a bootstrap refusal, from the diagnostics snapshot _apply took on the same exception
    before rollback/close. Source 'diag': a nonempty structured primary message starting with the exact refusal prefix.
    Source 'text': only if the structured primary is empty, the exception text (psycopg2's server text) starting with the
    exact prefix at offset 0, cut only at the exact delimiter '\nCONTEXT:  ', the remaining segment one line (no DETAIL,
    HINT or other lines). A nonempty structured primary must equal that segment whenever both carry the prefix, or this
    refuses. The literal is then parsed strictly: a PostgreSQL text[] of quoted, distinct, sorted entries.
    Returns (problems, source), or None when neither carries the prefix (another error)."""
    import re
    snap = getattr(error, "voalack_snapshot", None)
    assert snap is not None, "no diagnostics snapshot on the exception"
    primary, text = snap["primary"] or "", snap["text"] or ""
    segment = text.split("\nCONTEXT:  ", 1)[0] if text.startswith(BOOTSTRAP_PROBLEMS_PREFIX) else None
    if segment is not None:
        assert "\n" not in segment, f"extra lines before CONTEXT: {segment[:200]!r}"
    if primary.startswith(BOOTSTRAP_PROBLEMS_PREFIX):
        assert segment is None or segment == primary, f"diag primary {primary[:200]!r} != text segment {segment[:200]!r}"
        chosen, source = primary, "diag"
    elif primary:
        assert segment is None, f"diag primary {primary[:200]!r} disagrees with the prefixed text"
        return None
    elif segment is not None:
        chosen, source = segment, "text"
    else:
        return None
    literal = chosen[len(BOOTSTRAP_PROBLEMS_PREFIX):]
    assert re.fullmatch(r'\{"[^"\\]+"(,"[^"\\]+")*\}', literal), f"unparseable bootstrap problems: {literal!r}"
    problems = re.findall(r'"([^"\\]+)"', literal)
    assert problems == sorted(set(problems)), f"duplicate or unordered bootstrap problems: {problems!r}"
    return problems, source


def test_a_preexisting_guard_with_runtime_authority_is_refused_before_any_rewrite(phase_db):
    """The source-shaped permission facet: a guard schema and permits table created before the first install, owned
    as the source would own them but with an explicit runtime mutation grant. Refused by guard_pre's first statement:
    owner, ACL and objects unchanged (nothing revoked, repaired or frozen)."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    # The permits table in the exact source shape of guard_pre.sql, with its foreign-key closure, taken verbatim from
    # the packaged source (_permits_plant), so that without the first-statement refusal the install would proceed
    # past CREATE TABLE IF NOT EXISTS without an incidental shape collision (q4: the S3a-era literal had gone stale).
    _q(dsn, "CREATE SCHEMA voalack_guard AUTHORIZATION voalack_guard_owner; " + _permits_plant() +
            "".join(f"ALTER TABLE voalack_guard.{t} OWNER TO voalack_guard_owner; " for t in PLANT_TABLES) +
            "GRANT USAGE ON SCHEMA voalack_guard TO voalack_app; "
            "GRANT INSERT, UPDATE ON voalack_guard.maintenance_permits TO voalack_app", fetch=False)
    before = _q(dsn, GUARD_FINGERPRINT)
    assert before[0][0] and before[0][1] and before[0][2] and before[0][3], before   # nonempty: owner/ACL/objects
    with pytest.raises(psycopg2.Error) as exc:
        _apply(dsn)
    parsed = _bootstrap_problems(exc.value)
    snap = exc.value.voalack_snapshot
    assert PARTIAL in str(exc.value), (f"bootstrap problems: {json.dumps(parsed[0])}\nproblem source: {parsed[1]}"
                                       if parsed is not None else
                                       f"no bootstrap problems parsed (diagnostic preview only); diag primary "
                                       f"{(snap['primary'] or '')[:200]!r}; text {snap['text'][:200]!r}")
    assert _q(dsn, GUARD_FINGERPRINT) == before


def test_a_pre_existing_guard_schema_with_a_planted_object_is_refused(phase_db):
    """A guard schema created before the first install (with the right owner, so nothing collides) holding an object
    the inventory does not list: without the first-statement refusal it would be adopted silently, since admission
    leaves the guard's own namespace to guard_pre.sql. Refused before any change; the planted object is still there."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    _q(dsn, "CREATE SCHEMA voalack_guard AUTHORIZATION voalack_guard_owner; "
            "CREATE FUNCTION voalack_guard.lab_planted() RETURNS int LANGUAGE sql AS 'SELECT 1'", fetch=False)
    facts = ("SELECT (SELECT count(*) FROM pg_proc WHERE pronamespace = 'voalack_guard'::regnamespace), "
             "to_regclass('voalack_guard.frozen_inventory') IS NULL, "
             "(SELECT count(*) FROM pg_event_trigger WHERE evtname LIKE 'voalack%')")
    before = _q(dsn, facts)
    assert before == [(1, True, 0)]
    with pytest.raises(psycopg2.Error) as exc:
        _apply(dsn)
    assert PARTIAL in str(exc.value), exc.value
    assert _q(dsn, facts) == before


def test_an_intact_historical_installation_with_the_release_profile_is_admitted_as_the_release_phase(phase_db):
    """Decision (a): phase identity is the complete protected profile. An intact older main ancestor (73ed54e) whose
    protected objects are byte-identical to the 4d70e69c release's is admitted as phase 4d70e69c; its non-protected
    objects are then upgraded by schema.sql (the existing historical path). Not a damaged-release witness."""
    dsn = phase_db(OLD_T04)
    selected = _q(dsn, "SELECT count(*) FROM pg_proc WHERE oid IN (to_regprocedure('voalack.capture_ack()'), "
                       "to_regprocedure('voalack.refuse_change()'))")[0][0]
    assert selected == 2                                       # the release profile's functions are installed
    assert _apply_phase(dsn) == "4d70e69c"
    assert list(_q(dsn, "SELECT voalack_guard.inventory_problems()")[0][0]) == []


def test_apply_refuses_a_stale_packaged_expectation_before_any_sql(monkeypatch):
    """The integrity check runs before any SQL: a packaged expectation derived from other source bytes is refused."""
    from voalack import schema as voalack_schema
    calls = []

    class Conn:
        def cursor(self):
            calls.append("cursor")
            raise AssertionError("no SQL may be issued")

    real = voalack_schema.files

    class Fake:
        def __init__(self, inner):
            self.inner = inner

        def joinpath(self, *parts):
            target = self.inner.joinpath(*parts)
            if parts[-1] == "guard_pre.sql":
                return _Bytes(target.read_bytes() + b"-- tampered")
            return Fake(target) if not parts[-1].endswith(".sql") else target

    class _Bytes:
        def __init__(self, data):
            self.data = data

        def read_bytes(self):
            return self.data

    monkeypatch.setattr(voalack_schema, "files", lambda pkg: Fake(real(pkg)))
    with pytest.raises(voalack_schema.PackageIntegrityError):
        voalack_schema.apply(Conn())
    assert calls == []


def _tampered_package(monkeypatch, literal, edit, prepare_bytes=None):
    """Lab: the packaged files as schema.py reads them, with one expectation literal's text edited (and optionally the
    preparation step's bytes changed); every other file is the real packaged one."""
    from voalack import schema as voalack_schema
    real = voalack_schema.files

    class Text:
        def __init__(self, target, text=None, data=None):
            self.target, self.text, self.data = target, text, data

        def read_text(self, encoding="utf-8"):
            return self.text if self.text is not None else self.target.read_text(encoding=encoding)

        def read_bytes(self):
            return self.data if self.data is not None else self.target.read_bytes()

    class Dir:
        def __init__(self, inner):
            self.inner = inner

        def joinpath(self, *parts):
            target = self.inner.joinpath(*parts)
            if parts[-1] == literal:
                return Text(target, text=edit(target.read_text(encoding="utf-8")))
            if prepare_bytes is not None and parts[-1] == "lifetime_prepare.sql":
                return Text(target, text=prepare_bytes.decode(), data=prepare_bytes)
            return target if parts[-1].endswith(".sql") else Dir(target)
    monkeypatch.setattr(voalack_schema, "files", lambda pkg: Dir(real(pkg)))
    return voalack_schema


def _drop(source):
    return lambda text: "\n".join(l for l in text.split("\n") if not l.startswith(f"-- derived-from {source} "))


def _add(line):
    return lambda text: text.replace("-- derived-from guard_pre.sql", line + "\n-- derived-from guard_pre.sql", 1)


def _dup(source):
    def edit(text):
        line = next(l for l in text.split("\n") if l.startswith(f"-- derived-from {source} "))
        return text.replace(line, line + "\n" + line, 1)
    return edit


TAMPER = {
    "expected-missing-guard_pre": ("guard_expected.sql", _drop("guard_pre.sql")),
    "expected-missing-schema": ("guard_expected.sql", _drop("schema.sql")),
    "expected-missing-guard_post": ("guard_expected.sql", _drop("guard_post.sql")),
    "phases-missing-guard_pre": ("guard_phases.sql", _drop("guard_pre.sql")),
    "phases-missing-lifetime_prepare": ("guard_phases.sql", _drop("lifetime_prepare.sql")),
    "phases-foreign-source": ("guard_phases.sql", _add("-- derived-from schema.sql sha256 " + "0" * 64)),
    "expected-duplicate": ("guard_expected.sql", _dup("schema.sql")),
    "phases-path-like": ("guard_phases.sql", _add("-- derived-from ../guard_pre.sql sha256 " + "0" * 64)),
    "expected-malformed": ("guard_expected.sql", _add("-- derived-from guard_pre.sql sha256 not-a-digest")),
}


class _NoSql:
    def __init__(self):
        self.calls = []

    def cursor(self):
        self.calls.append("cursor")
        raise AssertionError("no SQL may be issued")

    def commit(self):
        self.calls.append("commit")
        raise AssertionError("nothing may be committed")


@pytest.mark.parametrize("case", list(TAMPER))
def test_a_tampered_derivation_declaration_is_refused_before_any_sql(monkeypatch, case):
    """r3 review: each expectation must declare exactly its own sources once each. A missing, foreign, duplicated,
    path-like or malformed declaration is refused by both entry points (apply and the preparation step) before a
    cursor is opened."""
    literal, edit = TAMPER[case]
    voalack_schema = _tampered_package(monkeypatch, literal, edit)
    for entry in (voalack_schema.apply, voalack_schema.prepare_lifetime_migration):
        conn = _NoSql()
        with pytest.raises(voalack_schema.PackageIntegrityError):
            entry(conn)
        assert conn.calls == [], (case, entry.__name__, conn.calls)


def test_a_removed_preparation_header_cannot_unbind_changed_preparation_bytes(monkeypatch):
    """The reviewer's counterexample: guard_phases.sql keeps its valid guard_pre.sql declaration but loses the
    lifetime_prepare.sql one, and lifetime_prepare.sql is changed. The preparation step is refused before any SQL."""
    voalack_schema = _tampered_package(monkeypatch, "guard_phases.sql", _drop("lifetime_prepare.sql"),
                                       prepare_bytes=b"SELECT 1; -- lab: changed preparation\n")
    conn = _NoSql()
    with pytest.raises(voalack_schema.PackageIntegrityError):
        voalack_schema.prepare_lifetime_migration(conn)
    assert conn.calls == []


def test_the_untampered_package_passes_the_integrity_check():
    """Control: the real packaged expectations declare exactly their sources and verify."""
    schema.verify_packaged_expectations()


def test_a_release_damaged_to_an_empty_protected_selection_is_refused_not_fresh(phase_db):
    """Fresh requires independent absence (no voalack, voalack_lifetime or voalack_publication schema), not merely an
    empty protected selection. A 4d70e69c installation that lost all four of its selected protected objects (the
    capture trigger and function, voalack.refuse_change() with every trigger that used it, the A1 revision hook) but
    keeps its schema, tables and data is partial project state: refused, raw state unchanged, no guard."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    _q(dsn, "DROP TRIGGER voalack_capture_ack ON public.alerts; DROP FUNCTION voalack.capture_ack(); "
            "DROP FUNCTION voalack.refuse_change() CASCADE", fetch=False)
    raw = ("SELECT (SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'voalack%'), "
           "(SELECT count(*) FROM pg_class WHERE relnamespace = to_regnamespace('voalack')), "
           "(SELECT count(*) FROM pg_proc WHERE pronamespace = to_regnamespace('voalack')), "
           "(SELECT count(*) FROM public.alerts)")
    assert _q(dsn, "SELECT to_regnamespace('voalack') IS NOT NULL")[0][0] is True
    before = (_q(dsn, raw), _q(dsn, GUARD_STATE))
    with pytest.raises(psycopg2.Error) as exc:
        _apply(dsn)
    assert REFUSED in str(exc.value), exc.value
    assert (_q(dsn, raw), _q(dsn, GUARD_STATE)) == before


BOOTSTRAP_REFUSED = "installed protected objects do not match the approved source expectation; bootstrap refused"
LAB_INJECTION = "GRANT EXECUTE ON FUNCTION voalack.alert_ownership() TO PUBLIC"
PUBLIC_EXECUTE = ("SELECT coalesce(bool_or(a.grantee = 0 AND a.privilege_type = 'EXECUTE'), false) "
                  "FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a "
                  "WHERE p.oid = to_regprocedure('voalack.alert_ownership()')")
INSTALL_STATE = ("SELECT to_regnamespace('voalack_guard') IS NOT NULL, "
                 "(SELECT count(*) FROM pg_event_trigger WHERE evtname LIKE 'voalack%'), "
                 "(SELECT proacl::text FROM pg_proc WHERE oid = to_regprocedure('voalack.alert_ownership()')), "
                 "(SELECT count(*) FROM public.alerts)")
# [lab] Embedded positivity check, run right after the injected grant inside the same installer transaction and before
# guard_post.sql: if the grant did not take effect, the batch fails with this distinct setup cause, never with the
# bootstrap refusal and never as a completed apply.
LAB_POSITIVITY = ("DO $lab$ BEGIN IF NOT (" + PUBLIC_EXECUTE + ") THEN RAISE EXCEPTION "
                  "'LAB SETUP: the injected PUBLIC EXECUTE is not present before guard_post.sql'; END IF; END $lab$")


def _sql_with_lab_statement(before_file, statement):
    """[lab] schema.full_sql()'s exact packaged files in schema.ORDER, with one labelled statement inserted immediately
    before `before_file`. Not the product's apply path: the product never takes a hook."""
    from importlib.resources import files
    sql_dir = files("voalack").joinpath("sql")
    parts = []
    for name in schema.ORDER:
        if name == before_file:
            parts.append(statement + ";   -- LAB INJECTION (test-only)")
        parts.append(sql_dir.joinpath(name).read_text(encoding="utf-8"))
    return "\n".join(parts)


def test_a_drift_between_the_schema_and_the_freeze_is_refused_not_frozen(phase_db):
    """The freeze source is the packaged expectation, not live state (r6/c1 remaining-gap disposition): on a guard-free
    release installation, a PUBLIC EXECUTE grant made after all of schema.sql and before guard_post.sql is still a
    mismatch against the package, so the first-freeze bootstrap check refuses and the transaction rolls back. The
    measured facets (guard schema presence, voalack event-trigger count, the function's raw proacl, the alert count,
    PUBLIC EXECUTE) equal their values before. [lab] One transaction as the installer, packaged integrity verified
    first, exactly like _apply_phase; the grant's presence is asserted inside that transaction before guard_post.sql."""
    dsn = phase_db(RELEASE, RELEASE_SHA256)
    schema.verify_packaged_expectations()
    assert _sql_with_lab_statement("no-such-file", "") == schema.full_sql()             # same assembly, no injection
    before = _q(dsn, INSTALL_STATE)
    assert before[0][0] is False and before[0][1] == 0, before                          # guard-free predecessor
    assert _q(dsn, PUBLIC_EXECUTE)[0][0] is False                                       # no PUBLIC EXECUTE before
    conn = psycopg2.connect(dsn)
    try:
        with pytest.raises(psycopg2.Error) as exc:
            with conn.cursor() as cur:
                cur.execute(_sql_with_lab_statement("guard_post.sql", LAB_INJECTION + ";\n" + LAB_POSITIVITY))
        assert "LAB SETUP" not in str(exc.value), exc.value                             # setup cause, not the refusal
        assert BOOTSTRAP_REFUSED in str(exc.value), exc.value
        assert "differs function voalack.alert_ownership()" in str(exc.value), exc.value
        conn.rollback()
    finally:
        conn.close()
    assert _q(dsn, INSTALL_STATE) == before                                             # measured facets restored
    assert _q(dsn, PUBLIC_EXECUTE)[0][0] is False


# --- q4: the planted permits closure cannot go stale ---------------------------------------------------------------------

PLANT_SHAPE = (
    "SELECT c.relname, c.relkind::text, "
    "(SELECT string_agg(a.attname || ':' || format_type(a.atttypid, a.atttypmod) || ':' || a.attnotnull::text || ':' "
    "        || a.attidentity::text || ':' || a.attgenerated::text || ':' || coalesce(co.collname, '-') || ':' "
    "        || coalesce(pg_get_expr(d.adbin, d.adrelid), 'nodefault'), ',' ORDER BY a.attnum) "
    "   FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
    "   LEFT JOIN pg_collation co ON co.oid = a.attcollation "
    "  WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), "
    "(SELECT string_agg(k.conname || ':' || k.contype::text || ':' || pg_get_constraintdef(k.oid), ',' ORDER BY k.conname) "
    "   FROM pg_constraint k WHERE k.conrelid = c.oid), "
    "(SELECT string_agg(pg_get_indexdef(i.indexrelid), ',' ORDER BY i.indexrelid::regclass::text) "
    "   FROM pg_index i WHERE i.indrelid = c.oid), "
    "(SELECT string_agg(sc.relname || ':' || format_type(sq.seqtypid, NULL) || ':' || sq.seqstart || ':' "
    "        || sq.seqincrement || ':' || sq.seqmin || ':' || sq.seqmax || ':' || sq.seqcache || ':' || sq.seqcycle "
    "        || ':' || dp.deptype::text || ':' || at.attname, ',' ORDER BY sc.relname) "
    "   FROM pg_depend dp JOIN pg_class sc ON sc.oid = dp.objid AND sc.relkind = 'S' "
    "   JOIN pg_sequence sq ON sq.seqrelid = sc.oid "
    "   JOIN pg_attribute at ON at.attrelid = dp.refobjid AND at.attnum = dp.refobjsubid "
    "  WHERE dp.classid = 'pg_class'::regclass AND dp.refclassid = 'pg_class'::regclass AND dp.refobjid = c.oid "
    "    AND dp.deptype IN ('a', 'i')) "
    "FROM pg_class c WHERE c.relnamespace = to_regnamespace('voalack_guard') AND c.relname = ANY (%s) ORDER BY c.relname")


def test_the_planted_permits_closure_has_the_installed_shape(phase_db):
    """The plant used by the runtime-authority test (_permits_plant) gives the four tables exactly the columns
    (type, NOT NULL, identity, generated, collation, default), constraints, indexes and owned sequences (parameters
    and dependency type: identity 'i' versus serial 'a') that a complete fresh install gives them. The plant is built
    in its own database under the same schema name, so no namespace is transplanted or renormalized, and this
    catalog query is independent of the extractor and of the guard's inventory functions."""
    installed = phase_db(RELEASE, RELEASE_SHA256)
    _apply(installed)
    planted = phase_db(RELEASE, RELEASE_SHA256)
    _q(planted, "CREATE SCHEMA voalack_guard AUTHORIZATION voalack_guard_owner; " + _permits_plant(), fetch=False)
    want = _q(installed, PLANT_SHAPE, (list(PLANT_TABLES),))
    assert [r[0] for r in want] == sorted(PLANT_TABLES), want
    assert _q(planted, PLANT_SHAPE, (list(PLANT_TABLES),)) == want
