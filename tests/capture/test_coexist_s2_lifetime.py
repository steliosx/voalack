"""Coexistence 3a S2 (contract r8 sections 3-9, 12): alert lifetimes, permanent id reservation, final-row ownership,
enrolment against the live alert, the projection lifetime fence, drift pause and the verifier's audit.

Development checkpoint, not for integration: the DDL protector and the full recovery permit/journal arrive in S3."""
import uuid

import psycopg2
from test_t05b_s3_observer import s4_db  # noqa: F401
import pytest

from conftest import APP_DSN, DSN, OPERATOR, VERIFIER_DSN, ack, basic, captures, guard_bypassed, inventory_problems, new_alert, sql, status  # noqa: E501


def lifetimes(alert_id):
    return sql("SELECT origin, closed_at IS NOT NULL, close_reason FROM voalack_lifetime.alert_lifetimes "
               "WHERE alert_id = %s", (alert_id,))


def foreign_alert(client, alert_id=None):
    body = {"resource": f"zabbix:host-{uuid.uuid4().hex[:8]}", "event": "ZabbixTrigger", "environment": "Development",
            "severity": "major", "service": ["lab"], "text": "synthetic foreign"}
    if alert_id:
        body["id"] = alert_id
    return client.post("/alert", json=body, headers=basic(OPERATOR))


def one_alert_body(alert_id=None):
    suffix = uuid.uuid4().hex[:12]
    body = {"resource": f"veeamone:lab-{suffix}", "event": "VeeamOneAlarm", "environment": "Development",
            "severity": "major", "value": "Error", "service": ["lab"], "text": "synthetic",
            "attributes": {"veeamAlarmCombinationId": f"comb-{suffix}", "captureId": f"cap-{suffix}"}}
    if alert_id:
        body["id"] = alert_id
    return body


LOCK_BOUND = "10s"   # every direct statement is bounded: a blocked witness fails and names its blockers


def _blockers():
    return sql("SELECT pid, state, left(query, 120) FROM pg_stat_activity WHERE datname = current_database() "
               "AND pid <> pg_backend_pid() AND state <> 'idle'")


def raises(statement, args=(), dsn=DSN, isolation=None):
    conn = psycopg2.connect(dsn)
    try:
        if isolation:
            conn.set_session(isolation_level=isolation)
        with conn.cursor() as cur:
            cur.execute(f"SET lock_timeout = '{LOCK_BOUND}'")
            cur.execute(statement, args)
        conn.commit()
        return None
    except psycopg2.Error as exc:
        conn.rollback()
        return str(exc).strip().splitlines()[0]
    finally:
        conn.close()


# --- lifetimes and reservation -------------------------------------------------------------------------------------

def test_a_one_alert_opens_a_lifetime_with_its_create_time(client, app):
    alert_id = new_alert(client, bound=False)
    assert lifetimes(alert_id) == [("insert", False, None)]
    assert sql("SELECT l.alert_create_time = a.create_time FROM voalack_lifetime.alert_lifetimes l "
               "JOIN alerts a ON a.id = l.alert_id WHERE l.alert_id = %s", (alert_id,)) == [(True,)]


def test_a_foreign_alert_opens_no_lifetime(client, app):
    r = foreign_alert(client)
    assert r.status_code == 201, r.get_data(as_text=True)
    assert lifetimes(r.get_json()["id"]) == []


def test_deleting_a_one_alert_closes_its_lifetime_and_retires_its_binding(client, app):
    alert_id = new_alert(client)
    sql("DELETE FROM alerts WHERE id = %s", (alert_id,), fetch=False)
    assert lifetimes(alert_id) == [("insert", True, "alert_deleted")]
    assert sql("SELECT active FROM voalack.bindings WHERE alert_id = %s", (alert_id,)) == [(False,)]
    assert sql("SELECT reason, lifetime_id IS NOT NULL FROM voalack_lifetime.binding_retirements "
               "WHERE alert_id = %s", (alert_id,)) == [("alert_deleted", True)]


@pytest.mark.parametrize("replacement", ["one", "foreign"])
def test_a_deleted_one_id_is_never_reused_through_the_api(client, app, replacement):
    alert_id = new_alert(client)
    sql("DELETE FROM alerts WHERE id = %s", (alert_id,), fetch=False)
    r = (client.post("/alert", json=one_alert_body(alert_id), headers=basic(OPERATOR)) if replacement == "one"
         else foreign_alert(client, alert_id))
    assert r.status_code >= 400, r.get_data(as_text=True)
    assert sql("SELECT count(*) FROM alerts WHERE id = %s", (alert_id,))[0][0] == 0
    assert lifetimes(alert_id) == [("insert", True, "alert_deleted")]           # reservation unchanged


def test_a_reserved_id_is_refused_by_direct_insert_of_any_class(client, app):
    alert_id = new_alert(client, bound=False)
    sql("DELETE FROM alerts WHERE id = %s", (alert_id,), fetch=False)
    err = raises("INSERT INTO alerts (id, resource, event, environment, severity, status, service, \"group\", value, "
                 "text, tags, attributes, origin, type, create_time, timeout, raw_data, customer, duplicate_count, "
                 "repeat, previous_severity, trend_indication, receive_time, last_receive_id, last_receive_time, "
                 "update_time, history) SELECT %s, 'zabbix:x', 'ZabbixTrigger', environment, severity, status, service, "
                 "\"group\", value, text, tags, attributes, origin, type, create_time, timeout, raw_data, customer, "
                 "duplicate_count, repeat, previous_severity, trend_indication, receive_time, last_receive_id, "
                 "last_receive_time, update_time, history FROM alerts LIMIT 1", (alert_id,))
    assert err and "alert id reserved" in err, err


# --- final-row ownership --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["event = 'ZabbixTrigger'", "resource = 'zabbix:host'", "resource = 'veeamone:'",
                                    "create_time = create_time + interval '1 second'"])
def test_a_one_alert_keeps_its_class_and_create_time(client, app, change):
    for bound in (True, False):
        alert_id = new_alert(client, bound=bound)
        err = raises(f"UPDATE alerts SET {change} WHERE id = %s", (alert_id,))
        assert err and "alert ownership is fixed" in err, (bound, err)


def test_a_one_alert_may_change_within_its_class(client, app):
    alert_id = new_alert(client, bound=False)
    assert raises("UPDATE alerts SET resource = 'veeamone:renamed', severity = 'minor' WHERE id = %s", (alert_id,)) is None


def test_a_foreign_alert_cannot_take_a_reserved_id(client, app):
    reserved = new_alert(client, bound=False)
    sql("DELETE FROM alerts WHERE id = %s", (reserved,), fetch=False)
    foreign_id = foreign_alert(client).get_json()["id"]
    err = raises("UPDATE alerts SET id = %s WHERE id = %s", (reserved, foreign_id))
    assert err and "alert id reserved" in err, err
    assert sql("SELECT count(*) FROM alerts WHERE id = %s", (foreign_id,))[0][0] == 1


def test_a_foreign_alert_may_take_a_free_id(client, app):
    foreign_id = foreign_alert(client).get_json()["id"]
    assert raises("UPDATE alerts SET id = %s WHERE id = %s", (str(uuid.uuid4()), foreign_id)) is None


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_alert_creation_and_id_changes_need_read_committed(client, app, isolation):
    one = new_alert(client, bound=False)
    err = raises("INSERT INTO alerts SELECT (jsonb_populate_record(NULL::alerts, to_jsonb(a) || "
                 "jsonb_build_object('id', %s, 'resource', a.resource || '-copy'))).* FROM alerts a WHERE a.id = %s",
                 (str(uuid.uuid4()), one), isolation=isolation)
    assert err and "requires read committed" in err, err
    foreign_id = foreign_alert(client).get_json()["id"]
    err = raises("UPDATE alerts SET id = %s WHERE id = %s", (str(uuid.uuid4()), foreign_id), isolation=isolation)
    assert err and "requires read committed" in err, err


def test_a_stale_snapshot_cannot_reuse_a_reservation(client, app):
    """A REPEATABLE READ snapshot taken before X's whole ONE lifecycle: its foreign insert of X is refused (by the
    isolation rule), never admitted on its stale view."""
    template = foreign_alert(client).get_json()["id"]    # visible to the snapshot below (taken after it exists)
    stale = psycopg2.connect(DSN)
    stale.set_session(isolation_level="REPEATABLE READ")
    cur = stale.cursor()
    cur.execute(f"SET lock_timeout = '{LOCK_BOUND}'")
    cur.execute("SELECT count(*) FROM voalack_lifetime.alert_lifetimes")     # the snapshot is taken here
    x = new_alert(client, bound=False)
    sql("DELETE FROM alerts WHERE id = %s", (x,), fetch=False)
    try:
        with pytest.raises(psycopg2.Error) as exc:
            cur.execute("INSERT INTO alerts SELECT (jsonb_populate_record(NULL::alerts, to_jsonb(a) || "
                        "jsonb_build_object('id', %s, 'resource', a.resource || '-copy'))).* FROM alerts a "
                        "WHERE a.id = %s", (x, template))
    finally:
        stale.rollback()
        stale.close()
    assert "requires read committed" in str(exc.value)
    assert sql("SELECT count(*) FROM alerts WHERE id = %s", (x,))[0][0] == 0


def test_truncating_alerts_is_refused(client, app):
    err = raises("TRUNCATE alerts CASCADE")
    assert err and "cannot be truncated" in err, (err, _blockers())


@pytest.fixture
def later_before_trigger():
    """[lab] a BEFORE trigger that runs after nothing else: rewrites NEW per a session setting, or skips the row."""
    sql("""CREATE OR REPLACE FUNCTION public.lab_rewrite_alert() RETURNS trigger LANGUAGE plpgsql AS $$
           BEGIN
             CASE current_setting('lab.rewrite', true)
               WHEN 'to_foreign' THEN NEW.event := 'ZabbixTrigger'; NEW.resource := 'zabbix:x';
               WHEN 'to_one' THEN NEW.event := 'VeeamOneAlarm'; NEW.resource := 'veeamone:x';
               WHEN 'id' THEN NEW.id := current_setting('lab.id');
               WHEN 'skip' THEN RETURN NULL;
               ELSE NULL;
             END CASE;
             RETURN NEW;
           END $$;
           CREATE TRIGGER zz_lab_rewrite BEFORE INSERT OR UPDATE ON public.alerts
             FOR EACH ROW EXECUTE FUNCTION public.lab_rewrite_alert();""", fetch=False)
    yield
    sql("DROP TRIGGER IF EXISTS zz_lab_rewrite ON public.alerts; DROP FUNCTION IF EXISTS public.lab_rewrite_alert()",
        fetch=False)


def _with(setting, statement, args=()):
    conn = psycopg2.connect(DSN)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET lock_timeout = '{LOCK_BOUND}'")
            for k, v in setting.items():
                cur.execute("SELECT set_config(%s, %s, true)", (k, v))
            cur.execute(statement, args)
        conn.commit()
        return None
    except psycopg2.Error as exc:
        conn.rollback()
        return str(exc).strip().splitlines()[0]
    finally:
        conn.close()


def test_a_later_before_trigger_cannot_change_the_class_on_an_unrelated_update(client, app, later_before_trigger):
    alert_id = new_alert(client, bound=False)
    err = _with({"lab.rewrite": "to_foreign"}, "UPDATE alerts SET severity = 'minor' WHERE id = %s", (alert_id,))
    assert err and "alert ownership is fixed" in err, err
    assert sql("SELECT event FROM alerts WHERE id = %s", (alert_id,)) == [("VeeamOneAlarm",)]


def test_a_later_before_trigger_cannot_move_a_foreign_insert_onto_a_reserved_id(client, app, later_before_trigger):
    reserved = new_alert(client, bound=False)
    sql("DELETE FROM alerts WHERE id = %s", (reserved,), fetch=False)
    template = foreign_alert(client).get_json()["id"]
    err = _with({"lab.rewrite": "id", "lab.id": reserved},
                "INSERT INTO alerts SELECT (jsonb_populate_record(NULL::alerts, to_jsonb(a) || "
                "jsonb_build_object('id', %s, 'resource', a.resource || '-copy'))).* FROM alerts a WHERE a.id = %s",
                (str(uuid.uuid4()), template))
    assert err and "alert id reserved" in err, err


def test_a_later_before_trigger_making_an_insert_one_class_opens_its_lifetime(client, app, later_before_trigger):
    template = foreign_alert(client).get_json()["id"]
    new_id = str(uuid.uuid4())
    assert _with({"lab.rewrite": "to_one"}, "INSERT INTO alerts SELECT (jsonb_populate_record(NULL::alerts, "
                 "to_jsonb(a) || jsonb_build_object('id', %s, 'resource', a.resource || '-copy'))).* FROM alerts a "
                 "WHERE a.id = %s", (new_id, template)) is None
    assert lifetimes(new_id) == [("insert", False, None)]                    # judged on the final row


def test_a_skipped_insert_leaves_no_lifetime(client, app, later_before_trigger):
    one = new_alert(client, bound=False)
    new_id = str(uuid.uuid4())
    assert _with({"lab.rewrite": "skip"}, "INSERT INTO alerts SELECT (jsonb_populate_record(NULL::alerts, "
                 "to_jsonb(a) || jsonb_build_object('id', %s, 'resource', a.resource || '-copy'))).* FROM alerts a "
                 "WHERE a.id = %s", (new_id, one)) is None
    assert sql("SELECT count(*) FROM alerts WHERE id = %s", (new_id,))[0][0] == 0
    assert lifetimes(new_id) == []


# --- enrolment, gate, projection fence, drift, audit ---------------------------------------------------------------

def test_enrolment_needs_a_one_alert_with_a_matching_open_lifetime(client, app):
    foreign_id = foreign_alert(client).get_json()["id"]
    err = raises("SELECT voalack.enroll_binding(%s, %s, 1)", (foreign_id, f"lab-{foreign_id}"))
    assert err and ("revision has no lifetime" in err or "not of the Veeam ONE class" in err), err


def test_a_legacy_binding_never_captures(client, app):
    """A binding whose revision has no lifetime (a pre-migration legacy revision) refuses until re-enrolled."""
    alert_id = new_alert(client)
    rev = sql("SELECT binding_id, binding_revision FROM voalack.bindings WHERE alert_id = %s", (alert_id,))[0]
    with guard_bypassed("A1 legacy construction: binding_revisions_immutable toggled and restored"):  # S3a A1
        sql("ALTER TABLE voalack.binding_revisions DISABLE TRIGGER USER", fetch=False)   # [lab] simulate legacy
        try:
            sql("UPDATE voalack.binding_revisions SET alert_lifetime_id = NULL "
                "WHERE (binding_id, binding_revision) = (%s, %s)", rev, fetch=False)
        finally:
            sql("ALTER TABLE voalack.binding_revisions ENABLE TRIGGER USER", fetch=False)
    response = ack(client, alert_id)
    assert response.status_code == 503, response.get_data(as_text=True)
    assert "re-enrolment" in response.get_json()["message"]
    assert (status(alert_id)[0], captures(alert_id)) == ("open", 0)


def test_event_lifetime_states(client, app):
    alert_id = new_alert(client)
    assert ack(client, alert_id).status_code == 200
    action = sql("SELECT action_id FROM voalack.captures WHERE alert_id = %s", (alert_id,))[0][0]
    state = lambda: sql("SELECT voalack._event_lifetime_state(%s, %s)", (action, alert_id))[0][0]   # noqa: E731
    assert state() == "current"
    assert sql("SELECT voalack._event_lifetime_state(%s, %s)", (str(uuid.uuid4()), alert_id))[0][0] == "unknown"
    sql("DELETE FROM alerts WHERE id = %s", (alert_id,), fetch=False)
    assert state() == "changed"


def test_projection_pauses_while_a_protection_drifted(client, app):
    epoch, head = sql("SELECT epoch, head_sha256 FROM voalack.recovery_epoch")[0]
    with guard_bypassed("S2 drift witness: projector pause"):          # S3a: drift needs the disclosed bypass
        sql("ALTER TABLE public.alerts DISABLE TRIGGER voalack_alert_ownership", fetch=False)
        assert "differs public_trigger voalack_alert_ownership" in inventory_problems()
        row = sql("SELECT outcome, status FROM voalack.project_next('lab', %s, %s)", (epoch, head))[0]
        intact = sql("SELECT voalack.protections_intact()")[0][0]
    assert (row, intact) == (("paused", "protection_drift"), False)
    assert sql("SELECT voalack.protections_intact()")[0][0] is True


def test_the_audit_is_the_verifiers_alone(client, app):
    with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack.audit_ownership()")
        report = cur.fetchone()[0]
    assert report["protections_intact"] is True and report["bindings_on_non_one_alerts"] == []
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("SELECT voalack.audit_ownership()")


def test_reapply_is_a_no_op_for_lifetimes(client, app):
    import psycopg2 as pg
    from voalack import schema
    new_alert(client, bound=False)
    before = sql("SELECT md5(string_agg(l::text, '|' ORDER BY lifetime_id)) FROM voalack_lifetime.alert_lifetimes l")
    with pg.connect(DSN) as conn:
        schema.apply(conn)
    assert sql("SELECT md5(string_agg(l::text, '|' ORDER BY lifetime_id)) FROM voalack_lifetime.alert_lifetimes l") == before
    assert sql("SELECT count(*) FROM voalack_lifetime.migrations WHERE version = 'lifetime-1'")[0][0] == 1


# --- migration on a populated pre-3a installation --------------------------------------------------------------------

def test_the_lifetime_migration_refuses_collisions_until_each_is_dispositioned(s4_db):
    """The S4 fixture's history names alerts that are not ONE-class (cloned with their own resource). Upgrading refuses
    and lists them. The separate preparation step creates the dispositions table on its own (the refused apply rolled
    back everything it made); once an operator records a disposition for each, the upgrade reserves them as
    collisions, gives current ONE rows lifetimes and records lifetime-1; a second application changes nothing."""
    import psycopg2 as pg
    from test_t05b_s3_observer import _populate_s4, _q
    from voalack import schema
    _populate_s4(s4_db)
    with pg.connect(s4_db.dsn) as conn:
        with pytest.raises(pg.Error) as exc:
            schema.apply(conn)
    assert "need a recorded disposition" in str(exc.value), exc.value
    colliding = sorted(set(_q(s4_db.dsn, "SELECT alert_id FROM voalack.prepared_intents UNION SELECT alert_id FROM "
                                         "voalack_publication.publications")))
    assert colliding and all(a in str(exc.value) for (a,) in colliding[:3]), (colliding[:3], exc.value)
    prep = pg.connect(s4_db.dsn)
    try:
        schema.prepare_lifetime_migration(prep)                # committed on its own
    finally:
        prep.close()
    record = ("INSERT INTO voalack_lifetime.migration_dispositions (alert_id, disposition, actor, basis) "
              "VALUES (%s, 'reserve_collision', 'lab-operator', 'lab: S4 fixture clone')")
    # S3a (prepared phase): a partial set of dispositions is still refused, with the prepared raw state unchanged
    raw = ("SELECT to_regnamespace('voalack_guard') IS NOT NULL, (SELECT array_agg(d::text ORDER BY d::text) FROM "
           "voalack_lifetime.migration_dispositions d), (SELECT array_agg(c.relname::text ORDER BY c.relname) FROM pg_class c "
           "WHERE c.relnamespace = 'voalack_lifetime'::regnamespace), (SELECT count(*) FROM public.alerts)")
    _q(s4_db.dsn, record, (colliding[0][0],), fetch=False)
    before = _q(s4_db.dsn, raw)
    if len(colliding) > 1:
        with pg.connect(s4_db.dsn) as conn:
            with pytest.raises(pg.Error) as exc:
                schema.apply(conn)
        assert "need a recorded disposition" in str(exc.value), exc.value
        assert _q(s4_db.dsn, raw) == before
    with pg.connect(s4_db.dsn) as conn:
        with conn.cursor() as cur:
            for (alert_id,) in colliding[1:]:
                cur.execute(record, (alert_id,))
    dispositions = _q(s4_db.dsn, "SELECT d::text FROM voalack_lifetime.migration_dispositions d ORDER BY 1")
    with pg.connect(s4_db.dsn) as conn:
        schema.apply(conn)
    assert _q(s4_db.dsn, "SELECT d::text FROM voalack_lifetime.migration_dispositions d ORDER BY 1") == dispositions
    assert _q(s4_db.dsn, "SELECT count(*) FROM voalack_lifetime.migrations WHERE version = 'lifetime-1'")[0][0] == 1
    reserved = _q(s4_db.dsn, "SELECT alert_id FROM voalack_lifetime.alert_lifetimes WHERE origin = 'migration_collision'")
    assert sorted(a for (a,) in reserved) == [a for (a,) in colliding]
    before = _q(s4_db.dsn, "SELECT md5(string_agg(l::text, '|' ORDER BY lifetime_id)) FROM voalack_lifetime.alert_lifetimes l")
    history = _q(s4_db.dsn, "SELECT m::text FROM voalack_lifetime.migrations m ORDER BY 1")
    with pg.connect(s4_db.dsn) as conn:
        schema.apply(conn)
    assert _q(s4_db.dsn, "SELECT md5(string_agg(l::text, '|' ORDER BY lifetime_id)) "
                         "FROM voalack_lifetime.alert_lifetimes l") == before
    assert _q(s4_db.dsn, "SELECT m::text FROM voalack_lifetime.migrations m ORDER BY 1") == history
    assert _q(s4_db.dsn, "SELECT d::text FROM voalack_lifetime.migration_dispositions d ORDER BY 1") == dispositions


# --- recovery: the current contract requires all four public-table triggers ---------------------------------------

def _contract():
    from voalack import recovery
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        return recovery.capture_contract(cur)


def _reinstall():
    from voalack import schema
    conn = psycopg2.connect(DSN)
    try:
        schema.apply(conn)
    finally:
        conn.close()


def test_the_current_capture_contract_holds_with_all_four_triggers(client, app):
    assert _contract() == []
    rendered = sql("SELECT voalack.protections_intact(), (SELECT array_agg(d ORDER BY d) FROM ("
                   "SELECT pg_get_triggerdef(t.oid) AS d FROM pg_trigger t WHERE t.tgrelid = 'public.alerts'::regclass "
                   "AND NOT t.tgisinternal) x)")[0]
    assert rendered[0] is True, rendered[1]          # on failure, show the definitions as rendered here


@pytest.mark.parametrize("change, expected", [
    ("DROP TRIGGER voalack_alert_lifetime ON public.alerts", "protection trigger voalack_alert_lifetime absent"),
    ("ALTER TABLE public.alerts DISABLE TRIGGER voalack_alert_ownership",
     "protection trigger voalack_alert_ownership absent or differs"),
    ("DROP TRIGGER voalack_alert_no_truncate ON public.alerts; CREATE TRIGGER voalack_alert_no_truncate "
     "BEFORE TRUNCATE ON public.alerts FOR EACH STATEMENT EXECUTE FUNCTION voalack.alert_ownership()",
     "protection trigger voalack_alert_no_truncate absent or differs"),
    ("CREATE TRIGGER lab_extra AFTER INSERT ON public.alerts FOR EACH ROW EXECUTE FUNCTION voalack.alert_lifetime()",
     "other voalack triggers on public.alerts"),
    # same name, type bits, function and no WHEN, but a deferred constraint trigger (only the definition differs)
    ("DROP TRIGGER voalack_alert_ownership ON public.alerts; CREATE CONSTRAINT TRIGGER voalack_alert_ownership "
     "AFTER UPDATE OR DELETE ON public.alerts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
     "EXECUTE FUNCTION voalack.alert_ownership()",
     "protection trigger voalack_alert_ownership absent or differs"),
    ("DROP TRIGGER voalack_alert_lifetime ON public.alerts; CREATE TRIGGER voalack_alert_lifetime AFTER INSERT ON "
     "public.alerts FOR EACH ROW WHEN (NEW.id IS NOT NULL) EXECUTE FUNCTION voalack.alert_lifetime()",
     "protection trigger voalack_alert_lifetime absent or differs"),
])
def test_missing_extra_or_drifted_protection_is_refused_by_the_capture_contract(client, app, change, expected):
    with guard_bypassed("S2 drift witness: recovery capture contract"):  # S3a: drift needs the disclosed bypass
        try:
            sql(change, fetch=False)
            problems = _contract()
            intact = sql("SELECT voalack.protections_intact()")[0][0]
            assert any(p.startswith(expected) for p in problems), problems
            assert intact is False                               # the projector's drift pause sees it too
        finally:
            sql("DROP TRIGGER IF EXISTS lab_extra ON public.alerts", fetch=False)
    assert _contract() == []


def test_detach_and_recreate_cover_all_four_triggers_and_leave_lifetime_and_publication_data(client, app):
    from voalack import recovery
    new_alert(client)
    names = ("voalack_capture_ack", "voalack_alert_lifetime", "voalack_alert_ownership", "voalack_alert_no_truncate")

    def present():
        return sorted(r[0] for r in sql("SELECT tgname FROM pg_trigger WHERE tgrelid = 'public.alerts'::regclass "
                                        "AND tgname = ANY(%s)", (list(names),)))

    def data():
        return sql("SELECT (SELECT md5(coalesce(string_agg(l::text, '|' ORDER BY lifetime_id), '')) "
                   "FROM voalack_lifetime.alert_lifetimes l), "
                   "(SELECT md5(coalesce(string_agg(p::text, '|' ORDER BY p::text), '')) "
                   "FROM voalack_publication.publications p)")[0]
    before = data()
    # [lab, historical] S3a: the real detach/recreate permits stay closed until the S3b containment exists, so this S2
    # recovery-coverage witness runs its legacy steps under the disclosed bypass; not a qualified recovery operation.
    with guard_bypassed("S2 recovery coverage of the four triggers (legacy detach/recreate)"):
        recovery.detach_capture_trigger(DSN)
        assert present() == []
        recovery.recreate_capture_trigger(DSN)
        assert present() == sorted(names)
        assert sorted(_contract()) == sorted(f"guard: differs event_trigger {n}"      # only the bypass itself
                                             for n in ("voalack_protect_alerts_drop", "voalack_protect_alerts_end"))
        assert data() == before
    assert _contract() == []


# --- permanent evidence: owner-level TRUNCATE refused (r8 section 4; row triggers do not fire on TRUNCATE) ----------

def _seed_permanent_evidence(client):
    """Every permanent lifetime table holds operator-recorded rows: a lifetime (a ONE alert), a retirement (a real
    deletion of a bound ONE alert), lifetime-1 (the schema's migration record), a valid disposition, and an
    attestation through the constrained operator function."""
    new_alert(client)
    retired = new_alert(client)
    sql("DELETE FROM alerts WHERE id = %s", (retired,), fetch=False)
    sql("INSERT INTO voalack_lifetime.migration_dispositions (alert_id, disposition, actor, basis) "
        "VALUES (%s, 'reserve_collision', 'lab-operator', 'lab: nonempty evidence')", (str(uuid.uuid4()),), fetch=False)
    _alert_id, rev, lifetime, _action = _legacy(client)
    assert _attest(rev, lifetime) is None


@pytest.mark.parametrize("table", ["alert_lifetimes", "binding_retirements", "migrations", "migration_dispositions",
                                   "legacy_attestations"])
def test_the_owner_cannot_truncate_permanent_lifetime_evidence(client, app, table):
    _seed_permanent_evidence(client)
    rows = (f"SELECT count(*), md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) "
            f"FROM voalack_lifetime.{table} x")
    marker = "SELECT version, inventory_sha256, applied_at FROM voalack_lifetime.migrations ORDER BY 1"
    before, mark = sql(rows)[0], sql(marker)
    assert before[0] > 0, (table, before)                  # explicitly nonempty operator evidence
    assert [m[0] for m in mark] == ["lifetime-1"]
    err = raises(f"SET ROLE voalack_admin; TRUNCATE voalack_lifetime.{table}")   # the table owner
    assert err and "rows are immutable" in err, err
    after_refusal = (sql(rows)[0], sql(marker))
    _reinstall()                                            # reapply stays a no-op
    after_reapply = (sql(rows)[0], sql(marker))
    from test_t04_s4_shared_restore import _evidence
    _evidence(f"s2-f1-truncate-{table}.json", {"table": table, "refusal": err, "before": before, "marker": mark,
                                               "after_refusal": after_refusal, "after_reapply": after_reapply})
    assert after_refusal == (before, mark) and after_reapply == (before, mark)   # rows, count, lifetime-1 kept


def test_the_prepare_only_dispositions_table_refuses_truncate_before_the_schema(s4_db):
    """The separately committed preparation step (lifetime_prepare.sql) on a pre-3a database, before any 3a schema
    apply: a recorded disposition cannot be truncated by the owner."""
    import psycopg2 as pg
    from test_t05b_s3_observer import _populate_s4, _q
    from voalack import schema
    _populate_s4(s4_db)
    assert _q(s4_db.dsn, "SELECT to_regclass('voalack_lifetime.alert_lifetimes') IS NULL")[0][0] is True
    conn = pg.connect(s4_db.dsn)
    try:
        schema.prepare_lifetime_migration(conn)
    finally:
        conn.close()
    _q(s4_db.dsn, "INSERT INTO voalack_lifetime.migration_dispositions (alert_id, disposition, actor, basis) "
                  "VALUES ('alert-confirmed', 'reserve_collision', 'lab-operator', 'lab: prepare-only')", fetch=False)
    rows = ("SELECT count(*), md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) "
            "FROM voalack_lifetime.migration_dispositions x")
    before = _q(s4_db.dsn, rows)[0]
    assert before[0] == 1
    err = raises("SET ROLE voalack_admin; TRUNCATE voalack_lifetime.migration_dispositions", dsn=s4_db.dsn)
    assert err and "rows are immutable" in err, err
    after = _q(s4_db.dsn, rows)[0]
    from test_t04_s4_shared_restore import _evidence
    _evidence("s2-f1-prepare-only-dispositions.json", {"refusal": err, "before": before, "after": after})
    assert after == before
    assert _q(s4_db.dsn, "SELECT to_regclass('voalack_lifetime.alert_lifetimes') IS NULL")[0][0] is True


# --- the owned ACK path checks the protections under the lock, before any staging -------------------------------

DRIFT_PROBLEMS = {"missing": "missing public_trigger voalack_alert_lifetime",
                  "disabled": "differs public_trigger voalack_alert_ownership",
                  "repointed": "differs public_trigger voalack_alert_no_truncate",
                  "extra": "extra public_trigger lab_extra",
                  "capture-disabled": "differs public_trigger voalack_capture_ack"}
DRIFT_IDS = ["missing", "disabled", "repointed", "extra", "capture-disabled"]
DRIFTS = [
    "DROP TRIGGER voalack_alert_lifetime ON public.alerts",
    "ALTER TABLE public.alerts DISABLE TRIGGER voalack_alert_ownership",
    "DROP TRIGGER voalack_alert_no_truncate ON public.alerts; CREATE TRIGGER voalack_alert_no_truncate BEFORE "
    "TRUNCATE ON public.alerts FOR EACH STATEMENT EXECUTE FUNCTION voalack.alert_ownership()",
    "CREATE TRIGGER lab_extra AFTER INSERT ON public.alerts FOR EACH ROW EXECUTE FUNCTION voalack.alert_lifetime()",
    "ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack",
]


@pytest.mark.parametrize("drift, kind", list(zip(DRIFTS, DRIFT_IDS)), ids=DRIFT_IDS)
def test_an_owned_ack_is_refused_before_staging_when_a_protection_drifted(client, app, monkeypatch, drift, kind):
    import voalack.boundary as boundary
    alert_id = new_alert(client)                            # a valid, bound ONE alert with its open lifetime
    frozen = []
    freeze = boundary._freeze_gate_facts
    monkeypatch.setattr(boundary, "_freeze_gate_facts", lambda *a, **k: frozen.append(1) or freeze(*a, **k))
    with guard_bypassed(f"S2 gate drift witness: {kind}"):        # S3a: drift needs the disclosed bypass
        try:
            sql(drift, fetch=False)
            assert DRIFT_PROBLEMS[kind] in inventory_problems()      # the specific drift, not only the bypass
            response = ack(client, alert_id)
        finally:
            sql("DROP TRIGGER IF EXISTS lab_extra ON public.alerts", fetch=False)
    assert response.status_code == 503, response.get_data(as_text=True)
    assert "protections not intact" in response.get_json()["message"]
    assert frozen == [] and status(alert_id)[0] == "open"
    assert (captures(alert_id), sql("SELECT count(*) FROM voalack.prepared_intents WHERE alert_id = %s",
                                    (alert_id,))[0][0]) == (0, 0)


@pytest.mark.parametrize("drift, kind", list(zip(DRIFTS[:4], DRIFT_IDS[:4])), ids=DRIFT_IDS[:4])
def test_a_foreign_ack_stays_upstream_while_a_protection_drifted(client, app, drift, kind):
    foreign_id = foreign_alert(client).get_json()["id"]
    with guard_bypassed(f"S2 foreign pass-through under drift: {kind}"):
        try:
            sql(drift, fetch=False)
            assert DRIFT_PROBLEMS[kind] in inventory_problems()
            response = ack(client, foreign_id)
        finally:
            sql("DROP TRIGGER IF EXISTS lab_extra ON public.alerts", fetch=False)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(foreign_id)[0] == "ack"


# --- legacy attestations: recorded operator authority (r8 section 7) ----------------------------------------------

def _legacy(client):
    """[lab] A captured ACK whose binding revision is then made legacy (no recorded lifetime)."""
    alert_id = new_alert(client)
    assert ack(client, alert_id).status_code == 200
    rev = sql("SELECT binding_id, binding_revision FROM voalack.bindings WHERE alert_id = %s", (alert_id,))[0]
    lifetime = sql("SELECT voalack.alert_open_lifetime(%s)", (alert_id,))[0][0]
    with guard_bypassed("A1 legacy construction: binding_revisions_immutable toggled and restored"):  # S3a A1
        sql("ALTER TABLE voalack.binding_revisions DISABLE TRIGGER USER", fetch=False)
        try:
            sql("UPDATE voalack.binding_revisions SET alert_lifetime_id = NULL "
                "WHERE (binding_id, binding_revision) = (%s, %s)", rev, fetch=False)
        finally:
            sql("ALTER TABLE voalack.binding_revisions ENABLE TRIGGER USER", fetch=False)
    action = sql("SELECT action_id FROM voalack.captures WHERE alert_id = %s", (alert_id,))[0][0]
    return alert_id, rev, lifetime, action


def _attest(rev, lifetime, actor="lab-operator", dsn=DSN):
    return raises("SET ROLE voalack_admin; SELECT voalack.attest_legacy_revision(%s, %s, %s, %s, 'lab basis')",
                  (rev[0], rev[1], lifetime, actor), dsn=dsn)


def test_a_legacy_revision_is_unknown_until_an_operator_attests_it(client, app):
    alert_id, rev, lifetime, action = _legacy(client)
    state = lambda: sql("SELECT voalack._event_lifetime_state(%s, %s)", (action, alert_id))[0][0]   # noqa: E731
    assert state() == "unknown"
    assert _attest(rev, lifetime) is None
    assert state() == "current_attested"                       # distinct from revision provenance ('current')
    row = sql("SELECT lifetime_id, actor, basis FROM voalack_lifetime.legacy_attestations "
              "WHERE (binding_id, binding_revision) = (%s, %s)", rev)
    assert row == [(lifetime, "lab-operator", "lab basis")]


def test_attestations_are_immutable_and_validated(client, app):
    alert_id, rev, lifetime, _ = _legacy(client)
    other = new_alert(client)
    other_lifetime = sql("SELECT voalack.alert_open_lifetime(%s)", (other,))[0][0]
    err = _attest(rev, other_lifetime)
    assert err and "not one of the binding alert's lifetimes" in err, err
    assert _attest(rev, lifetime) is None
    err = _attest(rev, lifetime)                                # a repeat
    assert err and "already attested" in err, err
    err = _attest(rev, other_lifetime)                          # a contradiction
    assert err and ("already attested" in err or "not one of" in err), err
    current = sql("SELECT binding_id, binding_revision FROM voalack.bindings WHERE alert_id = %s", (other,))[0]
    err = _attest(current, other_lifetime)                      # a revision that records its own lifetime
    assert err and "not a legacy revision" in err, err
    assert sql("SELECT count(*) FROM voalack_lifetime.legacy_attestations "
               "WHERE (binding_id, binding_revision) = (%s, %s)", rev)[0][0] == 1


def test_runtime_roles_cannot_attest(client, app):
    from conftest import SENDER_DSN
    alert_id, rev, lifetime, _ = _legacy(client)
    for dsn in (APP_DSN, SENDER_DSN, VERIFIER_DSN):
        err = raises("SELECT voalack.attest_legacy_revision(%s, %s, %s, 'x', 'y')", (rev[0], rev[1], lifetime),
                     dsn=dsn)
        assert err and "permission denied" in err, (dsn, err)
        err = raises("INSERT INTO voalack_lifetime.legacy_attestations (binding_id, binding_revision, lifetime_id, "
                     "actor, basis) VALUES (%s, %s, %s, 'x', 'y')", (rev[0], rev[1], lifetime), dsn=dsn)
        assert err and "permission denied" in err, (dsn, err)
    assert sql("SELECT count(*) FROM voalack_lifetime.legacy_attestations "
               "WHERE (binding_id, binding_revision) = (%s, %s)", rev)[0][0] == 0
