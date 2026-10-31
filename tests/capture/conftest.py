"""Capture tests: real Alerta 9.1.0 + PostgreSQL with the Voalack boundary installed."""
import base64
import os
import tempfile
import uuid

import psycopg2
import pytest

# Two lab connections: DSN is the lab-only superuser used by fixtures and observers (never by the
# application); APP_DSN is Alerta's runtime login (owner of Alerta's tables, member of voalack_app).
DSN = os.environ.get("VOALACK_LAB_DSN", "postgres://lab_admin:lab-only-admin@localhost/alerta")
APP_DSN = os.environ.get("VOALACK_LAB_APP_DSN", "postgres://alerta:lab-only-synthetic@localhost/alerta")
VERIFIER_DSN = os.environ.get("VOALACK_LAB_VERIFIER_DSN", "postgres://lab_verifier:lab-only-verifier@localhost/alerta")
SENDER_DSN = os.environ.get("VOALACK_LAB_SENDER_DSN", "postgres://lab_sender:lab-only-sender@localhost/alerta")
OPERATOR = ("operator@example.test", "synthetic-password-1")
READER = ("reader@example.test", "synthetic-password-2")
OPERATOR2 = ("operator2@example.test", "synthetic-password-3")
# Synthetic signing material (lab only): a 32-byte key in a file next to the tests.
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab-signing-key.bin")
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as handle:
        handle.write(b"lab-only-synthetic-signing-key-32")
LAB_CUSTOMER = "lab-customer"
# T04 S3c (disclosed fixture amendment): the lab database's recovery anchor, a directory outside the
# PostgreSQL data directory, bootstrapped once per session right after the schema.
LAB_ANCHOR_DIR = os.environ.get("VOALACK_LAB_ANCHOR_DIR") or tempfile.mkdtemp(prefix="voalack-anchor-")


def lab_anchor():
    from voalack import recovery
    return recovery.Anchor(LAB_ANCHOR_DIR)
CONFIG = {
    "VOALACK_DEPLOYMENT_ID": "lab-deployment", "VOALACK_SIGNING_KEY_FILES": {"lab-k1": KEY_FILE},
    "VOALACK_ACTIVE_KID": "lab-k1", "VOALACK_ALLOWED_AUTH_PROVIDERS": ["basic"],
    "VOALACK_MESSAGE_POLICY_REVISION": 1,
    "TESTING": True, "DATABASE_URL": APP_DSN, "AUTH_REQUIRED": True, "SECRET_KEY": "lab-only-synthetic-secret",
    "ADMIN_USERS": [], "PLUGINS": ["voalack"], "PLUGINS_RAISE_ON_ERROR": True,
    "ALLOWED_ENVIRONMENTS": ["Development"],
}


def basic(credentials):
    return {"Authorization": "Basic " + base64.b64encode(":".join(credentials).encode()).decode()}


def sql(query, args=(), fetch=True):
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute(query, args)
        return cur.fetchall() if fetch else None


@pytest.fixture(scope="session")
def app():
    from voalack import schema
    from voalack.boundary import create_app
    app = create_app(config_override=CONFIG)       # Alerta creates/updates its own tables as alerta
    with psycopg2.connect(DSN) as conn:            # the administrator applies the Voalack schema
        schema.apply(conn)
    from voalack import recovery                   # T04 S3c: explicit bootstrap of the lab installation
    if not os.path.exists(os.path.join(LAB_ANCHOR_DIR, recovery.LOG)):
        recovery.bootstrap(LAB_ANCHOR_DIR, DSN, {"basis": "lab session bootstrap (synthetic)"})
    with app.app_context():
        from alerta.auth.utils import generate_password_hash
        from alerta.models.user import User
        for (login, password), roles in ((OPERATOR, ["user"]), (READER, ["guest"]), (OPERATOR2, ["user"])):
            if not User.find_by_username(login):
                User(name=login.split("@")[0], login=login, password=generate_password_hash(password),
                     email=login, roles=roles, text="synthetic", email_verified=True).create()
    grant_policy(LAB_CUSTOMER, "lab-A")
    return app


def user_id(login):
    return sql("SELECT id FROM users WHERE login = %s", (login,))[0][0]


def grant_policy(*customers, revision=1):
    """Synthetic authorization policy: OPERATOR and OPERATOR2 may ACK these customers."""
    for login in (OPERATOR[0], OPERATOR2[0]):
        for customer in customers:
            sql("INSERT INTO voalack.authorization_policy VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (revision, user_id(login), customer), fetch=False)
    sql("INSERT INTO voalack.authorization_policy_active VALUES (true, %s) "
        "ON CONFLICT (singleton) DO UPDATE SET policy_revision = EXCLUDED.policy_revision", (revision,), fetch=False)


@pytest.fixture(autouse=True)
def lab_objects_do_not_outlive_their_test():
    # T04 S1: the verifier's readiness check refuses catalog drift, and the C3 fault-injection
    # tests leave their lab-only trigger function in schema voalack after dropping the trigger.
    yield
    sql("DROP FUNCTION IF EXISTS voalack.lab_fail_at_commit()", fetch=False)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def faults(app):
    """Register test-only fault plugins after the capture plugin; removed after each test."""
    from alerta.app import plugins
    added = []

    def add(name, plugin):
        plugins.plugins[name] = plugin
        added.append(name)
    yield add
    for name in added:
        plugins.plugins.pop(name, None)


def new_alert(client, bound=True, customer=LAB_CUSTOMER, occurrence_ref=None, instance_id="lab-one",
              target_id="4711"):
    """A synthetic Veeam ONE alarm. Bound: an active Error/major alarm with feed attributes, a customer
    and an immutable binding revision pinning its source fields and snapshot digest."""
    suffix = uuid.uuid4().hex[:12]
    r = client.post("/alert", json={"resource": f"veeamone:lab-{suffix}", "event": "VeeamOneAlarm",
                                     "environment": "Development", "severity": "major", "value": "Error",
                                     "service": ["lab"], "text": "synthetic",
                                     "attributes": {"veeamAlarmCombinationId": f"comb-{suffix}",
                                                    "captureId": f"cap-{suffix}"}},
                    headers=basic(OPERATOR))
    assert r.status_code == 201, r.get_data(as_text=True)
    alert_id = r.get_json()["id"]
    if bound:
        bind(alert_id, customer, occurrence_ref=occurrence_ref, instance_id=instance_id, target_id=target_id)
    return alert_id


def bind(alert_id, customer=LAB_CUSTOMER, revision=1, occurrence_ref=None, instance_id="lab-one", target_id="4711"):
    # T04 S2 fixture extension: instance and target are parameters (defaults unchanged).
    # T04 S1 fixture upgrade: a distinct occurrence per binding, so effect keys do not collide
    # unless a test asks for it (was: 'lab-occurrence' for every binding).
    occurrence_ref = occurrence_ref or f"lab-occurrence-{alert_id[:8]}"
    from voalack.envelope import SNAPSHOT_FIELDS, snapshot_digest
    sql("UPDATE alerts SET customer = %s WHERE id = %s", (customer, alert_id), fetch=False)
    row = sql("SELECT id, customer, resource, event, environment, origin, attributes FROM alerts WHERE id = %s",
              (alert_id,))[0]
    fields = dict(zip(("id", "customer", "resource", "event", "environment", "origin"), row[:6]))
    binding_id = f"lab-{alert_id}"
    sql("""INSERT INTO voalack.binding_revisions
             (binding_id, binding_revision, customer, source_namespace, instance_id, resource, event,
              environment, origin, combination_id, capture_id, target_kind, target_id, alarm_template_id,
              object_id, repeat_count, triggered_time, occurrence_ref, occurrence_evidence_sha256, snapshot_sha256,
              alert_lifetime_id)
           VALUES (%s, %s, %s, 'lab-feed', %s, %s, %s, %s, %s, %s, %s, 'triggered_alarm', %s, 7, 9, 0,
                   '2026-10-02T00:00:00Z', %s, %s, %s, voalack.alert_open_lifetime(%s))""",
        (binding_id, revision, customer, instance_id, fields["resource"], fields["event"], fields["environment"],
         fields["origin"], row[6]["veeamAlarmCombinationId"], row[6]["captureId"], target_id, occurrence_ref, "e" * 64,
         snapshot_digest({k: fields[k] for k in SNAPSHOT_FIELDS}), alert_id), fetch=False)
    # Coexistence 3a S2: the revision carries the alert's open lifetime; enrolment goes through the owner function.
    sql("SELECT voalack.enroll_binding(%s, %s, %s)", (alert_id, binding_id, revision), fetch=False)
    return binding_id


def ack(client, alert_id, who=OPERATOR, text="synthetic ack"):
    return client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": text},
                      headers=basic(who) if who else {})


def status(alert_id):
    return sql('SELECT status, (history[1]).type, (history[1])."user" FROM alerts WHERE id = %s', (alert_id,))[0]


def intents(alert_id):
    return sql("SELECT count(*) FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))[0][0]


def captures(alert_id):
    return sql("SELECT count(*) FROM voalack.captures WHERE alert_id = %s", (alert_id,))[0][0]


from contextlib import contextmanager


@contextmanager
def capture_does_nothing():
    """[lab, disposable database, disclosed fault boundary] A lab BEFORE INSERT trigger on voalack.captures skips the
    capture row (its function lives in schema public). Coexistence 3a S3a: protected function bodies and the four
    public triggers stay untouched and the enabled guard admits the lab trigger (voalack.captures triggers are not in
    the protected inventory), so the gate passes and the ACK reaches the late capture postcondition, which these
    witnesses exercise. Not an ordinary protected-path pass. The inventory is verified intact before and after, and the
    lab trigger is removed in finally. Yields the voalack log messages so a witness can prove the late path."""
    import logging
    assert inventory_problems() == []

    class _Records(logging.Handler):
        def __init__(self):
            super().__init__(logging.DEBUG)
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())
    handler = _Records()
    logger = logging.getLogger("voalack")
    try:
        logger.addHandler(handler)
        _exec_raw("CREATE OR REPLACE FUNCTION public.lab_skip_capture() RETURNS trigger LANGUAGE plpgsql AS "
                  "$$ BEGIN RETURN NULL; END $$")
        _exec_raw("CREATE TRIGGER lab_skip_capture BEFORE INSERT ON voalack.captures FOR EACH ROW "
                  "EXECUTE FUNCTION public.lab_skip_capture()")
        assert inventory_problems() == []                  # admitted: nothing protected changed
        yield handler.messages
    finally:
        logger.removeHandler(handler)
        _exec_raw("DROP TRIGGER IF EXISTS lab_skip_capture ON voalack.captures")
        _exec_raw("DROP FUNCTION IF EXISTS public.lab_skip_capture()")
        assert inventory_problems() == []


LATE_POSTCONDITION = "capture postcondition failed; local ACK rolled back"


GUARD_EVENT_TRIGGERS = ("voalack_protect_alerts_end", "voalack_protect_alerts_drop")
FOUR = ("voalack_capture_ack", "voalack_alert_ownership", "voalack_alert_lifetime", "voalack_alert_no_truncate")


def inventory_problems(dsn=None):
    return list(sql("SELECT voalack_guard.inventory_problems()")[0][0] if dsn is None else
                _sql_on(dsn, "SELECT voalack_guard.inventory_problems()")[0][0])


def _exec_raw(statement):
    """Execute DDL text verbatim (no parameter interpolation: function bodies may contain '%')."""
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute(statement)


def _sql_on(dsn, query, args=(), fetch=True):
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(query, args)
        return cur.fetchall() if fetch else None


@contextmanager
def guard_bypassed(why):
    """[lab, disposable database, DISCLOSED BYPASS] The trusted-superuser bypass of r8 section 10 (design review): the
    lab superuser disables the two event triggers so a test can create a drifted or detached inventory on purpose (to
    witness fail-closed detection, or to run a legacy recovery step whose real permit is not yet admitted). It is not
    a permit, not an approved recovery operation and not an ordinary protected-path pass. Before: the inventory is
    intact; exact protected function definitions/owners and the four public triggers are snapshotted. Finally, with the
    guard still disabled: those are restored exactly, then the only remaining problems must be the two disabled event
    triggers; they are re-enabled and the complete inventory is verified intact. `why` names the legacy oracle."""
    assert inventory_problems() == [], inventory_problems()
    functions = sql("SELECT p.oid::regprocedure::text, pg_get_functiondef(p.oid), pg_get_userbyid(p.proowner) "
                    "FROM pg_proc p WHERE p.oid IN (SELECT f FROM voalack_guard.protected_functions() f "
                    "WHERE f IS NOT NULL)")
    triggers = sql("SELECT t.tgname, pg_get_triggerdef(t.oid) FROM pg_trigger t "
                   "WHERE t.tgrelid = 'public.alerts'::regclass AND NOT t.tgisinternal AND t.tgname = ANY(%s)",
                   (list(FOUR),))
    assert sorted(t[0] for t in triggers) == sorted(FOUR)
    left = ["restoration did not complete"]
    try:
        for name in GUARD_EVENT_TRIGGERS:
            sql(f"ALTER EVENT TRIGGER {name} DISABLE", fetch=False)
        yield
    finally:
        try:
            for signature, definition, owner in functions:
                _exec_raw(definition)
                _exec_raw(f"ALTER FUNCTION {signature} OWNER TO {owner}")
            for name in FOUR:
                _exec_raw(f"DROP TRIGGER IF EXISTS {name} ON public.alerts")
            for name, definition in triggers:
                _exec_raw(definition)
            left = inventory_problems()
        finally:
            for name in GUARD_EVENT_TRIGGERS:                      # always re-enabled, whatever happened above
                sql(f"ALTER EVENT TRIGGER {name} ENABLE", fetch=False)
        # checked after the re-enable: a failed restoration stays a visible failure, never a silent pass
        assert sorted(left) == sorted(f"differs event_trigger {n}" for n in GUARD_EVENT_TRIGGERS), (why, left)
        assert inventory_problems() == [], (why, inventory_problems())


@pytest.fixture(autouse=True)
def _guard_baseline():
    """Coexistence 3a S3a (design review): every test starts from an intact, enabled protected inventory once the guard
    is installed, so a failed bypass restoration in an earlier test can never pass for a clean setup here."""
    try:
        installed = sql("SELECT to_regprocedure('voalack_guard.inventory_problems()') IS NOT NULL")[0][0]
    except psycopg2.Error:
        installed = False
    if installed:
        problems = inventory_problems()
        assert problems == [], f"baseline protected inventory not intact before this test: {problems}"
    yield


def clone_database(dump, dsn):
    """[lab, disposable sibling construction] Restore a full pg_dump of the lab database into a new, empty database.
    Coexistence 3a S3a: a full dump replays the guard's event triggers before the dump's trailing ACL statements, which
    the enabled guard would then refuse. So the clone is restored without the two event triggers; if the source carried
    the guard, they are created afterwards from their frozen definitions (event-trigger DDL is outside the guard), and
    the clone's protected inventory must then be intact. Not the product's restore path (refused until S3c)."""
    import subprocess
    listing = subprocess.run(["pg_restore", "-l", str(dump)], check=True, capture_output=True, text=True).stdout
    keep = [line for line in listing.splitlines() if " EVENT TRIGGER " not in line]
    guarded = len(keep) != len(listing.splitlines())
    toc = f"{dump}.toc"
    with open(toc, "w") as handle:
        handle.write("\n".join(keep) + "\n")
    subprocess.run(["pg_restore", "-L", toc, "-d", dsn, str(dump)], check=True)
    if guarded:
        # pg_dump omits an ACL equal to the object's default, so a relation the approved source made explicit with
        # REVOKE ALL ... FROM PUBLIC (owner-only, equal to acldefault) comes back with no ACL. Only for that exact
        # representational case, re-run the source's own REVOKE; every other difference stays and fails below.
        rematerialise = _sql_on(dsn, """
            SELECT f.name FROM voalack_guard.frozen_inventory f
              JOIN pg_class c ON c.oid = to_regclass(f.name)
             WHERE f.kind = 'relation' AND c.relacl IS NULL AND c.relkind = 'r'
               AND f.attrs = 'r|' || pg_get_userbyid(c.relowner) || '|' || acldefault('r', c.relowner)::text""")
        for (name,) in rematerialise:
            _sql_on(dsn, f"REVOKE ALL ON {name} FROM PUBLIC", fetch=False)
        # The same representational case for the two protected schemas (inventory kind 'namespace').
        namespaces = _sql_on(dsn, """
            SELECT f.name FROM voalack_guard.frozen_inventory f JOIN pg_namespace n ON n.nspname = f.name
             WHERE f.kind = 'namespace' AND n.nspacl IS NULL
               AND f.attrs = pg_get_userbyid(n.nspowner) || '|' || acldefault('n', n.nspowner)::text""")
        for (name,) in namespaces:
            _sql_on(dsn, f"REVOKE ALL ON SCHEMA {name} FROM PUBLIC", fetch=False)
        _sql_on(dsn, "CREATE EVENT TRIGGER voalack_protect_alerts_end ON ddl_command_end "
                     "EXECUTE FUNCTION voalack_guard.protect()", fetch=False)
        _sql_on(dsn, "CREATE EVENT TRIGGER voalack_protect_alerts_drop ON sql_drop "
                     "EXECUTE FUNCTION voalack_guard.protect()", fetch=False)
        problems = _sql_on(dsn, "SELECT voalack_guard.inventory_problems()")[0][0]
        detail = _sql_on(dsn, "SELECT f.kind, f.name, f.attrs, c.attrs FROM voalack_guard.frozen_inventory f "
                              "JOIN voalack_guard.current_inventory() c USING (kind, name) WHERE f.attrs <> c.attrs")
        assert list(problems) == [], f"cloned sibling inventory not intact: {problems}; frozen vs current: {detail}"
