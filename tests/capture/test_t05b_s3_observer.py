"""T05b S3: integration coverage of the ledger-only observer (design r2 + r3 + r3a + r3b).

Direct-SQL witnesses through the sender and administrator roles, as in S1.
"""
import json
import os
import uuid
from datetime import datetime, timezone

import pytest

from conftest import clone_database, new_alert, sql
from test_t04_s2_sender import _owner, fake, instance  # noqa: F401
from test_t04_s3c_recovery import sibling  # noqa: F401
from test_t04_s4_recovery import full_sibling  # noqa: F401
from test_t05b_s1_observer import ACKED, _begin, _enable, _record, summary


def _revise_binding(alert_id):
    """[lab] a new binding revision for the alert (same key): the next reservation opens a new chain."""
    cols = ("binding_id, binding_revision, customer, source_namespace, instance_id, resource, event, environment, "
            "origin, combination_id, capture_id, target_kind, target_id, alarm_template_id, object_id, repeat_count, "
            "triggered_time, occurrence_ref, occurrence_evidence_sha256, snapshot_sha256, alert_lifetime_id")
    sql(f"INSERT INTO voalack.binding_revisions ({cols}) SELECT {cols.replace('binding_revision,', 'binding_revision + 1,', 1)} "
        "FROM voalack.binding_revisions r WHERE (r.binding_id, r.binding_revision) = "
        "(SELECT binding_id, binding_revision FROM voalack.bindings WHERE alert_id = %s)", (alert_id,), fetch=False)
    sql("UPDATE voalack.bindings SET binding_revision = binding_revision + 1 WHERE alert_id = %s", (alert_id,),
        fetch=False)


def _observe_states(owner, alert_id, states):
    for s in states:
        obs, row = _begin(owner, alert_id)
        assert row["outcome"] == "reserved", row
        assert _record(owner, obs, s)["r_result"] == "stored"


def test_status_reports_the_latest_state_of_each_chain(client, app, instance, fake):
    """Two chains for one alert (binding revisions 1 and 2), several stored rows in each: status lists exactly the
    latest row of each chain, in revision order; completions count every stored row."""
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    _observe_states(owner, alert_id, [summary(), summary(**ACKED), summary()])          # rev 1: A, B, A
    _revise_binding(alert_id)
    _observe_states(owner, alert_id, [summary(**ACKED), summary()])                      # rev 2: B, A
    status = sql("SELECT voalack.observation_status(%s)", (alert_id,))[0][0]
    got = [(c["binding_revision"], c["classification"]) for c in status["chains"]]
    assert got == [(1, "not_acked"), (2, "not_acked")], status
    latest = sql("SELECT DISTINCT ON (binding_revision) binding_revision, obs_id::text FROM voalack.source_observations "
                 "WHERE alert_id = %s ORDER BY binding_revision, reservation_seq DESC", (alert_id,))
    assert [(c["binding_revision"], str(c["obs_id"])) for c in status["chains"]] == latest, (status, latest)
    assert status["completions"] == {"stored": 5}


def _restore_older_pin(obs):
    """[lab] the reservation row as a restore from an older epoch could leave it: its saved acquisition pin differs
    from the owner row's, while the owner row itself stays valid for the current epoch. Done as the lab
    administrator with the immutability trigger disabled for this one row change and enabled again."""
    sql("ALTER TABLE voalack.observation_reads DISABLE TRIGGER observation_reads_immutable; "
        "UPDATE voalack.observation_reads SET acquired_head_sha256 = %s WHERE obs_id = %s; "
        "ALTER TABLE voalack.observation_reads ENABLE TRIGGER observation_reads_immutable", ("f" * 64, obs), fetch=False)


def _owner_fenced_alone(owner):
    return sql("SELECT voalack._owner_fenced(%s, %s, %s, ARRAY['active'])",
               (owner.instance_id, owner.generation, owner.incarnation))[0][0]


@pytest.mark.parametrize("pins", ["differ", "match"])
def test_the_saved_pin_is_compared_with_the_current_owner_row(client, app, instance, fake, pins):
    """Deferred from S1 (distinct comparison): _owner_fenced alone passes for the current owner, so only the
    saved-pin clause of the admission statement can refuse. Differing pins: refused owner_fenced, nothing stored.
    Matching pins (positive control, identical setup otherwise): the record is admitted and stored."""
    _enable(instance)
    alert_id = new_alert(client, instance_id=instance)
    owner = _owner(instance, fake)
    obs, row = _begin(owner, alert_id)
    assert row["outcome"] == "reserved", row
    if pins == "differ":
        _restore_older_pin(obs)
    assert sql("SELECT tgenabled FROM pg_trigger WHERE tgname = 'observation_reads_immutable' "
               "AND tgrelid = 'voalack.observation_reads'::regclass") == [("O",)]   # immutability re-enabled
    assert _owner_fenced_alone(owner) is True                           # the owner check alone would admit
    rec = _record(owner, obs, summary())
    expected = ("recorded", "refused:owner_fenced") if pins == "differ" else ("recorded", "stored")
    assert (rec["outcome"], rec["r_result"]) == expected, rec
    assert sql("SELECT count(*) FROM voalack.source_observations WHERE alert_id = %s", (alert_id,))[0][0] == \
        (0 if pins == "differ" else 1)


# --- capture contract and cross-schema dependencies -----------------------------------------------------------------

def _capture_contract():
    import psycopg2
    from conftest import DSN
    from voalack import recovery
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        return recovery.capture_contract(cur)


def _dependencies():
    import psycopg2
    from conftest import DSN
    from voalack import recovery
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        return recovery.cross_schema_dependencies(cur)


def test_the_capture_contract_is_intact_with_the_observer_enabled(client, app, instance, fake):
    """Positive control on the shared database (public.alerts present): with the observer installed and enabled,
    the approved capture trigger and body are unchanged and the contract reports no problem. This alone does not
    establish observer coverage; the coupling control below and the admin audit do."""
    from voalack import recovery
    _enable(instance)
    assert sql("SELECT to_regclass('public.alerts') IS NOT NULL")[0][0] is True
    assert sql("SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t WHERE t.tgrelid = 'public.alerts'::regclass "
               "AND t.tgname = 'voalack_capture_ack'")[0][0] == recovery.CAPTURE_TRIGGERDEF
    assert _capture_contract() == []


def test_an_observer_coupled_to_alerta_is_rejected_by_the_capture_contract(app):
    """Negative coupling control [lab]: a trigger on public.alerts that calls an observer function is reported by
    the capture contract and is visible as a cross-schema dependency; removing it restores both."""
    from conftest import guard_bypassed
    from voalack import recovery
    # Coexistence 3a S3a (amended openly): such a trigger is refused DDL under the enabled guard; the coupling control
    # creates it under the disclosed lab bypass. The contract reports it twice: its own check and the shared inventory.
    with guard_bypassed("legacy observer-coupling control"):
        sql("CREATE TRIGGER lab_observer_coupling BEFORE UPDATE ON public.alerts FOR EACH ROW "
            "EXECUTE FUNCTION voalack._observer_flag_bump()", fetch=False)
        try:
            problems, deps = _capture_contract(), _dependencies()
        finally:
            sql("DROP TRIGGER lab_observer_coupling ON public.alerts", fetch=False)
    assert [p for p in problems if not p.startswith("guard: ")] == ["other voalack triggers on public.alerts"], problems
    assert "guard: extra public_trigger lab_observer_coupling" in problems, problems
    assert [d for d in deps if d not in recovery.ALLOWED_DEPENDENCIES] == \
        [("trigger", "lab_observer_coupling on public.alerts", "function", "voalack._observer_flag_bump()")], deps
    assert _capture_contract() == [] and _dependencies() == recovery.ALLOWED_DEPENDENCIES   # 3a: four approved


def test_cross_schema_dependencies_are_unchanged_and_would_see_an_observer_reference(client, app, instance, fake):
    """With the observer installed and enabled, the only outside-schema dependency is the approved one. Lab
    dependency-visibility control (a fixture, not a product mutation): a view outside voalack over
    voalack.observation_reads appears in the list; dropping it restores the approved list."""
    from voalack import recovery
    _enable(instance)
    assert _dependencies() == recovery.ALLOWED_DEPENDENCIES   # 3a: four approved
    sql("CREATE VIEW public.lab_observer_view AS SELECT obs_id FROM voalack.observation_reads", fetch=False)
    try:
        deps = _dependencies()
    finally:
        sql("DROP VIEW public.lab_observer_view", fetch=False)
    extra = [d for d in deps if d not in recovery.ALLOWED_DEPENDENCIES]
    assert all(d in deps for d in recovery.ALLOWED_DEPENDENCIES)
    assert extra and all("lab_observer_view" in d[1] and d[3].startswith("voalack.observation_reads") for d in extra), deps
    assert _dependencies() == recovery.ALLOWED_DEPENDENCIES   # 3a: four approved


# --- collision oracles (r3 C4) --------------------------------------------------------------------------------------

def _fact_tables(dsn=None):
    """Every capture, intent, binding, verification, authorization, delivery, settlement, recovery, event and
    projection table of schema voalack (all but the five observation tables), the publication ledger, and
    Alerta's alerts and notes (schema-qualified)."""
    q = ("SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
         "WHERE c.relkind = 'r' AND ((n.nspname = 'voalack' AND c.relname NOT IN ('observation_chains', "
         "'observation_reads', 'observation_completions', 'source_observations', 'observation_evidence')) "
         "OR (n.nspname, c.relname) IN (('voalack_publication', 'publications'), ('public', 'alerts'), "
         "('public', 'notes'))) ORDER BY 1")
    return [r[0] for r in (sql(q) if dsn is None else _q(dsn, q))]


def _fingerprints(dsn=None):
    """Full ordered row fingerprints of every fact table (see _fact_tables)."""
    run = sql if dsn is None else (lambda statement: _q(dsn, statement))
    return {t: run(f"SELECT md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) FROM {t} x")[0][0]
            for t in _fact_tables(dsn)}


def _observation_with_seq(owner, alert_id, seq):
    """[lab] a stored observation of ``alert_id`` (created and bound beforehand, on another key) whose
    reservation_seq equals ``seq`` (sequence set by the lab administrator), so it coincides numerically with a
    reconciliation id. Only observation rows are written here."""
    sql("SELECT setval('voalack.observation_seq', %s, false)", (seq,), fetch=False)
    obs, row = _begin(owner, alert_id)
    assert row["outcome"] == "reserved", row
    assert sql("SELECT reservation_seq FROM voalack.observation_reads WHERE obs_id = %s", (obs,))[0][0] == seq
    assert _record(owner, obs, summary(**ACKED))["r_result"] == "stored"
    return obs


def _settle(owner, reconciliation_id):
    from test_t04_s2_sender import _call
    return _call("SELECT voalack.settle_by_reconciliation(%s, %s, %s, %s, %s) AS o",
                 (str(uuid.uuid4()), reconciliation_id, owner.instance_id, owner.generation, owner.incarnation))["o"]


def _above_all_ids():
    """[lab] a number above every observation and reconciliation id; the reconciliation sequence is moved there."""
    high = sql("SELECT greatest((SELECT coalesce(max(reservation_seq), 0) FROM voalack.observation_reads), "
               "(SELECT coalesce(max(reconciliation_id), 0) FROM voalack.reconciliations)) + 100000")[0][0]
    sql("SELECT setval(pg_get_serial_sequence('voalack.reconciliations', 'reconciliation_id'), %s)", (high,),
        fetch=False)
    return high


@pytest.mark.parametrize("observed", [False, True], ids=["without_observation", "with_observation"])
def test_an_unknown_id_is_never_a_reconciliation(client, app, instance, fake, observed):
    """Unknown id, with and without an observation holding that number: settlement is refused no_reconciliation and
    no fact row changes (the observation alone changes none either)."""
    _enable(instance)
    owner = _owner(instance, fake)
    seq = _above_all_ids() + 50000
    assert sql("SELECT count(*) FROM voalack.reconciliations WHERE reconciliation_id = %s", (seq,))[0][0] == 0
    if observed:
        other = new_alert(client, instance_id=instance, target_id="4712")
        before = _fingerprints()
        _observation_with_seq(owner, other, seq)
        assert _fingerprints() == before
    before = _fingerprints()
    assert _settle(owner, seq) == "no_reconciliation"
    assert _fingerprints() == before


@pytest.mark.parametrize("observed", [False, True], ids=["without_observation", "with_observation"])
@pytest.mark.parametrize("kind", ["ineligible", "eligible"])
def test_a_coincident_observation_changes_no_reconciliation_outcome(client, app, instance, fake, kind, observed):
    """The same reconciliation, with and without a stored observation whose reservation_seq equals its id. Inserting
    the observation changes no fact row. Ineligible (evidence_only): refused not_attributable and no fact row
    changes. Independently eligible (attributable): settles on its own provenance - exactly one automatic
    confirmed_attributed settlement naming this reconciliation, effect REMOTE_CONFIRMED with no in-flight attempt,
    the key's guard removed, and the two outcome events of an attributed settlement."""
    from test_t04_s3b_settlement import _uncertain
    from test_t05a_reverse_state import _events
    _enable(instance)
    _above_all_ids()
    other = new_alert(client, instance_id=instance, target_id="4712")
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    if kind == "ineligible":
        fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True,
                               "comment": "another comment"}                         # unattributed: evidence_only
    result = owner.reconcile(attempt_id, settle=False)
    assert result.get("classification") == ("evidence_only" if kind == "ineligible" else "attributable"), result
    rid = sql("SELECT reconciliation_id FROM voalack.reconciliations WHERE attempt_id = %s", (attempt_id,))[0][0]
    if observed:
        before = _fingerprints()
        _observation_with_seq(owner, other, rid)
        assert _fingerprints() == before                                # the observation alone changes nothing
    events, before = _events(effect_id), _fingerprints()
    outcome = _settle(owner, rid)
    if kind == "ineligible":
        assert outcome == "not_attributable", outcome
        assert _fingerprints() == before                                # a refused decision changes nothing
        return
    assert outcome == "settled", outcome
    assert sql("SELECT outcome, path, reconciliation_id, effect_state FROM voalack.settlements WHERE attempt_id = %s",
               (attempt_id,)) == [("confirmed_attributed", "automatic", rid, "REMOTE_CONFIRMED")]
    assert sql("SELECT state, in_flight_attempt FROM voalack.effects WHERE effect_id = %s", (effect_id,)) == \
        [("REMOTE_CONFIRMED", None)]
    assert sql("SELECT count(*) FROM voalack.target_guards WHERE attempt_id = %s", (attempt_id,))[0][0] == 0
    assert _events(effect_id) == events + ["settled:confirmed_attributed", "confirmed"]


def test_a_historical_observation_never_settles_a_newer_attempt(client, app, instance, fake):
    """observesettles killer, frozen historical-first order: (1) an eligible attempt completes and its genuine
    matching-operation observation is stored on the unheld key; (2) a different uncertain attempt on the same key
    gets an evidence_only reconciliation; (3) settlement is refused: no new settlement, the effect stays UNCERTAIN,
    attempt, guard and projection rows unchanged."""
    from test_t04_s2_sender import _effect
    from test_t04_s3b_settlement import _successor, _uncertain
    first = _effect(client, app, instance)
    owner = _owner(instance, fake)
    assert owner.apply_once(first)["outcome"] == "confirmed"
    alert_id = sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
                   "WHERE e.effect_id = %s", (first,))[0][0]
    _enable(instance)                                                   # fences the sending owner
    observer = _successor(instance, fake, owner, quiesce=False)
    seen = observer.observe(alert_id)
    assert seen.get("classification") == "acked_with_matching_voalack_operation", seen
    fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": False}   # [inject] unacked in ONE
    effect_id, attempt_id, observer = _uncertain(client, app, instance, fake, owner=observer)
    fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True, "comment": "another comment"}
    assert observer.reconcile(attempt_id, settle=False)["classification"] == "evidence_only"
    rid = sql("SELECT reconciliation_id FROM voalack.reconciliations WHERE attempt_id = %s", (attempt_id,))[0][0]
    before = _fingerprints()
    outcome = _settle(observer, rid)
    assert outcome == "not_attributable", outcome
    assert sql("SELECT state FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0][0] == "UNCERTAIN"
    assert _fingerprints() == before


# --- administrative installation audit ------------------------------------------------------------------------------

def _audit():
    import psycopg2
    from conftest import DSN
    from voalack import observer_audit
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        return observer_audit.audit(cur), observer_audit.inventory(cur)


def test_the_installed_observer_matches_the_frozen_inventory(app):
    """Positive control: the freshly installed observer equals the frozen inventory in every class, and every class
    is non-empty (a checker that ignored the observer would compare empty lists). The installed inventory is also
    written to the evidence (it is the source of the frozen file)."""
    from test_t04_s4_shared_restore import _evidence
    from voalack import observer_audit
    problems, installed = _audit()
    _evidence("observer-inventory.json", installed)
    assert all(installed[c] for c in observer_audit.CLASSES), {c: len(installed[c]) for c in observer_audit.CLASSES}
    assert problems == [], problems


DRIFTS = {   # class -> (drift, restore), each as the lab administrator
    "tables": ("ALTER TABLE voalack.observation_evidence RENAME TO lab_observation_evidence",
               "ALTER TABLE voalack.lab_observation_evidence RENAME TO observation_evidence"),
    "columns": ("ALTER TABLE voalack.instance_config ALTER COLUMN observer_enabled SET DEFAULT true",
                "ALTER TABLE voalack.instance_config ALTER COLUMN observer_enabled SET DEFAULT false"),
    "sequences": ("ALTER SEQUENCE voalack.observation_seq INCREMENT BY 2",
                  "ALTER SEQUENCE voalack.observation_seq INCREMENT BY 1"),
    "constraints": ("ALTER TABLE voalack.observation_reads DROP CONSTRAINT observation_reads_reservation_seq_key",
                    "ALTER TABLE voalack.observation_reads ADD CONSTRAINT observation_reads_reservation_seq_key "
                    "UNIQUE (reservation_seq)"),
    "functions": ("ALTER FUNCTION voalack.observation_status(text) SECURITY INVOKER",
                  "ALTER FUNCTION voalack.observation_status(text) SECURITY DEFINER"),
    "triggers": ("ALTER TABLE voalack.observation_chains DISABLE TRIGGER observation_chains_immutable",
                 "ALTER TABLE voalack.observation_chains ENABLE TRIGGER observation_chains_immutable"),
    "acls": ("GRANT SELECT ON voalack.observation_reads TO voalack_app",
             "REVOKE SELECT ON voalack.observation_reads FROM voalack_app"),
}


@pytest.mark.parametrize("cls", list(DRIFTS))
def test_each_class_of_observer_drift_is_reported(app, cls):
    """One drift per class is reported in exactly that class (a renamed table also in every class keyed by its name);
    after the restore the audit is clean again."""
    drift, restore = DRIFTS[cls]
    assert _audit()[0] == []
    sql(drift, fetch=False)
    try:
        problems = _audit()[0]
    finally:
        sql(restore, fetch=False)
    expected = ["tables", "columns", "constraints", "triggers", "acls"] if cls == "tables" else [cls]   # a renamed
    assert [p.split(":", 1)[0] for p in problems] == expected, problems         # table moves its rows in every class

    assert _audit()[0] == []


# --- upgrade from the frozen S4 schema, failed apply, reapply -------------------------------------------------------

S4_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "schema_s4_345f31b5.sql")
S4_SCHEMA_SHA256 = "345f31b5ea6ba28cc008c190a8a4a6dacadc7d81d0340fd40db6ac9147f7c960"   # 29228ef5, reviewed


class S4(tuple):
    """(dsn, anchor directory) of a populated S4 database."""
    dsn = property(lambda self: self[0])
    anchor = property(lambda self: self[1])


@pytest.fixture
def s4_db(client, app, tmp_path):
    """A copy of the whole lab database (Alerta's public tables with real alerts and notes) whose Voalack schemas
    are replaced by the frozen S4 installation (29228ef5 schema bytes, sha256 checked), with its own anchor.
    Populated by ``_populate_s4``. [lab] The history is constructed (labelled): delivery rows are inserted as an
    S4 deployment would hold them, through every S4 constraint and trigger; recovery, event, projection,
    publication and note history is produced by the recovery procedure and the projector against the S4 schema.
    Compatibility of the old S4 application workflows themselves is not proved by this fixture."""
    import hashlib
    import uuid as _uuid
    from conftest import DSN
    from test_t04_s3c_recovery import _admin, _dsn, _run
    from test_t04_s3c_restore import PRIVILEGES
    with open(S4_SCHEMA, "rb") as handle:
        source = handle.read()
    assert hashlib.sha256(source).hexdigest() == S4_SCHEMA_SHA256
    new_alert(client)                                                    # at least one real alert to clone
    name = f"voalack_s4up_{_uuid.uuid4().hex[:8]}"
    dump = tmp_path / f"{name}-lab.dump"
    _run(["pg_dump", "-Fc", "-f", str(dump), DSN])
    _admin(f"CREATE DATABASE {name}")
    dsn = _dsn(name)
    try:
        clone_database(dump, dsn)                              # 3a S3a: guard-aware lab clone
        # The S4 installation predates coexistence 3a: its copy keeps no voalack_lifetime schema (else the
        # lab's lifetime-1 record would make the upgrade's migration a no-op) and no DDL protector. [lab, historical
        # construction] The copy's event triggers are dropped first (event-trigger DDL is outside the guard), then
        # the guard schema with the rest.
        _q(dsn, "DROP EVENT TRIGGER IF EXISTS voalack_protect_alerts_end; "
                "DROP EVENT TRIGGER IF EXISTS voalack_protect_alerts_drop", fetch=False)
        _q(dsn, "DROP SCHEMA voalack_publication CASCADE; DROP SCHEMA voalack CASCADE; "
                "DROP SCHEMA IF EXISTS voalack_lifetime CASCADE; DROP SCHEMA IF EXISTS voalack_guard CASCADE",
           fetch=False)
        _q(dsn, source.decode("utf-8"), fetch=False)                    # the S4 installation
        _q(dsn, PRIVILEGES, fetch=False)
        anchor = tmp_path / f"{name}-anchor"
        anchor.mkdir()
        yield S4((dsn, str(anchor)))
    finally:
        _admin(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


import contextlib


@contextlib.contextmanager
def _pre_3a_recovery():
    """[lab] The S4 fixture is a pre-coexistence-3a installation: it has the capture trigger but none of the three
    3a protection triggers. Populating it runs the recovery cycle, so for that population only, recovery checks
    and detaches/recreates the pre-3a contract (capture trigger alone). The product's recovery is unchanged and
    requires all four protections; the upgrade tests apply the 3a schema afterwards."""
    from voalack import recovery
    saved = (recovery.PROTECTION_TRIGGERS, recovery.PROTECTION_TRIGGERDEFS, recovery.ALLOWED_DEPENDENCIES)
    recovery.PROTECTION_TRIGGERS, recovery.PROTECTION_TRIGGERDEFS, recovery.ALLOWED_DEPENDENCIES = \
        {}, {}, [recovery.ALLOWED_DEPENDENCY]
    try:
        yield
    finally:
        recovery.PROTECTION_TRIGGERS, recovery.PROTECTION_TRIGGERDEFS, recovery.ALLOWED_DEPENDENCIES = saved


def _populate_s4(db):
    with _pre_3a_recovery():
        return _populate_s4_pre_3a(db)


def _disposition_s4_collisions(db):
    """[lab] The operator step before upgrading this S4 fixture to coexistence 3a: its cloned alerts reuse ids that
    the S4 history protected but are not of the Veeam ONE class (r8 section 7 migration collisions). Prepare the
    dispositions table on its own, then record one disposition per colliding id, as an operator would; the upgrade
    then reserves them. Returns the ids."""
    import psycopg2
    from voalack import intent, schema
    conn = psycopg2.connect(db.dsn)
    try:
        schema.prepare_lifetime_migration(conn)
    finally:
        conn.close()
    history = _q(db.dsn, "SELECT a.id, a.event, a.resource FROM public.alerts a WHERE a.id IN ("
                         "SELECT alert_id FROM voalack.prepared_intents UNION SELECT alert_id FROM voalack.captures "
                         "UNION SELECT alert_id FROM voalack_publication.publications "
                         "UNION SELECT alert_id FROM voalack.bindings)")
    colliding = sorted(i for i, event, resource in history if intent.alert_class(event, resource) != intent.ONE_CLASS)
    for alert_id in colliding:
        _q(db.dsn, "INSERT INTO voalack_lifetime.migration_dispositions (alert_id, disposition, actor, basis) "
                   "VALUES (%s, 'reserve_collision', 'lab-operator', 'lab: S4 fixture clone')", (alert_id,),
           fetch=False)
    return colliding


def _populate_s4_pre_3a(db):
    """Nonempty coherent S4 history: recovery bootstrap; the S3b-shaped delivery history (confirmed, uncertain,
    settled, not_sent, aborted_before_dispatch, queued; owners in every state) whose actions point at real cloned
    alerts; outcome events from the S4 triggers; the projector drained (projections, publications and actual
    public.notes); one supervised close / inventory / recover / reopen cycle and a second drain."""
    import json as _json
    import psycopg2
    from test_t04_s3c_recovery import _seed_s3b
    from voalack import projector, recovery
    recovery.bootstrap(db.anchor, db.dsn, {"basis": "lab S4 fixture bootstrap"})
    with psycopg2.connect(db.dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack._pin_epoch()")      # as every S4 event source does: the epoch row first
        assert cur.fetchone()[0] is True
        _seed_s3b(cur)
        cur.execute("SELECT DISTINCT alert_id FROM voalack.prepared_intents WHERE alert_id LIKE 'alert-%%'")
        for (alert_id,) in cur.fetchall():                               # real alerts for the seeded actions
            cur.execute("INSERT INTO public.alerts SELECT (jsonb_populate_record(NULL::public.alerts, "
                        "to_jsonb(a) || jsonb_build_object('id', %s, 'resource', %s, 'customer', NULL))).* "
                        "FROM public.alerts a WHERE a.id NOT LIKE 'alert-%%' LIMIT 1",
                        (alert_id, f"lab-s4-{alert_id}"))   # own key; the intents' (S3b-shaped, NULL) customer
    projector_dsn = db.dsn.replace("lab_admin:lab-only-admin", "lab_projector:lab-only-projector")

    def drain():
        while projector.run(projector_dsn, db.anchor, "lab-s4-fixture", max_steps=500)[-1]["outcome"] not in \
                ("idle", "busy", "paused", "deferred"):
            pass
    drain()
    recovery.close(db.anchor, db.dsn)
    for inst, generation in _q(db.dsn, "SELECT instance_id, owner_generation FROM voalack.session_owners "
                                        "WHERE state IN ('active', 'suspended')"):
        _q(db.dsn, "SELECT voalack.record_containment(%s, %s, %s::jsonb)",
           (inst, generation, _json.dumps({"process_stopped": True, "no_requests_executing": True,
                                           "basis": "lab S4 fixture: no process runs"})), fetch=False)
    head = recovery.inventory(db.anchor, db.dsn)
    review = recovery.write_review(db.anchor, {"ref": "lab S4 fixture", "backup_id": "none", "backup_sha256": None,
                                               "inventory_sha256": head.line["inventory_sha256"], "decision": "adopt"})
    recovery.recover(db.anchor, db.dsn, review, layout="shared")
    recovery.reopen(db.anchor, db.dsn, layout="shared")
    drain()
    counts = {t: _q(db.dsn, f"SELECT count(*) FROM {t}")[0][0] for t in _all_tables(db.dsn)}
    statuses = _q(db.dsn, "SELECT status, count(*) FROM voalack.projections GROUP BY 1 ORDER BY 1")
    from test_t04_s4_shared_restore import _evidence
    _evidence("s4-populated-counts.json", {"counts": counts, "projection_statuses": statuses})
    for table in ("voalack.effects", "voalack.attempts", "voalack.settlements", "voalack.outcome_events",
                  "voalack.recovery_transitions", "voalack.recovery_adoptions", "voalack.projections",
                  "voalack_publication.publications", "public.notes"):
        assert counts[table] > 0, (table, counts, statuses)              # every promised history is non-empty
    assert _q(db.dsn, "SELECT count(*) FROM voalack_publication.publications p JOIN public.notes n "
                      "ON n.id = p.note_id AND n.alert = p.alert_id")[0][0] == counts["voalack_publication.publications"]
    return counts


def _all_tables(dsn):
    """Every table of both Voalack schemas, plus Alerta's alerts and notes (schema-qualified)."""
    return [r[0] for r in _q(dsn, "SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n "
                                  "ON n.oid = c.relnamespace WHERE c.relkind = 'r' AND (n.nspname IN ('voalack', "
                                  "'voalack_publication') OR (n.nspname, c.relname) IN (('public', 'alerts'), "
                                  "('public', 'notes'))) ORDER BY 1")]


def _q(dsn, statement, args=(), fetch=True):
    import psycopg2
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(statement, args) if args else cur.execute(statement)   # no args: a literal % stays literal
        return cur.fetchall() if fetch else None


def _columns(dsn, tables):
    """The current column list of each named (schema-qualified) table, in attribute order."""
    return {t: [r[0] for r in _q(dsn, "SELECT attname FROM pg_attribute WHERE attrelid = %s::regclass AND attnum > 0 "
                                      "AND NOT attisdropped ORDER BY attnum", (t,))] for t in tables}


def _all_rows(dsn, tables, columns=None):
    """Full ordered row fingerprints of the named (schema-qualified) tables, over ``columns`` (the pre-upgrade list of
    each table, so a column the upgrade adds does not change an unchanged row's fingerprint)."""
    columns = columns or _columns(dsn, tables)
    out = {}
    for t in tables:
        cols = ", ".join(f'"{c}"' for c in columns[t])
        out[t] = _q(dsn, f"SELECT md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) "
                         f"FROM (SELECT {cols} FROM {t}) x")[0][0]
    return out


def _observer_absent(dsn):
    return _q(dsn, "SELECT to_regclass('voalack.observation_reads') IS NULL AND NOT EXISTS (SELECT 1 FROM "
                   "information_schema.columns WHERE table_schema = 'voalack' AND table_name = 'instance_config' "
                   "AND column_name = 'observer_enabled')")[0][0]


def _audit_on(dsn):
    import psycopg2
    from voalack import observer_audit
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        return observer_audit.audit(cur)


def test_s3a_staging_distinguishes_a_historical_pre_3a_installation(s4_db):
    """Coexistence 3a S3a (new): the staged refusal recognises a 3a installation by any marker, and only a genuinely
    historical pre-3a installation (this frozen S4 copy, no marker at all) is not refused by it."""
    from conftest import DSN
    from voalack import recovery
    markers = "SELECT to_regnamespace('voalack_guard'), to_regnamespace('voalack_lifetime'), " \
              "to_regprocedure('voalack.protections_intact()'), " \
              "(SELECT count(*) FROM pg_event_trigger WHERE evtname LIKE 'voalack%')"
    assert _q(s4_db.dsn, markers) == [(None, None, None, 0)]
    recovery._refuse_staged_restore(s4_db.dsn)                           # historical: not refused by the staging
    with pytest.raises(recovery.RestoreRefused, match="restore is staged"):
        recovery._refuse_staged_restore(DSN)                             # the installed lab database: refused

def test_upgrade_from_s4_adds_the_observer_off_and_keeps_every_row(s4_db):
    """Populated S4 history (confirmed, uncertain, settled, not_sent, aborted_before_dispatch, queued; owners in
    every state; the events and projections the S4 triggers derive): after the upgrade every pre-existing table has
    identical full row fingerprints, every instance has observer_enabled = false with an unchanged config_revision,
    the observation tables are empty, and the installed observer matches the frozen inventory."""
    import psycopg2
    from voalack import schema
    _populate_s4(s4_db)
    _disposition_s4_collisions(s4_db)   # 3a: the operator's collision dispositions
    tables = _all_tables(s4_db.dsn)
    columns = _columns(s4_db.dsn, tables)
    before = _all_rows(s4_db.dsn, tables, columns)
    revisions = _q(s4_db.dsn, "SELECT instance_id, config_revision FROM voalack.instance_config ORDER BY 1")
    assert _q(s4_db.dsn, "SELECT count(*) FROM voalack.attempts WHERE state IN ('not_sent', 'aborted_before_dispatch')")[0][0] == 2
    with psycopg2.connect(s4_db.dsn) as conn:
        schema.apply(conn)
    assert _all_rows(s4_db.dsn, tables, columns) == before
    assert _q(s4_db.dsn, "SELECT instance_id, config_revision, observer_enabled FROM voalack.instance_config ORDER BY 1") == \
        [(i, r, False) for i, r in revisions]
    assert _q(s4_db.dsn, "SELECT (SELECT count(*) FROM voalack.observation_reads) + "
                     "(SELECT count(*) FROM voalack.source_observations)")[0][0] == 0
    assert _audit_on(s4_db.dsn) == []


# Scope: functions (identity, body digest, owner, security, configuration, ACL), relations of every kind (name,
# kind, owner, ACL; indexes and sequences only by these), columns, constraints and non-internal triggers of both
# Voalack schemas, plus the triggers on public.alerts. Not included: sequence values or options, index
# definitions, schema ACLs.
FULL_CATALOG = """
SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (
  SELECT 'fn ' || p.oid::regprocedure::text || ' ' || md5(p.prosrc) || ' ' || pg_get_userbyid(p.proowner) || ' '
         || p.prosecdef || ' ' || coalesce(array_to_string(p.proconfig, ','), '') || ' '
         || coalesce(array_to_string(p.proacl, ','), '') AS x
    FROM pg_proc p WHERE p.pronamespace IN ('voalack'::regnamespace, 'voalack_publication'::regnamespace)
  UNION ALL
  SELECT 'rel ' || c.relname::text || ' ' || c.relkind::text || ' ' || pg_get_userbyid(c.relowner) || ' '
         || coalesce(array_to_string(c.relacl, ','), '')
    FROM pg_class c WHERE c.relnamespace IN ('voalack'::regnamespace, 'voalack_publication'::regnamespace)
  UNION ALL
  SELECT 'col ' || c.relname::text || '.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) || ' '
         || a.attnotnull || ' ' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
    LEFT JOIN pg_attrdef d ON (d.adrelid, d.adnum) = (a.attrelid, a.attnum)
   WHERE c.relnamespace IN ('voalack'::regnamespace, 'voalack_publication'::regnamespace) AND a.attnum > 0 AND NOT a.attisdropped
  UNION ALL
  SELECT 'con ' || c.relname::text || ' ' || k.conname || ' ' || pg_get_constraintdef(k.oid)
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid WHERE c.relnamespace IN ('voalack'::regnamespace, 'voalack_publication'::regnamespace)
  UNION ALL
  SELECT 'trg ' || t.tgrelid::regclass::text || ' ' || pg_get_triggerdef(t.oid) || ' ' || t.tgenabled::text
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
   WHERE NOT t.tgisinternal AND (c.relnamespace IN ('voalack'::regnamespace, 'voalack_publication'::regnamespace) OR t.tgrelid = 'public.alerts'::regclass)
) y"""
OBSERVER_ABSENT = """
SELECT NOT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'voalack'::regnamespace AND relname = ANY(%(rels)s))
   AND NOT EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace = 'voalack'::regnamespace AND proname = ANY(%(fns)s))
   AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = ANY(%(trgs)s))
   AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'voalack'
                   AND table_name = 'instance_config' AND column_name = 'observer_enabled')"""
INJECTED = """
DO $lab$ BEGIN
    RAISE EXCEPTION 'lab injected migration failure after DDL (observer installed: %)',
        CASE WHEN to_regclass('voalack.observation_reads') IS NOT NULL THEN 'yes' ELSE 'no' END;
END $lab$;"""


def test_a_failed_observer_migration_rolls_back_to_the_s4_state(s4_db):
    """An injected failure after the observer DDL, inside the one migration transaction, rolls everything back: the
    populated S4 rows (pre-upgrade columns), the full catalog (functions with bodies, owners, definer settings and
    ACLs; relations with owners and ACLs; columns with defaults; constraints; triggers incl. public.alerts) are
    exactly the S4 ones and no observer object exists; a committed apply then succeeds."""
    import psycopg2
    from voalack import observer_audit, schema
    _populate_s4(s4_db)
    _disposition_s4_collisions(s4_db)   # 3a: the operator's collision dispositions
    tables = _all_tables(s4_db.dsn)
    columns = _columns(s4_db.dsn, tables)
    rows, catalog = _all_rows(s4_db.dsn, tables, columns), _q(s4_db.dsn, FULL_CATALOG)[0][0]
    absent = {"rels": list(observer_audit.OBSERVER_TABLES + observer_audit.OBSERVER_SEQUENCES),
              "fns": list(observer_audit.OBSERVER_FUNCTIONS), "trgs": list(observer_audit.OBSERVER_TRIGGERS)}
    assert _q(s4_db.dsn, OBSERVER_ABSENT, absent)[0][0] is True
    migration = psycopg2.connect(s4_db.dsn)
    try:
        with pytest.raises(psycopg2.errors.RaiseException,
                           match=r"lab injected migration failure after DDL \(observer installed: yes\)"):
            migration.cursor().execute(schema.full_sql() + INJECTED)          # one transaction, failing after DDL
        migration.rollback()
    finally:
        migration.close()
    assert _all_rows(s4_db.dsn, tables, columns) == rows
    assert _q(s4_db.dsn, FULL_CATALOG)[0][0] == catalog
    assert _q(s4_db.dsn, OBSERVER_ABSENT, absent)[0][0] is True
    with psycopg2.connect(s4_db.dsn) as conn:
        schema.apply(conn)
    assert _all_rows(s4_db.dsn, tables, columns) == rows and _audit_on(s4_db.dsn) == []


def test_reapply_preserves_both_flag_states_history_and_the_sequence(s4_db):
    """After the upgrade, one instance enabled (a real flag change with its revision bump) and one left disabled,
    with [lab] observation history inserted by the administrator in all five tables (a stored read with its
    completion and source observation, an unchanged read, an unfinished read and a bad summary's digest-only
    evidence): a second application keeps both flags, both revisions, every observation row, every pre-existing S4
    row and both sequence positions (the next reservation number and evidence id continue, never reset)."""
    import psycopg2
    from voalack import schema
    _populate_s4(s4_db)
    _disposition_s4_collisions(s4_db)   # 3a: the operator's collision dispositions
    with psycopg2.connect(s4_db.dsn) as conn:
        schema.apply(conn)
    _q(s4_db.dsn, "UPDATE voalack.instance_config SET observer_enabled = true WHERE instance_id = 'up-active'", fetch=False)
    key = ("up-active", "triggered_alarm", "4711", "alert-lab", "lab-binding", 1)
    _q(s4_db.dsn, "INSERT INTO voalack.observation_chains (instance_id, target_kind, target_id, alert_id, binding_id, "
              "binding_revision) VALUES (%s, %s, %s, %s, %s, %s)", key, fetch=False)
    reads = {}
    for kind in ("stored", "unchanged", "unfinished", "bad"):
        obs, seq = str(uuid.uuid4()), _q(s4_db.dsn, "SELECT nextval('voalack.observation_seq')")[0][0]
        _q(s4_db.dsn, "INSERT INTO voalack.observation_reads (obs_id, alert_id, binding_id, binding_revision, "
                  "instance_id, target_kind, target_id, reservation_seq, reader_generation, reader_incarnation, "
                  "credential_ref, config_revision, provider_contract, acquired_epoch, acquired_head_sha256, eligible) "
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, 'cred-up-active', 2, 'fake-one/v1', 1, %s, '[]')",
           (obs, key[3], key[4], key[5], key[0], key[1], key[2], seq, str(uuid.uuid4()), "a" * 64), fetch=False)
        reads[kind] = (obs, seq)
    for kind in ("stored", "unchanged"):
        _q(s4_db.dsn, "INSERT INTO voalack.observation_completions (obs_id, result, input_sha256, state_sha256, "
                  "classification) VALUES (%s, %s, %s, %s, 'acked')",
           (reads[kind][0], kind, ("b" if kind == "stored" else "c") * 64, "d" * 64), fetch=False)
    _q(s4_db.dsn, "INSERT INTO voalack.source_observations (obs_id, instance_id, target_kind, target_id, alert_id, "
              "binding_id, binding_revision, reservation_seq, state_sha256, classification, summary) "
              "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'acked', '{}')",
       (reads["stored"][0], key[0], key[1], key[2], key[3], key[4], key[5], reads["stored"][1], "d" * 64), fetch=False)
    _q(s4_db.dsn, "INSERT INTO voalack.observation_evidence (obs_id, kind, reason, input_sha256, input_octets) "
              "VALUES (%s, 'bad_summary', 'client_times', %s, 120)", (reads["bad"][0], "e" * 64), fetch=False)
    flags = _q(s4_db.dsn, "SELECT instance_id, config_revision, observer_enabled FROM voalack.instance_config ORDER BY 1")
    assert ("up-active", 2, True) in flags and any(f[2] is False for f in flags), flags
    counts = {t: _q(s4_db.dsn, f"SELECT count(*) FROM {t}")[0][0] for t in OBSERVATION_TABLES}
    assert all(counts.values()), counts                                  # every promised class is nonempty
    observed = _row_sets(s4_db.dsn)
    others = [t for t in _all_tables(s4_db.dsn) if t not in OBSERVATION_TABLES]
    s4_rows = _all_rows(s4_db.dsn, others)
    last_seq = max(seq for _, seq in reads.values())
    last_evidence = _q(s4_db.dsn, "SELECT max(evidence_id) FROM voalack.observation_evidence")[0][0]
    with psycopg2.connect(s4_db.dsn) as conn:
        schema.apply(conn)                                           # the reapplication
    assert _q(s4_db.dsn, "SELECT instance_id, config_revision, observer_enabled FROM voalack.instance_config "
                     "ORDER BY 1") == flags
    assert _row_sets(s4_db.dsn) == observed
    assert _all_rows(s4_db.dsn, others) == s4_rows                       # every pre-existing S4 row unchanged
    assert _q(s4_db.dsn, "SELECT nextval('voalack.observation_seq')")[0][0] == last_seq + 1
    assert _q(s4_db.dsn, "SELECT nextval(pg_get_serial_sequence('voalack.observation_evidence', 'evidence_id'))")[0][0] \
        == last_evidence + 1
    assert _audit_on(s4_db.dsn) == []


# --- supervised restore (W1-W4), bounded by the backup point ------------------------------------------------------

OBSERVATION_TABLES = ("voalack.observation_chains", "voalack.observation_reads", "voalack.observation_completions",
                      "voalack.source_observations", "voalack.observation_evidence")


def _row_sets(dsn, tables=OBSERVATION_TABLES):
    """The full rows of each observation table, as sorted row texts."""
    return {t: sorted(r[0] for r in _q(dsn, f"SELECT x::text FROM {t} x")) for t in tables}


def _appended_only(before, after, new_obs, expected):
    """Every row of ``before`` is still present byte for byte, and the only added rows are ``expected[t]`` rows per
    table, each naming one of ``new_obs``."""
    from collections import Counter
    for t in before:
        assert not Counter(before[t]) - Counter(after[t]), (t, "a backed-up row changed or vanished")
        added = list((Counter(after[t]) - Counter(before[t])).elements())
        assert len(added) == expected.get(t, 0), (t, added)
        assert all(any(o in row for o in new_obs) for row in added), (t, added)


def _seed_observer_history(sib, owner, alert_id):
    """[native] Coherent nonempty history in all five observation tables before the backup: a stored observation,
    an unchanged one, a bad summary (digest-only evidence; its reservation stays unfinished) and an unfinished
    reservation. Returns the unfinished reservation's obs_id."""
    from test_t04_s3c_recovery import _q as _sq, _sql_as_sender
    assert owner.observe(alert_id)["result"] == "stored"
    assert owner.observe(alert_id)["result"] == "unchanged"
    bad = str(uuid.uuid4())
    row = _sql_as_sender(sib, "SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)",
                         (bad, alert_id, owner.instance_id, owner.generation, owner.incarnation))
    assert row["outcome"] == "reserved", row
    rec = _sql_as_sender(sib, "SELECT * FROM voalack.record_observation(%s, %s, %s, %s, %s::jsonb, "
                              "%s::timestamptz, %s::timestamptz)",
                         (bad, owner.instance_id, owner.generation, owner.incarnation, json.dumps(summary()),
                          datetime.now(timezone.utc).isoformat(), None))    # a start without a completion
    assert rec["outcome"] == "bad_summary", rec
    unfinished = str(uuid.uuid4())
    row = _sql_as_sender(sib, "SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)",
                         (unfinished, alert_id, owner.instance_id, owner.generation, owner.incarnation))
    assert row["outcome"] == "reserved", row
    counts = {t: _sq(sib.dsn, f"SELECT count(*) FROM {t}")[0][0] for t in OBSERVATION_TABLES}
    assert all(counts.values()), counts                                  # every promised class is nonempty
    return unfinished


def _reconstructed_reader(sib, instance, fake, owner):
    """[lab reconstruction] A reader rebuilt with the old owner's original identities (generation, incarnation,
    configuration) and its old acquired anchor head; never stopped and never acquired again."""
    from voalack.recovery import Anchor
    from voalack.sender import FakeOneTransport, OwnerSession
    stale = OwnerSession(sib.sender, instance, owner.owner_id, FakeOneTransport(fake.url), anchor=Anchor(sib.anchor))
    stale.generation, stale.incarnation = owner.generation, owner.incarnation
    stale.credential_ref, stale.config, stale.head = owner.credential_ref, owner.config, owner.head
    assert stale.stopped is None and stale.token is None and not stale.journal
    return stale


def _old_reader_is_fenced_by_the_database(sib, instance, fake, owner, alert_id, flag):
    """W2 after adoption: the old owner process was stopped by supervised containment, so its own latch would refuse
    locally; a reconstructed reader with its pins must reach the restored database and be refused there, with no
    login and no GET. Adoption changed the epoch/head and contained the restored owner row, so the database refuses
    by state (check_owner contained, begin_observation owner_fenced, the reader held as fenced); the epoch/head
    clause, which applies only to an active row, is shadowed, and the old pins are shown directly not to match."""
    from test_t04_s3c_recovery import _q as _sq, _sql_as_sender
    assert owner.stopped                                                 # containment stopped the real process
    stale = _reconstructed_reader(sib, instance, fake, owner)
    assert _sq(sib.dsn, "SELECT observer_enabled FROM voalack.instance_config WHERE instance_id = %s",
               (instance,)) == [(flag,)]
    [(generation, incarnation, state, epoch, head)] = _sq(
        sib.dsn, "SELECT owner_generation, incarnation::text, state, acquired_epoch, acquired_head_sha256 "
                 "FROM voalack.session_owners WHERE instance_id = %s", (instance,))
    assert (generation, incarnation, state) == (owner.generation, owner.incarnation, "contained")
    assert _sq(sib.dsn, "SELECT (epoch, head_sha256) = (%s, %s) FROM voalack.recovery_epoch", (epoch, head)) == \
        [(False,)]                                                       # the old pins differ from the current ones
    assert _sq(sib.dsn, "SELECT voalack._epoch_pin(%s, %s, 'ordinary')", (epoch, head)) == [(False,)]
    assert _sq(sib.dsn, "SELECT voalack.check_owner(%s, %s, %s)",
               (instance, owner.generation, owner.incarnation)) == [("contained",)]
    before = (fake.counts["logins"], fake.counts["reads"])
    row = _sql_as_sender(sib, "SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)",
                         (str(uuid.uuid4()), alert_id, instance, owner.generation, owner.incarnation))
    assert row["outcome"] == "owner_fenced", row
    result = stale.observe(alert_id)
    assert (result["outcome"], result["reason"]) == ("held", "fenced"), result
    assert stale.stopped == "fenced"                                     # stopped by the database's answer
    assert (fake.counts["logins"], fake.counts["reads"]) == before
    assert (stale.transport.counts["logins"], stale.transport.counts["reads"]) == (0, 0)
    return before


def _fresh_owner_is_current(sib, instance, fresh):
    """The positive control: the fresh owner acquired after reopen holds the current pins."""
    from test_t04_s3c_recovery import _q as _sq
    assert _sq(sib.dsn, "SELECT voalack.check_owner(%s, %s, %s)",
               (instance, fresh.generation, fresh.incarnation)) == [("active",)]
    assert _sq(sib.dsn, "SELECT voalack._epoch_pin(o.acquired_epoch, o.acquired_head_sha256, 'ordinary') "
                        "FROM voalack.session_owners o WHERE o.instance_id = %s", (instance,)) == [(True,)]


def _fresh_reader_continues(sib, fresh, alert_id, backed_up, max_seq, max_evidence):
    """W4 (enabled): a fresh observation is recorded after the backed-up history with a later reservation number;
    every backed-up row is unchanged and only its own rows are appended; a later bad summary appends evidence with a
    later evidence id (both sequences continue, no collision)."""
    from collections import Counter
    from test_t04_s3c_recovery import _q as _sq, _sql_as_sender
    pre = _row_sets(sib.dsn)
    result = fresh.observe(alert_id)
    assert (result["outcome"], result["result"]) == ("recorded", "stored"), result
    assert _sq(sib.dsn, "SELECT reservation_seq FROM voalack.observation_reads WHERE obs_id = %s",
               (result["obs_id"],))[0][0] > max_seq
    after = _row_sets(sib.dsn)
    _appended_only(pre, after, [result["obs_id"]], {"voalack.observation_reads": 1,
                                                   "voalack.observation_completions": 1,
                                                   "voalack.source_observations": 1})
    bad = str(uuid.uuid4())
    assert _sql_as_sender(sib, "SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)",
                          (bad, alert_id, fresh.instance_id, fresh.generation, fresh.incarnation))["outcome"] == "reserved"
    assert _sql_as_sender(sib, "SELECT * FROM voalack.record_observation(%s, %s, %s, %s, %s::jsonb, "
                               "%s::timestamptz, %s::timestamptz)",
                          (bad, fresh.instance_id, fresh.generation, fresh.incarnation, json.dumps(summary()),
                           datetime.now(timezone.utc).isoformat(), None))["outcome"] == "bad_summary"
    assert _sq(sib.dsn, "SELECT evidence_id FROM voalack.observation_evidence WHERE obs_id = %s",
               (bad,))[0][0] > max_evidence
    _appended_only(after, _row_sets(sib.dsn), [bad], {"voalack.observation_reads": 1,
                                                     "voalack.observation_evidence": 1})
    final = _row_sets(sib.dsn)
    for t in backed_up:                                                  # the backed-up history is never replaced
        assert not Counter(backed_up[t]) - Counter(final[t]), (t, "a backed-up row changed or vanished")


def _maxima(sib):
    from test_t04_s3c_recovery import _q as _sq
    return (_sq(sib.dsn, "SELECT coalesce(max(reservation_seq), 0) FROM voalack.observation_reads")[0][0],
            _sq(sib.dsn, "SELECT coalesce(max(evidence_id), 0) FROM voalack.observation_evidence")[0][0])


@pytest.mark.parametrize("flag", [True, False], ids=["enabled", "disabled"])
def test_s3a_staged_supervised_restore_keeps_backed_up_history_and_fences_old_readers(client, app, instance, fake,
                                                                                       sibling, tmp_path, flag):
    """[native] Voalack-only supervised restore on a sibling database.
    W1: the observation history captured in the backup (enabled: nonempty in all five tables) survives with
        identical full rows; an observation recorded after the backup point is lost (backup-bounded, by deliberate
        exclusion from the inventory); the restored flag is the backed-up flag.
    W2: a lab reader rebuilt with the old owner's pins (not the stopped process) is refused by the restored
        database (the adopted owner row is contained), with no login or GET.
    W3: a reservation from before the backup without a completion stays preserved; a successor cannot record it
        (not_reader) and it grants no GET.
    W4: after supervised reopen and a fresh acquisition, observation proceeds (enabled: every backed-up row
        unchanged, only new rows appended, both sequences continue) or is refused observer_disabled with no login
        and no read (disabled)."""
    from test_t04_s3c_recovery import _owner as _sib_owner, _q as _sq
    from test_t04_s3c_restore import _close_and_inventory, _staged_restore_and_recover
    alert_id = new_alert(client, instance_id=instance)                   # before the copy: bound in the sibling
    sib = sibling()
    _sq(sib.dsn, "UPDATE voalack.instance_config SET observer_enabled = %s WHERE instance_id = %s", (flag, instance),
        fetch=False)
    owner = _sib_owner(sib, instance, fake)
    if flag:
        unfinished = _seed_observer_history(sib, owner, alert_id)
    dump = tmp_path / "observer-backup.dump"
    sib.dump(dump)                                                       # the backup point
    backed_up = _row_sets(sib.dsn)
    max_seq, max_evidence = _maxima(sib)
    if flag:
        fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True}   # [inject] a change
        assert owner.observe(alert_id)["result"] == "stored"                                     # after the backup
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527, extended to these IDs a8dc7cd2): the steps
    # above are unchanged; the backup-bound recover is refused as staged. The original post-recovery oracles (at
    # f2395b2a) are an explicit S3c debt, re-proved with the admitted restore there.
    _staged_restore_and_recover(sib, inventory_sha, dump, fake=fake)


def test_the_shared_restore_procedure_keeps_observer_history_and_fences_old_readers(client, app, instance, fake,
                                                                                    tmp_path, full_sibling):
    """[native] The same W1-W4 with the observer enabled and nonempty history, through the actual shared-database
    procedure (restore_shared, validated journal, shared recover and reopen) on a full sibling; before adoption the
    database alone answers active for the old pins and the external anchor fences a reconstructed old reader; the
    capture contract holds after the procedure."""
    from test_t04_s3c_recovery import _owner as _sib_owner, _q as _sq, _sql_as_sender
    from test_t04_s3c_restore import _close_and_inventory
    from test_t04_s4_shared_restore import _contract, _review
    from voalack import recovery
    alert_id = new_alert(client, instance_id=instance)
    sib = full_sibling()
    _sq(sib.dsn, "UPDATE voalack.instance_config SET observer_enabled = true WHERE instance_id = %s", (instance,),
        fetch=False)
    owner = _sib_owner(sib, instance, fake)
    unfinished = _seed_observer_history(sib, owner, alert_id)
    dump = tmp_path / "shared-observer.dump"
    sib.dump(dump)                                                       # the backup point
    backed_up = _row_sets(sib.dsn)
    max_seq, max_evidence = _maxima(sib)
    fake.alarms["4711"] = {"target_id": "4711", "kind": "triggered_alarm", "acked": True}       # [inject] a change
    assert owner.observe(alert_id)["result"] == "stored"                                         # after the backup
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    journal = tmp_path / "journal"
    journal.mkdir()
    # Coexistence 3a S3a (converted openly; S2/S3 records kept): the restore is staged-refused before any change, so
    # W1-W4 through the shared procedure are re-proved in S3c. Here: refused; the observer history and the post-backup
    # observation are exactly as before the attempt, the journal holds only 'begin', and the contract holds.
    current = _row_sets(sib.dsn)
    with pytest.raises(recovery.RestoreRefused, match="restore is staged"):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
    assert _row_sets(sib.dsn) == current and current != backed_up
    assert recovery.RestoreJournal(str(journal), inventory_sha).steps() == ["begin"]
    assert _contract(sib.dsn) == []


def _blocked_by(dsn, holder_pid, pattern, seconds=10.0):
    """[native] the pid of a backend in a Lock wait whose blockers include ``holder_pid`` and whose query matches
    ``pattern``; None if not seen within ``seconds``."""
    import time as _time
    limit = _time.monotonic() + seconds
    while _time.monotonic() < limit:
        rows = _q(dsn, "SELECT pid FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                       "AND %s = ANY(pg_blocking_pids(pid)) AND query ~ %s", (holder_pid, pattern))
        if rows:
            return rows[0][0]
        _time.sleep(0.05)
    return None


def test_a_recovery_close_waits_for_an_admitted_record_to_commit(client, app, instance, fake, sibling):
    """[native] epoch-lock ordering on the observer path through COMMIT: a record admitted in an open transaction
    holds the recovery epoch row FOR SHARE (the admission's epoch pin); the supervisor's close, which updates that
    row, is seen blocked by exactly that backend; when the record commits, the close completes; the stored row is
    from before the close, and the owner is then fenced (observe holds, no login or GET)."""
    import threading
    import psycopg2
    import psycopg2.extras
    from test_t04_s3c_recovery import _owner as _sib_owner, _q as _sq
    from voalack import recovery
    alert_id = new_alert(client, instance_id=instance)
    sib = sibling()
    _sq(sib.dsn, "UPDATE voalack.instance_config SET observer_enabled = true WHERE instance_id = %s", (instance,),
        fetch=False)
    owner = _sib_owner(sib, instance, fake)
    obs = str(uuid.uuid4())
    a = psycopg2.connect(sib.sender)
    cur = a.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    out = {}

    def close():
        try:
            recovery.close(sib.anchor, sib.dsn)
            out["closed"] = True
        except Exception as exc:                                         # reported, asserted below
            out["error"] = f"{type(exc).__name__}: {exc}"
    worker = threading.Thread(target=close)
    try:
        cur.execute("SELECT * FROM voalack.begin_observation(%s, %s, %s, %s, %s)",
                    (obs, alert_id, instance, owner.generation, owner.incarnation))
        assert cur.fetchone()["outcome"] == "reserved"
        a.commit()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("SELECT * FROM voalack.record_observation(%s, %s, %s, %s, %s::jsonb, %s::timestamptz, "
                    "%s::timestamptz)", (obs, instance, owner.generation, owner.incarnation, json.dumps(summary()),
                                         now, now))
        assert cur.fetchone()["r_result"] == "stored"                 # admitted, not committed: epoch row pinned
        cur.execute("SELECT pg_backend_pid() AS pid")
        holder = cur.fetchone()["pid"]
        worker.start()
        waiter = _blocked_by(sib.dsn, holder, "close_recovery|recovery_epoch")
        assert waiter is not None, "the close never waited on the admitted record"
        assert worker.is_alive() and "closed" not in out
        a.commit()                                                       # the record commits first
    finally:
        a.close()
        if worker.ident is not None:
            worker.join(30)
    assert "error" not in out and out.get("closed") is True, out
    assert _sq(sib.dsn, "SELECT phase FROM voalack.recovery_epoch")[0][0] != "open"
    assert _sq(sib.dsn, "SELECT count(*) FROM voalack.source_observations WHERE obs_id = %s", (obs,))[0][0] == 1
    before = (fake.counts["logins"], fake.counts["reads"])
    assert owner.observe(alert_id)["outcome"] == "held"
    assert (fake.counts["logins"], fake.counts["reads"]) == before


@pytest.mark.parametrize("observed", [False, True], ids=["without_observation", "with_observation"])
@pytest.mark.parametrize("variant", ["eligible", "ineligible"])
def test_s3a_staged_coincident_observation_changes_no_recovery_settlement(client, app, instance, fake, sibling,
                                                                         tmp_path, variant, observed):
    """[native] recovery path (r3 C4): a held attempt lost by a supervised restore is read in maintenance; its
    recovery reconciliation id is made to equal a restored observation's reservation_seq (with_observation) or no
    observation exists (without_observation). Recording the observations changes no fact row. An unknown id (one
    that is no recovery reconciliation; with_observation it is another observation's reservation_seq) is refused
    wrong_reconciliation, and the outcome the read does not support is refused classification_mismatch; neither
    refusal changes a fact row. The outcome the read supports then settles: eligible, recovered_attributed on an
    attributable read; ineligible (ineligible for attributable settlement), recovered_retired on a not_acked read,
    which that read legitimately supports. The hold is released exactly as without any observation."""
    from test_t04_s2_sender import _effect
    from test_t04_s3c_recovery import _owner as _sib_owner, _q as _sq
    from test_t04_s3c_restore import _close_and_inventory, _staged_restore_and_recover
    first = _effect(client, app, instance, occurrence_ref="lab-occ-s3-collision")
    other = new_alert(client, instance_id=instance, target_id="4712")     # the observation's alert, another key
    third = new_alert(client, instance_id=instance, target_id="4713")     # the unknown id's observation
    sib = sibling()
    _sq(sib.dsn, "UPDATE voalack.instance_config SET observer_enabled = true WHERE instance_id = %s", (instance,),
        fetch=False)
    seq, unknown = 700001, 700501
    if observed:
        owner = _sib_owner(sib, instance, fake, owner_id="lab-observer")
        owner.login()                                                   # its provider session row first
        before = _fingerprints(sib.dsn)
        for alert_id, number in ((other, seq), (third, unknown)):
            _sq(sib.dsn, "SELECT setval('voalack.observation_seq', %s, false)", (number,), fetch=False)
            result = owner.observe(alert_id)
            assert result["outcome"] == "recorded", result
            assert _sq(sib.dsn, "SELECT reservation_seq FROM voalack.observation_reads WHERE obs_id = %s",
                       (result["obs_id"],))[0][0] == number
        assert _fingerprints(sib.dsn) == before                         # the observations alone change nothing
        owner.stop("lab")                                               # a later owner sends
        _sq(sib.dsn, "SELECT voalack.record_containment(%s, %s, %s::jsonb)",
            (instance, owner.generation, json.dumps({"process_stopped": True, "no_requests_executing": True,
                                                    "basis": "lab: observer stopped"})), fetch=False)
    dump = tmp_path / "before-dispatch.dump"
    sib.dump(dump)
    sender_owner = _sib_owner(sib, instance, fake, owner_id="lab-sender")
    fake.script["ack"] = "close_after_body" if variant == "eligible" else "close_before_body"
    sent = sender_owner.apply_once(first)
    assert sent["outcome"] == "uncertain", sent
    fake.script["ack"] = "success"
    inventory_sha = _close_and_inventory(sib, instance, fake, [sender_owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527, extended to these IDs a8dc7cd2): the steps
    # above are unchanged; the backup-bound recover is refused as staged. The original post-recovery oracles (at
    # f2395b2a) are an explicit S3c debt, re-proved with the admitted restore there.
    _staged_restore_and_recover(sib, inventory_sha, dump, fake=fake)


