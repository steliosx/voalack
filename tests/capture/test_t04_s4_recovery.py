"""T04 S4: outcome events and projection across the supervised recovery procedure (r2 R2/R5, r3 C1/C3,
D1-D7), natively on sibling databases.

The S3c procedure helpers are reused unchanged. ``full_sibling`` copies the whole lab database (Alerta's
public tables, voalack and voalack_publication) so that notes and alerts exist; the supported restore is
still exactly ``Sibling.restore`` of a ``-n voalack`` dump, which leaves public and voalack_publication
untouched.
"""
import hashlib
import os
import shutil
import threading
import time
import uuid

import psycopg2
import psycopg2.extras
import pytest

from conftest import DSN, LAB_ANCHOR_DIR, clone_database
from test_t04_s2_sender import _effect, fake, instance  # noqa: F401
from test_t04_s3c_recovery import (SETTLER_LOGIN, Sibling, _admin, _dsn, _owner, _q, _run,  # noqa: F401
                                   sibling)
from test_t04_s3c_restore import (PRIVILEGES, _capture, _close_and_inventory, _files, _holds, _maintenance,
                                  _promote, _settler_dsn)
from test_t04_s4_projection import check_identities_on, note_id
from voalack import projector, recovery, sender, settler, verifier
from voalack.recovery import Anchor

PROJECTOR_LOGIN = "lab_projector:lab-only-projector"
VERIFIER_LOGIN = "lab_verifier:lab-only-verifier"


@pytest.fixture
def full_sibling(app, tmp_path):
    """Factory: a copy of the whole lab database in a new database, with a copy of the lab anchor."""
    made = []

    def make():
        name = f"voalack_s4_{uuid.uuid4().hex[:8]}"
        dump = tmp_path / f"{name}-full.dump"
        _run(["pg_dump", "-Fc", "-f", str(dump), DSN])
        _admin(f"CREATE DATABASE {name}")
        made.append(name)
        dsn = _dsn(name)
        clone_database(dump, dsn)                          # 3a S3a: guard-aware lab clone
        _q(dsn, PRIVILEGES, fetch=False)
        anchor_dir = tmp_path / f"{name}-anchor"
        shutil.copytree(LAB_ANCHOR_DIR, anchor_dir)
        return Sibling(name, dsn, _dsn(name, "lab_sender:lab-only-sender"), str(anchor_dir))
    yield make
    for name in made:
        _admin(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


def rows(dsn, statement, args=()):
    with psycopg2.connect(dsn) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(statement, args)
        return [dict(r) for r in cur.fetchall()] if cur.description else []


def events(sib, action):
    return rows(sib.dsn, "SELECT * FROM voalack.outcome_events WHERE action_id = %s ORDER BY revision", (action,))


def markers(sib, action):
    return rows(sib.dsn, "SELECT revision, epoch, status, detail FROM voalack.projections WHERE action_id = %s "
                         "ORDER BY revision", (action,))


def publications(sib, action):
    return rows(sib.dsn, "SELECT * FROM voalack_publication.publications WHERE action_id = %s "
                         "ORDER BY epoch, revision", (action,))


def all_publications(sib):
    return rows(sib.dsn, "SELECT * FROM voalack_publication.publications ORDER BY note_id")


def drain(sib):
    out = []
    while True:
        batch = projector.run(_dsn(sib.name, PROJECTOR_LOGIN), sib.anchor, "lab-s4-projector", max_steps=500)
        out.extend(batch)
        if batch[-1]["outcome"] != "done":
            return out


def action_of(sib, effect_id):
    return _q(sib.dsn, "SELECT action_id::text FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0][0]


def publication_catalog(sib):
    """Owner, ACLs, triggers and constraints of the protected schema, as the catalog has them."""
    return {
        "schema": _q(sib.dsn, "SELECT pg_get_userbyid(nspowner), nspacl::text FROM pg_namespace "
                              "WHERE nspname = 'voalack_publication'"),
        "table": _q(sib.dsn, "SELECT pg_get_userbyid(c.relowner), c.relacl::text FROM pg_class c "
                             "JOIN pg_namespace n ON n.oid = c.relnamespace "
                             "WHERE n.nspname = 'voalack_publication' AND c.relname = 'publications'"),
        "triggers": _q(sib.dsn, "SELECT t.tgname, t.tgtype, t.tgenabled, t.tgfoid::regprocedure::text FROM pg_trigger t "
                                "WHERE t.tgrelid = 'voalack_publication.publications'::regclass AND NOT t.tgisinternal "
                                "ORDER BY 1"),
        "constraints": _q(sib.dsn, "SELECT conname, contype, pg_get_constraintdef(oid) FROM pg_constraint "
                                   "WHERE conrelid = 'voalack_publication.publications'::regclass ORDER BY 1"),
        "function": _q(sib.dsn, "SELECT pg_get_userbyid(p.proowner), p.prosecdef, p.proconfig, p.proacl::text "
                                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                                "WHERE n.nspname = 'voalack_publication'"),
    }


def layout_of(sib):
    """The layout each fixture declares (never inferred from the catalog): full copies are shared with
    Alerta; the S3c sibling copies are Voalack-only."""
    return "shared" if sib.name.startswith("voalack_s4_") else "voalack_only"


def journal_of(sib):
    journal = os.path.join(os.path.dirname(sib.anchor), f"{sib.name}-journal")
    os.makedirs(journal, exist_ok=True)
    return journal


def _restore_only(sib, inventory_sha, dump):
    """The supported restore through the supervisor procedure (D9), only under the inventoried anchor;
    the anchor files are unchanged by it."""
    before = _files(sib.anchor)
    assert recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, journal_of(sib),
                                   layout=layout_of(sib)) == "validated"
    assert _files(sib.anchor) == before
    with open(dump, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _recover(sib, inventory_sha, dump, backup_sha256):
    review = recovery.write_review(sib.anchor, {"ref": "lab review", "backup_id": f"lab-dump:{os.path.basename(str(dump))}",
                                                "backup_sha256": backup_sha256, "inventory_sha256": inventory_sha,
                                                "decision": "adopt"})
    return recovery.recover(sib.anchor, sib.dsn, review, layout=layout_of(sib), journal_dir=journal_of(sib))


def _reopen(sib, instance, fake):
    return recovery.reopen(sib.anchor, sib.dsn, layout=layout_of(sib), journal_dir=journal_of(sib))


# --- D2, R2, C3: a supported restore under published notes ---------------------------------------------

def test_publications_survive_the_restore_and_order_the_new_lineage(client, app, instance, fake, full_sibling,
                                                                    tmp_path):
    effect_id = _effect(client, app, instance)
    sib = full_sibling()
    action = action_of(sib, effect_id)
    e0 = Anchor(sib.anchor).head().epoch
    dump = tmp_path / "unprojected.dump"
    sib.dump(dump)                                               # (e0, 1) queued, not yet projected
    drain(sib)                                                   # copied lab events, and (e0, 1)
    owner = _owner(sib, instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    drain(sib)
    assert [(p["epoch"], p["revision"]) for p in publications(sib, action)] == [(e0, 1), (e0, 2)]
    pubs_before, catalog_before = all_publications(sib), publication_catalog(sib)
    notes_before = _q(sib.dsn, "SELECT count(*) FROM public.notes")[0][0]

    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    assert drain(sib)[-1]["outcome"] == "paused"                  # R5: closed, nothing written
    # Coexistence 3a S3a (converted openly; S2 records kept): the restore is staged-refused before any change, so the
    # S2 oracles that follow it (D2 survival, R5 open-row pause, C3 epoch, R2/C1 ordering, the held note) are
    # re-proved in S3c. Here: refused, and the publications, catalog and notes are exactly as before; still paused.
    with pytest.raises(recovery.RestoreRefused, match="restore is staged"):
        _restore_only(sib, inventory_sha, dump)
    assert all_publications(sib) == pubs_before and publication_catalog(sib) == catalog_before
    assert _q(sib.dsn, "SELECT count(*) FROM public.notes")[0][0] == notes_before
    assert drain(sib)[-1]["outcome"] == "paused"


def test_reused_revision_after_restore_is_a_visible_publication_conflict(client, app, instance, fake, full_sibling,
                                                                         tmp_path):
    """A capture promoted again in the restored database before adoption (the restored row reads open)
    reuses revision 1 of epoch e0 with other content: never published over the recorded publication."""
    action = _capture(client, instance)
    sib = full_sibling()
    dump = tmp_path / "before-promotion.dump"
    sib.dump(dump)
    e0 = Anchor(sib.anchor).head().epoch
    effect_id = _promote(app, sib, action)
    owner = _owner(sib, instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    drain(sib)
    old = publications(sib, action)
    assert [(p["epoch"], p["revision"]) for p in old] == [(e0, 1), (e0, 2)]
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a (converted openly; S2 records kept): the restore is staged-refused before any change, so the
    # reused-revision conflict after a restore is re-proved in S3c. Here: refused, the publications unchanged.
    with pytest.raises(recovery.RestoreRefused, match="restore is staged"):
        _restore_only(sib, inventory_sha, dump)
    assert publications(sib, action) == old


def test_a_lower_event_is_superseded_by_a_recorded_higher_publication(client, app, instance, full_sibling):
    """Branch witness: a recorded publication above an unprojected event (inserted directly by the lab
    superuser for this witness) makes the event history only: a marker, no note, no publication."""
    effect_id = _effect(client, app, instance)
    sib = full_sibling()
    action = action_of(sib, effect_id)
    with psycopg2.connect(sib.dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT epoch, alert_id, customer FROM voalack.outcome_events WHERE action_id = %s", (action,))
        epoch, alert_id, customer = cur.fetchone()
        cur.execute("INSERT INTO voalack_publication.publications (note_id, action_id, epoch, revision, event_sha256, "
                    "note_row_sha256, alert_id, customer) VALUES (%s, %s, %s, 9, %s, %s, %s, %s)",
                    (note_id("a" * 64), action, epoch, "a" * 64, "b" * 64, alert_id, customer))
    drain(sib)
    assert [(m["revision"], m["status"], m["detail"]) for m in markers(sib, action)] == \
           [(1, "superseded_by_publication", f"high-water {epoch}:9")]
    assert _q(sib.dsn, "SELECT count(*) FROM public.notes WHERE attributes->'voalack'->>'action_id' = %s",
              (action,))[0][0] == 0


# --- D1: promotion pins the epoch ------------------------------------------------------------------------

def _verify(app, sib, action):
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(_dsn(sib.name, VERIFIER_LOGIN)) as conn:
        return verifier.run_once(conn, "lab-verifier-s4", signing.ctx, signing.keys, action_id=action)


def test_promotion_defers_unless_the_database_is_open(client, app, instance, fake, sibling):
    action = _capture(client, instance)
    sib = sibling()
    recovery.close(sib.anchor, sib.dsn)
    result = _verify(app, sib, action)
    assert (result["outcome"], result["reason"]) == ("deferred", "recovery_not_open"), result
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.verifications WHERE action_id = %s", (action,))[0][0] == 0
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.effects WHERE action_id = %s", (action,))[0][0] == 0
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.outcome_events WHERE action_id = %s", (action,))[0][0] == 0
    _q(sib.dsn, "DELETE FROM voalack.recovery_epoch", fetch=False)
    _q(sib.dsn, "UPDATE voalack.verification_claims SET lease_until = now() WHERE action_id = %s", (action,),
       fetch=False)
    result = _verify(app, sib, action)
    assert (result["outcome"], result["reason"]) == ("deferred", "recovery_uninitialized"), result
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.effects WHERE action_id = %s", (action,))[0][0] == 0


def test_promotion_waiting_behind_a_close_sees_the_close(client, app, instance, sibling):
    """[native] The close holds recovery_epoch FOR UPDATE; the promotion's pin waits, then re-reads the
    locked row, sees 'closed' and defers with nothing recorded."""
    action = _capture(client, instance)
    sib = sibling()
    blocker = psycopg2.connect(sib.dsn)
    cur = blocker.cursor()
    cur.execute("SELECT * FROM voalack.recovery_epoch FOR UPDATE")
    out = {}
    thread = threading.Thread(target=lambda: out.setdefault("r", _verify(app, sib, action)))
    thread.start()
    for _ in range(100):
        waiting = _q(sib.dsn, "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                              "WHERE NOT l.granted AND a.usename = 'lab_verifier'")[0][0]
        if waiting:
            break
        time.sleep(0.05)
    assert waiting, "the promotion did not wait on the epoch row"
    cur.execute("UPDATE voalack.recovery_epoch SET phase = 'closed', head_seq = head_seq + 1, "
                "head_sha256 = repeat('c', 64)")
    blocker.commit()
    blocker.close()
    thread.join(10)
    assert (out["r"]["outcome"], out["r"]["reason"]) == ("deferred", "recovery_not_open"), out
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.effects WHERE action_id = %s", (action,))[0][0] == 0


# --- C3: hold events carry the new epoch; the release event comes from the settlement --------------------

def test_hold_events_carry_the_adoption_epoch_and_the_exact_release_outcome(client, app, instance, fake, sibling,
                                                                            tmp_path):
    first = _effect(client, app, instance, occurrence_ref="lab-occ-s4-a")
    second = _effect(client, app, instance, occurrence_ref="lab-occ-s4-b")      # same physical key
    sib = sibling()
    dump = tmp_path / "before-dispatch.dump"
    sib.dump(dump)
    e0 = Anchor(sib.anchor).head().epoch
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_after_body"
    sent = owner.apply_once(first)
    assert sent["outcome"] == "uncertain", sent
    fake.script["ack"] = "success"
    a_first, a_second = action_of(sib, first), action_of(sib, second)
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a (converted openly; S2 records kept): this Voalack-only sibling copies a 3a-era voalack schema
    # (voalack.protections_intact present) without its guard or lifetime schemas, a recognised installation with its
    # guard missing, so the restore is staged-refused before any change. The hold events across adoption and the
    # exact release outcome are re-proved in S3c. Here: refused; the actions' events are exactly as before.
    before = (events(sib, a_first), events(sib, a_second))
    with pytest.raises(recovery.RestoreRefused, match="restore is staged"):
        _restore_only(sib, inventory_sha, dump)
    assert (events(sib, a_first), events(sib, a_second)) == before
    assert [(e["revision"], e["epoch"]) for e in before[0]][:1] == [(1, e0)]


# --- R4 and D5: readiness refuses event-trigger and publication drift ------------------------------------

PROFILE_LOGINS = {"verifier": (VERIFIER_LOGIN, verifier.VERIFIER), "sender": ("lab_sender:lab-only-sender", sender.SENDER),
                  "settler": (SETTLER_LOGIN, settler.SETTLER), "projector": (PROJECTOR_LOGIN, projector.PROJECTOR)}

EVENT_DRIFT = {
    "dropped": ("DROP TRIGGER settlements_outcome ON voalack.settlements", {"sender", "settler", "projector"}),
    "before": ("DROP TRIGGER effects_outcome_insert ON voalack.effects; "
               "CREATE TRIGGER effects_outcome_insert BEFORE INSERT ON voalack.effects "
               "FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event()", {"verifier", "projector"}),
    "no_column_list": ("DROP TRIGGER effects_outcome_state ON voalack.effects; "
                       "CREATE TRIGGER effects_outcome_state AFTER UPDATE ON voalack.effects "
                       "FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event()", {"sender", "settler", "projector"}),
    "when": ("DROP TRIGGER recovery_settlements_outcome ON voalack.recovery_settlements; "
             "CREATE TRIGGER recovery_settlements_outcome AFTER INSERT ON voalack.recovery_settlements FOR EACH ROW "
             "WHEN (NEW.outcome <> 'recovered_retired') EXECUTE FUNCTION voalack._outcome_event()",
             {"settler", "projector"}),
    "disabled": ("ALTER TABLE voalack.recovered_holds DISABLE TRIGGER recovered_holds_outcome", {"projector"}),
    "replica": ("ALTER TABLE voalack.effects ENABLE REPLICA TRIGGER effects_outcome_state",
                {"sender", "settler", "projector"}),
    "deferred": ("DROP TRIGGER settlements_outcome ON voalack.settlements; "
                 "CREATE CONSTRAINT TRIGGER settlements_outcome AFTER INSERT ON voalack.settlements "
                 "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event()",
                 {"sender", "settler", "projector"}),
    "other_function": ("DROP TRIGGER recovered_effects_outcome ON voalack.recovered_effects; "
                       "CREATE TRIGGER recovered_effects_outcome AFTER INSERT ON voalack.recovered_effects "
                       "FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change()", {"projector"}),
}


@pytest.mark.parametrize("drift", sorted(EVENT_DRIFT))
def test_readiness_refuses_event_trigger_drift(app, sibling, drift):
    sib = sibling()
    statement, failing = EVENT_DRIFT[drift]
    _q(sib.dsn, statement, fetch=False)
    for name, (login, profile) in PROFILE_LOGINS.items():
        with psycopg2.connect(_dsn(sib.name, login)) as conn:
            if name in failing:
                with pytest.raises(verifier.NotReady, match="event_trigger_drift"):
                    verifier.check_ready(conn, profile)
            else:
                verifier.check_ready(conn, profile)
    assert _q(sib.dsn, "SELECT voalack._event_coverage_ready()")[0][0] is False
    with pytest.raises(psycopg2.errors.RaiseException, match="coverage is incomplete"):
        _q(sib.dsn, "SELECT voalack.backfill_projection_snapshot()")


PUBLICATION_DRIFT = {
    "granted_to_sender": ("GRANT USAGE ON SCHEMA voalack_publication TO voalack_sender; "
                          "GRANT SELECT ON voalack_publication.publications TO voalack_sender",
                          {"sender"}, "publication_access"),
    "granted_to_public": ("GRANT SELECT ON voalack_publication.publications TO PUBLIC",
                          set(PROFILE_LOGINS), "publication_access"),
    "projector_member_of_owner": ("GRANT voalack_admin TO lab_projector", {"projector"}, "publication_access"),
    "owner": ("ALTER TABLE voalack_publication.publications OWNER TO lab_admin",
              set(PROFILE_LOGINS), "publication_schema_drift"),
    "definer_guard": ("ALTER FUNCTION voalack_publication.refuse_change() SECURITY DEFINER",
                      set(PROFILE_LOGINS), "publication_schema_drift"),
    "truncate_guard_dropped": ("DROP TRIGGER publications_no_truncate ON voalack_publication.publications",
                               set(PROFILE_LOGINS), "publication_guard_drift"),
    "unique_dropped": ("ALTER TABLE voalack_publication.publications "
                       "DROP CONSTRAINT publications_action_id_epoch_revision_key",
                       set(PROFILE_LOGINS), "publication_guard_drift"),
}


@pytest.mark.parametrize("drift", sorted(PUBLICATION_DRIFT))
def test_readiness_refuses_publication_drift(app, sibling, drift):
    sib = sibling()
    statement, failing, condition = PUBLICATION_DRIFT[drift]
    _q(sib.dsn, statement, fetch=False)
    try:
        for name, (login, profile) in PROFILE_LOGINS.items():
            with psycopg2.connect(_dsn(sib.name, login)) as conn:
                if name in failing:
                    with pytest.raises(verifier.NotReady, match=condition):
                        verifier.check_ready(conn, profile)
                else:
                    verifier.check_ready(conn, profile)
    finally:
        if drift == "projector_member_of_owner":
            _q(sib.dsn, "REVOKE voalack_admin FROM lab_projector", fetch=False)   # a cluster-wide role grant


# --- r1 §6: snapshot backfill -----------------------------------------------------------------------------

def test_backfill_creates_one_snapshot_per_action_without_events(client, app, instance, sibling):
    effect_id = _effect(client, app, instance)
    sib = sibling()
    action = action_of(sib, effect_id)
    with psycopg2.connect(sib.dsn) as conn, conn.cursor() as cur:   # history from before the triggers existed
        cur.execute("SET session_replication_role = replica")
        cur.execute("DELETE FROM voalack.outcome_events WHERE action_id = %s", (action,))
        cur.execute("DELETE FROM voalack.projection_actions WHERE action_id = %s", (action,))
    made = _q(sib.dsn, "SELECT voalack.backfill_projection_snapshot()")[0][0]
    assert made >= 1
    evs = events(sib, action)
    assert [(e["revision"], e["outcome"]) for e in evs] == [(1, "snapshot:queued")]
    assert "snapshot of the recorded outcome (queued); historical time unknown" in evs[0]["note_text"]
    assert evs[0]["facts"]["historical_time"] == "unknown"
    assert _q(sib.dsn, "SELECT voalack.backfill_projection_snapshot()")[0][0] == 0      # idempotent
    assert len(events(sib, action)) == 1
    check_identities_on(sib.dsn, action)


def test_the_gate_precedes_every_projection_write(client, app, instance, full_sibling):
    """R5: closed at the anchor and in the database, a pending event whose alert is gone produces no
    conflict marker, no position change and no note: 'paused' comes before any write. The copy is drained
    first and the capture promoted inside it, so this event is the only pending one (the projector would
    otherwise pause on an older event before reaching it)."""
    action = _capture(client, instance)
    sib = full_sibling()
    drain(sib)
    _promote(app, sib, action)
    pending = _q(sib.dsn, "SELECT count(*) FROM voalack.projection_actions x "
                          "LEFT JOIN voalack.projection_positions p ON p.action_id = x.action_id "
                          "WHERE x.last_revision > coalesce(p.last_projected_revision, 0) "
                          "AND NOT EXISTS (SELECT 1 FROM voalack.projections m WHERE m.action_id = x.action_id "
                          "AND m.revision = coalesce(p.last_projected_revision, 0) + 1)")[0][0]
    assert pending == 1
    alert_id = _q(sib.dsn, "SELECT alert_id FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0][0]
    _q(sib.dsn, "DELETE FROM public.alerts WHERE id = %s", (alert_id,), fetch=False)
    recovery.close(sib.anchor, sib.dsn)
    marks = _q(sib.dsn, "SELECT count(*) FROM voalack.projections")[0][0]
    assert drain(sib)[-1]["outcome"] == "paused"
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.projections")[0][0] == marks
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.projection_positions WHERE action_id = %s", (action,))[0][0] == 0


# --- the transaction markers are not capabilities (caller-settable custom settings) ----------------------

RUNTIME_LOGINS = {"app": "alerta:lab-only-synthetic", "verifier": VERIFIER_LOGIN, "sender": "lab_sender:lab-only-sender",
                  "settler": SETTLER_LOGIN, "projector": PROJECTOR_LOGIN}
FORGE = ("SELECT set_config('voalack.epoch_pin', txid_current()::text, true), "
         "set_config('voalack.schema_migration', txid_current()::text, true)")


@pytest.mark.parametrize("login", sorted(RUNTIME_LOGINS))
def test_a_forged_marker_authorizes_no_runtime_write(app, sibling, login):
    """Every runtime login can set the markers; none can then write an event source or call a private
    helper (privileges, not the marker, protect them)."""
    sib = sibling()
    statements = [
        "UPDATE voalack.effects SET state = 'BLOCKED'",
        "INSERT INTO voalack.settlements (decision_id) VALUES (gen_random_uuid())",
        "INSERT INTO voalack.recovered_effects (effect_key, adoption_id) VALUES ('x', 0)",
        "INSERT INTO voalack.recovered_holds (adoption_id) VALUES (0)",
        "INSERT INTO voalack.recovery_settlements (decision_id) VALUES (gen_random_uuid())",
        "INSERT INTO voalack.outcome_events (action_id) VALUES (gen_random_uuid())",
        "SELECT voalack._append_event(gen_random_uuid(), 'queued', '{}'::jsonb)",
        "SELECT voalack._pin_epoch()",
        "SELECT voalack._outcome_event()",
    ]
    for statement in statements:
        with psycopg2.connect(_dsn(sib.name, RUNTIME_LOGINS[login])) as conn, conn.cursor() as cur:
            cur.execute(FORGE)
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute(statement)


@pytest.mark.parametrize("forged, refusal", [
    ("schema_migration", "pinned the recovery epoch row first"),       # the former pre-bootstrap selector
    ("epoch_pin", "needs an initialized recovery epoch"),               # passes the marker check; no row
])
def test_a_forged_marker_cannot_select_the_pre_bootstrap_branch(client, app, instance, fake, sibling, forged, refusal):
    """Before bootstrap (no epoch row) a producer fails closed for a runtime login that forged one marker:
    the effect change and its missing event roll back together. Each marker is forged alone, so each guard
    is exercised on its own."""
    from test_t04_s2_sender import _owner as lab_owner
    effect_id = _effect(client, app, instance)
    owner = lab_owner(instance, fake)
    attempt = str(uuid.uuid4())
    with psycopg2.connect(_dsn("alerta", "lab_sender:lab-only-sender")) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)",
                    (attempt, effect_id, instance, owner.generation, owner.incarnation))
    sib = sibling()
    _q(sib.dsn, "DELETE FROM voalack.recovery_epoch", fetch=False)
    with psycopg2.connect(sib.sender) as conn, conn.cursor() as cur:
        cur.execute(f"SELECT set_config('voalack.{forged}', txid_current()::text, true)")
        with pytest.raises(psycopg2.errors.RaiseException, match=refusal):
            cur.execute("SELECT voalack.hold_attempt(%s, %s, %s, %s, 'lab: forged marker')",
                        (attempt, instance, owner.generation, owner.incarnation))
    assert _q(sib.dsn, "SELECT state FROM voalack.attempts WHERE attempt_id = %s", (attempt,))[0][0] == "started"
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.outcome_events WHERE action_id = %s",
              (action_of(sib, effect_id),))[0][0] == 1