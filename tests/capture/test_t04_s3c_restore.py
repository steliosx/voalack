"""T04 S3c: supervised recovery of a restored database (spec r1, milestone M2; design response
1dae56ab C1, C2, C4, C5, C8).

Every case runs the supervised procedure natively on a sibling database (see
test_t04_s3c_recovery): close (anchor, then database) -> stop, contain and quiesce every owner
(revocation and executing = 0 at the fake provider) -> inventory -> pg_restore of an earlier dump,
only while the anchor names that inventory -> review -> recovering line and adoption -> maintenance
reads and hold settlement -> reopen. The anchor directory's files are hashed around every restore.
Counts: ACK connects and writes, provider receipts and effects, logins and reads.
"""
import hashlib
import json
import os
import threading
import time
import uuid

import psycopg2
import pytest

from conftest import OPERATOR, VERIFIER_DSN, ack, new_alert, sql
from test_t04_s2_sender import _effect, fake, instance  # noqa: F401
from test_t04_s3b_settlement import _lab, _now, _quiescence_evidence
from test_t04_s3c_recovery import SETTLER_LOGIN, _net, _owner, _q, _sql_as_sender, sibling  # noqa: F401
from voalack import recovery, settler, verifier
from voalack.recovery import Anchor, AnchorConflict, AnchorInvalid, Supervisor
from voalack.sender import FakeOneTransport, OwnerSession, OwnerStopped

PRIVILEGES = "ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"


def _settler_dsn(sib):
    return sib.dsn.replace("lab_admin:lab-only-admin", SETTLER_LOGIN)


def _files(directory):
    """[file] sha256 of every file in the anchor directory (the lock file excepted)."""
    out = {}
    for name in sorted(os.listdir(directory)):
        if name != recovery.LOCK:
            with open(os.path.join(directory, name), "rb") as handle:
                out[name] = hashlib.sha256(handle.read()).hexdigest()
    return out


def _sessions(sib, instance, owner):
    return [r[0] for r in _q(sib.dsn, "SELECT session_ref FROM voalack.provider_sessions WHERE instance_id = %s "
                                      "AND owner_generation = %s AND incarnation = %s ORDER BY opened_at",
                             (instance, owner.generation, owner.incarnation))]


def _contain(sib, instance, owner, fake, quiesce=True):
    """[native] The supervisor stops the process, records its containment, revokes each of its
    sessions at the provider and records the observed quiescence."""
    owner.stop("lab: supervisor stop")
    _q(sib.dsn, "SELECT voalack.record_containment(%s, %s, %s::jsonb)",
       (instance, owner.generation, json.dumps({"process_stopped": True, "no_requests_executing": True,
                                                 "basis": "lab: supervisor stopped the owner"})), fetch=False)
    if quiesce:
        evidence = _quiescence_evidence(fake, _sessions(sib, instance, owner))
        _q(sib.dsn, "SELECT voalack.record_quiescence(%s, %s, %s, %s::jsonb)",
           (instance, owner.generation, owner.incarnation, json.dumps(evidence)))


def _cleanup(sib, instance, fake):
    """[native] The supervisor's credential-wide cleanup at the provider in the closed phase (R1): every
    session of the credential revoked, registered or not, then no live or executing session observed."""
    credential = _q(sib.dsn, "SELECT credential_ref FROM voalack.instance_config WHERE instance_id = %s",
                    (instance,))[0][0]
    status, body = _lab(fake, "POST", f"/lab/credentials/{credential}/revoke")
    revoke = {"status": status, "credential": body["credential"], "revoked": body["revoked"], "observed_at": _now()}
    limit = time.monotonic() + 10
    while True:
        time.sleep(0.002)
        status, seen = _lab(fake, "GET", f"/lab/credentials/{credential}/executing")
        if seen["executing"] == 0 or time.monotonic() > limit:
            break
    executing = {"status": status, **seen, "observed_at": _now()}
    return _q(sib.dsn, "SELECT voalack.record_recovery_cleanup(%s, %s, %s::jsonb)",
              (instance, credential, json.dumps({"revoke": revoke, "executing": executing,
                                                  "basis": "lab: fake provider credential view"})))[0][0]


def _close_and_inventory(sib, instance, fake, owners, quiesce=True, cleanup=True):
    recovery.close(sib.anchor, sib.dsn)
    for owner in owners:
        _contain(sib, instance, owner, fake, quiesce=quiesce)
    if cleanup:
        _cleanup(sib, instance, fake)
    _contain_copied_rows(sib, instance)
    head = recovery.inventory(sib.anchor, sib.dsn)
    return head.line["inventory_sha256"]


def _contain_copied_rows(sib, instance):
    """Recovery is database-wide: the sibling also holds other instances' owner rows copied from the lab
    database; no process of theirs runs against the sibling, and the supervisor contains them too."""
    for inst, generation in _q(sib.dsn, "SELECT instance_id, owner_generation FROM voalack.session_owners "
                                        "WHERE state IN ('active', 'suspended') AND instance_id <> %s", (instance,)):
        _q(sib.dsn, "SELECT voalack.record_containment(%s, %s, %s::jsonb)",
           (inst, generation, json.dumps({"process_stopped": True, "no_requests_executing": True,
                                          "basis": "lab: row copied from the lab database; no process of it "
                                                   "runs against this sibling"})), fetch=False)


def _restore_and_recover(sib, inventory_sha, dump=None, backup_id="none"):
    """Restore (when a dump is given) only under the inventoried anchor; then review and recover."""
    backup_sha256 = None
    if dump is not None:
        recovery.restore_permitted(sib.anchor, inventory_sha)
        before = _files(sib.anchor)
        with open(dump, "rb") as handle:
            backup_sha256 = hashlib.sha256(handle.read()).hexdigest()           # the exact dump bytes (R6)
        sib.restore(dump)
        _q(sib.dsn, PRIVILEGES, fetch=False)
        assert _files(sib.anchor) == before                                   # [file] restore leaves the anchor
        backup_id = backup_id if backup_id != "none" else f"lab-dump:{os.path.basename(str(dump))}"
    review = recovery.write_review(sib.anchor, {"ref": "lab review", "backup_id": backup_id,
                                                "backup_sha256": backup_sha256, "inventory_sha256": inventory_sha,
                                                "decision": "adopt"})
    return recovery.recover(sib.anchor, sib.dsn, review, layout="voalack_only")   # T04 S4: declared layout


STAGED_SCHEMAS = ("voalack", "voalack_lifetime", "voalack_publication", "voalack_guard")
STAGED_CATALOG = (
    # every function in the project schemas: body, language, owner, security, configuration and raw ACL
    "SELECT 'function', p.oid::regprocedure::text, md5(p.prosrc) || '|' || p.provolatile::text || '|' || "
    "p.prokind::text || '|' || pg_get_function_result(p.oid), l.lanname, pg_get_userbyid(p.proowner), "
    "p.prosecdef::text, coalesce(p.proconfig::text, 'NULL'), coalesce(p.proacl::text, 'NULL') FROM pg_proc p "
    "JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang WHERE n.nspname = ANY(%(s)s)",
    # every relation in the project schemas plus public.alerts: kind, owner and raw ACL
    "SELECT 'relation', n.nspname || '.' || c.relname, c.relkind::text, pg_get_userbyid(c.relowner), "
    "coalesce(c.relacl::text, 'NULL'), '', '', '' FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = ANY(%(s)s) OR c.oid IN (to_regclass('public.alerts'), to_regclass('public.notes'))",
    # every column and every constraint of those relations
    "SELECT 'column', a.attrelid::regclass::text || '.' || a.attname, format_type(a.atttypid, a.atttypmod), "
    "a.attnotnull::text, coalesce(pg_get_expr(d.adbin, d.adrelid), ''), coalesce(a.attacl::text, 'NULL'), '', '' "
    "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
    "LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
    "WHERE a.attnum > 0 AND NOT a.attisdropped AND (n.nspname = ANY(%(s)s) OR c.oid IN (to_regclass('public.alerts'), to_regclass('public.notes')))",
    "SELECT 'constraint', k.conrelid::regclass::text || '.' || k.conname, pg_get_constraintdef(k.oid), '', '', '', "
    "'', '' FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace WHERE n.nspname = ANY(%(s)s) "
    "OR k.conrelid IN (to_regclass('public.alerts'), to_regclass('public.notes'))",
    # every non-internal trigger on those relations, with its definition and enabled state
    "SELECT 'trigger', t.tgrelid::regclass::text || '.' || t.tgname, pg_get_triggerdef(t.oid), t.tgenabled::text, "
    "'', '', '', '' FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE NOT t.tgisinternal AND (n.nspname = ANY(%(s)s) OR c.oid IN (to_regclass('public.alerts'), to_regclass('public.notes')))",
    # every event trigger, and the project schemas' owner and raw ACL
    "SELECT 'event_trigger', e.evtname, e.evtevent, e.evtenabled::text, pg_get_userbyid(e.evtowner), "
    "e.evtfoid::regprocedure::text, coalesce(e.evttags::text, 'NULL'), '' FROM pg_event_trigger e",
    "SELECT 'namespace', n.nspname, pg_get_userbyid(n.nspowner), coalesce(n.nspacl::text, 'NULL'), '', '', '', '' "
    "FROM pg_namespace n WHERE n.nspname = ANY(%(s)s)",
    # every index of those relations: definition, validity, primary/unique/immediate/replica-identity flags
    "SELECT 'index', i.indexrelid::regclass::text, pg_get_indexdef(i.indexrelid), i.indisvalid::text || '|' || "
    "i.indisready::text || '|' || i.indislive::text, i.indisprimary::text || '|' || i.indisunique::text || '|' || "
    "i.indimmediate::text || '|' || i.indisreplident::text, '', '', '' FROM pg_index i JOIN pg_class c "
    "ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ANY(%(s)s) "
    "OR c.oid IN (to_regclass('public.alerts'), to_regclass('public.notes'))",
    # every sequence's definition and owning column (its position is read separately, never through nextval)
    "SELECT 'sequence', sq.seqrelid::regclass::text, format_type(sq.seqtypid, NULL) || '|' || sq.seqstart::text "
    "|| '|' || sq.seqincrement::text || '|' || sq.seqmin::text || '|' || sq.seqmax::text || '|' || sq.seqcache::text "
    "|| '|' || sq.seqcycle::text, coalesce((SELECT string_agg(dp.deptype::text || ':' || dp.refobjid::regclass::text "
    "|| '.' || dp.refobjsubid::text, ',' ORDER BY dp.deptype, dp.refobjid, dp.refobjsubid) FROM pg_depend dp WHERE dp.classid = 'pg_class'::regclass "
    "AND dp.objid = sq.seqrelid AND dp.refclassid = 'pg_class'::regclass), 'none'), '', '', '', '' "
    "FROM pg_sequence sq JOIN pg_class c ON c.oid = sq.seqrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = ANY(%(s)s)")


def _staged_state(sib, fake=None):
    """[native raw state] What a staged refusal must leave unchanged (reviewer condition ce6816ae): the complete,
    deterministic row values of every table in the project schemas and of public.alerts when present (holds,
    effects, adoptions, settlements, recovery epoch, permits, journals, lifetime, publication and guard rows: md5 of
    the ordered row texts plus the count), the raw catalog facts above (functions, relations, columns, constraints, triggers, event
    triggers, indexes, namespaces, sequence definitions and owners, with raw ACLs), every sequence's last_value and
    is_called (read directly, never through nextval), public.notes when present, every anchor file's sha256 (head
    and chain included) and the provider's complete lab state (counters, live and issued sessions, alarm payloads,
    receipts, read targets, executing). Excluded: cluster-level roles, database ACLs and settings; the refused path
    only runs read-only queries (_layout_state, _publication_digest, _recognised_3a) before it raises."""
    tables = _q(sib.dsn, "SELECT format('%%I.%%I', n.nspname, c.relname) FROM pg_class c JOIN pg_namespace n "
                         "ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p') AND (n.nspname = ANY(%s) "
                         "OR c.oid IN (to_regclass('public.alerts'), to_regclass('public.notes'))) ORDER BY 1",
                (list(STAGED_SCHEMAS),))
    sequences = _q(sib.dsn, "SELECT format('%%I.%%I', n.nspname, c.relname) FROM pg_class c JOIN pg_namespace n "
                            "ON n.oid = c.relnamespace WHERE c.relkind = 'S' AND n.nspname = ANY(%s) ORDER BY 1",
                   (list(STAGED_SCHEMAS),))
    positions = {q: _q(sib.dsn, f"SELECT last_value, is_called FROM {q}")[0] for (q,) in sequences}
    rows = {t: _q(sib.dsn, f"SELECT count(*), md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) "
                           f"FROM {t} x")[0] for (t,) in tables}
    catalog = sorted(tuple(r) for query in STAGED_CATALOG for r in _q(sib.dsn, query, {"s": list(STAGED_SCHEMAS)}))
    provider = None if fake is None else (dict(fake.counts), sorted(fake.sessions.items()), sorted(fake.issued.items()),
                                          json.dumps(fake.alarms, sort_keys=True, default=str), list(fake.receipts),
                                          list(fake.read_targets), fake.executing)
    return {"rows": rows, "positions": positions, "catalog": catalog, "anchor": _files(sib.anchor),
            "provider": provider}


def _staged_restore_and_recover(sib, inventory_sha, dump, fake=None, backup_id="none"):
    """Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the same restore-permitted check, restore and
    review as _restore_and_recover, on a recognised non-empty Voalack-only installation; recover() with the review
    naming the backup is then refused as staged, before any anchor, adoption or open change: the anchor stays
    inventoried and the complete raw state (_staged_state) is unchanged. The original post-adoption oracles are an
    explicit S3c debt (re-proved with the admitted restore there)."""
    recovery.restore_permitted(sib.anchor, inventory_sha)
    before_files = _files(sib.anchor)
    with open(dump, "rb") as handle:
        backup_sha256 = hashlib.sha256(handle.read()).hexdigest()
    sib.restore(dump)
    _q(sib.dsn, PRIVILEGES, fetch=False)
    assert _files(sib.anchor) == before_files
    backup_id = backup_id if backup_id != "none" else f"lab-dump:{os.path.basename(str(dump))}"
    review = recovery.write_review(sib.anchor, {"ref": "lab review", "backup_id": backup_id,
                                                "backup_sha256": backup_sha256, "inventory_sha256": inventory_sha,
                                                "decision": "adopt"})
    assert _q(sib.dsn, "SELECT to_regprocedure('voalack.protections_intact()') IS NOT NULL")[0][0] is True
    assert _q(sib.dsn, "SELECT count(*) FROM voalack.effects")[0][0] > 0              # recognised and non-empty
    before = _staged_state(sib, fake)
    assert before["rows"] and before["catalog"]
    with pytest.raises(recovery.AnchorConflict, match="recovery from a restored backup is staged"):
        recovery.recover(sib.anchor, sib.dsn, review, layout="voalack_only")
    assert recovery.Anchor(sib.anchor).head().phase == "inventoried"
    assert _staged_state(sib, fake) == before


def _maintenance(sib, instance, fake, owner_id="lab-maintenance"):
    owner = OwnerSession(sib.sender, instance, owner_id, FakeOneTransport(fake.url), anchor=Anchor(sib.anchor),
                         mode="maintenance")
    owner.acquire()
    return owner


def _reopen(sib, instance, fake, maintenance=()):
    for owner in maintenance:
        _contain(sib, instance, owner, fake, quiesce=False)
    return recovery.reopen(sib.anchor, sib.dsn, layout="voalack_only")


def _holds(sib, instance):
    return _q(sib.dsn, "SELECT hold_id, status, members, holders FROM voalack.recovered_holds WHERE instance_id = %s "
                       "ORDER BY hold_id", (instance,))


def _effect_holds(sib, effect_key):
    return _q(sib.dsn, "SELECT effect_key FROM voalack.recovered_effects WHERE effect_key = %s", (effect_key,))


def _key(sib, effect_id):
    return _q(sib.dsn, "SELECT effect_key FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0][0]


def _recur(fake, target_id="4711"):
    """[fake] The alarm recurred and is not acknowledged at the provider: a resend would now be
    accepted and applied (the hazard C1 describes), so nothing but the holds can stop it."""
    with fake.lock:
        fake.alarms.pop(target_id, None)


def _capture(client, instance, occurrence_ref=None):
    """A captured, signed human ACK that has not been verified or promoted yet."""
    alert_id = new_alert(client, instance_id=instance, occurrence_ref=occurrence_ref)
    assert ack(client, alert_id).status_code == 200
    return sql("SELECT action_id::text FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))[0][0]


def _promote(app, sib, action_id):
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(sib.dsn.replace("lab_admin:lab-only-admin", "lab_verifier:lab-only-verifier")) as conn:
        result = verifier.run_once(conn, "lab-verifier-s3c", signing.ctx, signing.keys, action_id=action_id)
    assert result["outcome"] == "verified", result
    return result["effect_id"]


# --- C1: completed work is never resurrected -------------------------------------------------------

@pytest.mark.parametrize("snapshot", ["queued", "before_promotion"])
def test_s3a_staged_completed_work_is_not_resurrected(client, app, instance, fake, sibling, tmp_path, snapshot):
    """Snapshot with the effect QUEUED (or its capture not yet promoted); the ACK is sent and
    confirmed; the supervised procedure restores the snapshot. The restored QUEUED effect, or the
    same capture promoted again to the same key, never sends: the complete inventory shows the key's
    progress, so adoption holds it."""
    dump = tmp_path / "snapshot.dump"
    if snapshot == "queued":
        effect_id = _effect(client, app, instance)
        sib = sibling()
        sib.dump(dump)
    else:
        action_id = _capture(client, instance)
        sib = sibling()
        sib.dump(dump)
        effect_id = _promote(app, sib, action_id)
    key = _key(sib, effect_id)
    owner = _owner(sib, instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed" and fake.counts["receipts"] == 1
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, inventory_sha, dump, fake=fake)


# --- lost unresolved work: held, read in maintenance, settled -----------------------------------------

@pytest.mark.parametrize("variant", ["attributed", "retired"])
def test_s3a_staged_lost_unresolved_work_is_held_read_and_settled(client, app, instance, fake, sibling, tmp_path, variant):
    first = _effect(client, app, instance, occurrence_ref="lab-occ-lost-a")
    second = _effect(client, app, instance, occurrence_ref="lab-occ-lost-b")      # same physical key
    sib = sibling()
    dump = tmp_path / "before-dispatch.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_after_body" if variant == "attributed" else "close_before_body"
    sent = owner.apply_once(first)
    assert sent["outcome"] == "uncertain", sent
    fake.script["ack"] = "success"
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, inventory_sha, dump, fake=fake)


def test_s3a_staged_hold_release_needs_known_quiescent_holders(client, app, instance, fake, sibling, tmp_path):
    """A holder contained without quiescence (or with no known sessions) keeps the hold for ever, and
    the hold alone (no guard row exists after the restore) keeps the key from new work."""
    first = _effect(client, app, instance, occurrence_ref="lab-occ-unknown-a")
    second = _effect(client, app, instance, occurrence_ref="lab-occ-unknown-b")
    sib = sibling()
    dump = tmp_path / "before.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    assert owner.apply_once(first)["outcome"] == "uncertain"
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner], quiesce=False)
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, inventory_sha, dump, fake=fake)


# --- restored older progress, in-flight work at the close ---------------------------------------------

def test_s3a_staged_restored_older_progress_is_fenced_and_held(client, app, instance, fake, sibling, tmp_path):
    """Snapshot while the attempt is started (permit unconsumed, guard in flight); the ACK is then
    confirmed; the supervised restore brings the older attempt back. It is fenced, its effect held and
    its key held (restored guard), so neither it nor another action on the key sends."""
    first = _effect(client, app, instance, occurrence_ref="lab-occ-old-a")
    second = _effect(client, app, instance, occurrence_ref="lab-occ-old-b")
    sib = sibling()
    dump = tmp_path / "started.dump"
    owner = _owner(sib, instance, fake, hooks={"after_start": lambda _: sib.dump(dump)})
    sent = owner.apply_once(first)
    assert sent["outcome"] == "confirmed"
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, inventory_sha, dump, fake=fake)


def test_ack_in_flight_at_the_close_is_held_by_the_inventory(client, app, instance, fake, sibling):
    """An ACK past its final check when the close happens completes at the provider; the owner can no
    longer record it; quiescence waits for it; the inventory shows it dispatched and adoption holds
    its key (no restore: an unchanged database is adopted)."""
    first = _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    fake.script["delay"] = 1.5
    outcome = {}
    worker = threading.Thread(target=lambda: outcome.update(owner.apply_once(first)))
    worker.start()
    limit = time.monotonic() + 10
    while fake.executing == 0 and time.monotonic() < limit:
        time.sleep(0.01)
    assert fake.executing == 1
    recovery.close(sib.anchor, sib.dsn)
    worker.join(15)
    assert outcome["reason"] == "owner_fenced_after_send" and fake.counts["receipts"] == 1
    fake.script["delay"] = 0.0
    inventory_sha = _close_and_inventory(sib, instance, fake, [owner])
    _restore_and_recover(sib, inventory_sha)                                  # backup "none"
    [(_, status, members, _)] = _holds(sib, instance)
    assert status == "active" and members[0]["state"] == "dispatched" and members[0]["source"] == "inventory"


# --- stale epochs, crash points, refusals -----------------------------------------------------------

def test_stale_epoch_rows_are_refused_after_recovery(client, app, instance, fake, sibling, tmp_path):
    _effect(client, app, instance)
    sib = sibling()
    old = _owner(sib, instance, fake)
    epoch1 = tmp_path / "epoch1.dump"
    sib.dump(epoch1)
    inventory_sha = _close_and_inventory(sib, instance, fake, [old])
    _restore_and_recover(sib, inventory_sha)
    recovering = tmp_path / "recovering.dump"
    sib.dump(recovering)
    _reopen(sib, instance, fake)
    assert _owner(sib, instance, fake, owner_id="lab-epoch2").head[0] == 5      # positive control
    for dump, row in ((epoch1, (1, "open")), (recovering, (2, "recovering"))):
        sib.restore(dump)                                                     # unannounced: anchor at open(2)
        _q(sib.dsn, PRIVILEGES, fetch=False)
        assert sib.phase()[0][:2] == row
        with pytest.raises(psycopg2.errors.RaiseException, match="anchor head does not match"):
            _owner(sib, instance, fake, owner_id="lab-stale")
    assert _sql_as_sender(sib, "SELECT voalack.check_owner(%s, %s, %s) AS s",
                          (instance, old.generation, old.incarnation))["s"] in ("contained", "epoch_changed")


def test_every_recovery_step_reruns_after_a_crash(client, app, instance, fake, sibling):
    _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    recovery.close(sib.anchor, sib.dsn)
    _contain(sib, instance, owner, fake)
    _cleanup(sib, instance, fake)
    _contain_copied_rows(sib, instance)

    def crash(at):
        if at == "rename:anchor.log":
            raise OSError("lab: crash before the inventoried line")
    with pytest.raises(OSError, match="lab: crash"):
        recovery.inventory(sib.anchor, sib.dsn, supervisor=Supervisor(sib.anchor, fault=crash))
    head = Anchor(sib.anchor).head()
    assert head.phase == "closed"                                             # the document alone is not a step
    with pytest.raises(AnchorConflict):
        recovery.restore_permitted(sib.anchor, "0" * 64)
    inventoried = recovery.inventory(sib.anchor, sib.dsn)
    sha = inventoried.line["inventory_sha256"]
    review = recovery.write_review(sib.anchor, {"ref": "lab review", "backup_id": "none", "backup_sha256": None,
                                                "inventory_sha256": sha, "decision": "adopt"})
    line = Supervisor(sib.anchor).append((inventoried.seq, inventoried.sha256), "recovering", inventory_sha256=sha,
                                         backup_id="none", backup_sha256=None, review_sha256=review,
                                         review_ref="lab review")
    with pytest.raises(psycopg2.errors.RaiseException, match="anchor head does not match"):
        _maintenance(sib, instance, fake)                                      # crash before adoption
    assert recovery.recover(sib.anchor, sib.dsn, review, layout="voalack_only") == line               # re-run: same line, adopted now
    assert sib.phase()[0][:3] == (2, "recovering", line.seq)
    other = recovery.write_review(sib.anchor, {"ref": "other review", "backup_id": "none", "backup_sha256": None,
                                               "inventory_sha256": sha, "decision": "adopt"})
    with pytest.raises(AnchorConflict):
        recovery.recover(sib.anchor, sib.dsn, other, layout="voalack_only")                           # conflicting replay
    text = Anchor(sib.anchor).document(f"inventory-{sha}.json", sha).decode()
    args = (2, line.seq, line.sha256, text, sha, "none", None, review, "lab review")
    adopt = "SELECT outcome FROM voalack.adopt_recovery(%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)"
    assert _q(sib.dsn, adopt, args)[0][0] == "already_adopted"
    with pytest.raises(psycopg2.errors.RaiseException, match="other input"):
        _q(sib.dsn, adopt, args[:5] + ("other", "e" * 64, review, "lab review"))
    adoption = _q(sib.dsn, "SELECT input_sha256 FROM voalack.recovery_adoptions WHERE epoch = 2")[0][0]
    manifest = Supervisor(sib.anchor).write_document("adoption", recovery.canonical(
        {"v": 1, "epoch": 2, "recovering_seq": line.seq, "recovering_sha256": line.sha256, "inventory_sha256": sha,
         "review_sha256": review, "backup_id": "none", "backup_sha256": None, "adoption_input_sha256": adoption}))
    opened = Supervisor(sib.anchor).append((line.seq, line.sha256), "open", adoption_sha256=manifest)
    with pytest.raises(psycopg2.errors.RaiseException, match="anchor head does not match"):
        _owner(sib, instance, fake, owner_id="lab-before-db-open")             # crash before the database opens
    assert recovery.reopen(sib.anchor, sib.dsn, layout="voalack_only") == opened
    assert _q(sib.dsn, "SELECT voalack.open_recovery(2, %s, %s)", (opened.seq, opened.sha256))[0][0] == "already_open"
    assert _owner(sib, instance, fake, owner_id="lab-open").head == (opened.seq, opened.sha256)


@pytest.mark.parametrize("defect", ["tampered", "other_epoch", "not_newer"])
def test_adoption_refuses_a_bad_inventory_or_epoch(client, app, instance, fake, sibling, defect):
    _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    sha = _close_and_inventory(sib, instance, fake, [owner])
    text = Anchor(sib.anchor).document(f"inventory-{sha}.json", sha).decode()
    epoch = 2
    if defect == "tampered":
        assert '"format": "voalack-inventory/2"' in text
        text = text.replace('"format": "voalack-inventory/2"', '"format": "voalack-inventory/3"')
        match = "digest mismatch"
    elif defect == "other_epoch":
        document = json.loads(text)
        document["epoch"] = 7
        text = _q(sib.dsn, "SELECT %s::jsonb::text", (json.dumps(document),))[0][0]
        sha = hashlib.sha256(text.encode()).hexdigest()
        match = "previous epoch"
    else:
        epoch = 1
        document = json.loads(text)
        document["epoch"] = 0
        text = _q(sib.dsn, "SELECT %s::jsonb::text", (json.dumps(document),))[0][0]
        sha = hashlib.sha256(text.encode()).hexdigest()
        match = "newer than the database"
    with pytest.raises(psycopg2.errors.RaiseException, match=match):
        _q(sib.dsn, "SELECT outcome FROM voalack.adopt_recovery(%s, 9, %s, %s::jsonb, %s, 'none', NULL, %s, 'lab')",
           (epoch, "a" * 64, text, sha, "b" * 64))
    assert sib.phase()[0][1] == "closed" and _q(sib.dsn, "SELECT count(*) FROM voalack.recovered_holds")[0][0] == 0


def test_missing_inventory_document_closes_the_anchor(client, app, instance, fake, sibling):
    _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    sha = _close_and_inventory(sib, instance, fake, [owner])
    os.remove(os.path.join(sib.anchor, f"inventory-{sha}.json"))
    with pytest.raises(AnchorInvalid):
        Anchor(sib.anchor).head()
    with pytest.raises(AnchorInvalid):
        recovery.restore_permitted(sib.anchor, sha)


def test_s3a_staged_maintenance_capability_and_waits_keep_the_hold(client, app, instance, fake, sibling, tmp_path):
    """The maintenance owner cannot start, consume or reconcile; a configuration change while its
    recovery read is outstanding is refused at record time and stops it; the hold stays."""
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "before.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    sent = owner.apply_once(first)
    fake.script["ack"] = "success"
    sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, sha, dump, fake=fake)


def test_s3a_staged_unknown_commit_of_a_hold_settlement_is_resolved_by_the_same_decision(client, app, instance, fake,
                                                                              sibling, tmp_path):
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "before.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    owner.apply_once(first)
    fake.script["ack"] = "success"
    sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, sha, dump, fake=fake)


def test_s3a_staged_configuration_change_during_a_settlement_wait_keeps_the_hold(client, app, instance, fake, sibling, tmp_path):
    """[native] An administrator transaction holds the instance configuration row while the settler
    waits for it, then commits a change: the settlement re-checks after the wait and refuses."""
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "before.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    owner.apply_once(first)
    fake.script["ack"] = "success"
    sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, sha, dump, fake=fake)


