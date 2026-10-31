"""T04 S4 (D9): the supervised Voalack-only restore in a database shared with Alerta.

The bare restore command fails in the shared layout (the capture trigger on public.alerts depends on
voalack.capture_ack()); recovery.restore_shared detaches exactly that trigger after validating it, runs
the unchanged restore, recreates the trigger from the installed schema source and validates before
recovery continues. Shared-database witnesses run on full sibling copies; the actual Alerta route
witnesses (an ACK while the trigger is absent, and requests in flight at detach and at recreation) run
on the lab database, because the test application is bound to it (step-level witnesses).
"""
import hashlib
import json
import os
import subprocess
import threading
import time
from contextlib import contextmanager

import psycopg2
import pytest

from conftest import DSN, GUARD_EVENT_TRIGGERS, OPERATOR, ack, guard_bypassed, basic, captures, intents, new_alert, sql, status
from test_c3_transaction import _Hook
from test_t04_s2_sender import _effect, fake, instance  # noqa: F401
from test_t04_s3c_recovery import _owner, _q, sibling  # noqa: F401
from test_t04_s3c_restore import _close_and_inventory, _files
from test_t04_s4_recovery import all_publications, drain, full_sibling, publication_catalog  # noqa: F401
from voalack import recovery, verifier
from voalack.recovery import RestoreFailed, RestoreRefused


def _evidence(name, data):
    if os.path.isdir("/out"):
        with open(f"/out/{name}", "w") as handle:
            json.dump(data, handle, default=str, indent=2)


def _contract(dsn):
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        return recovery.capture_contract(cur)


def _review(sib, inventory_sha, dump):
    with open(dump, "rb") as handle:
        backup_sha = hashlib.sha256(handle.read()).hexdigest()
    return recovery.write_review(sib.anchor, {"ref": "lab review", "backup_id": f"lab-dump:{os.path.basename(str(dump))}",
                                              "backup_sha256": backup_sha, "inventory_sha256": inventory_sha,
                                              "decision": "adopt"})


def _inventoried(client, app, instance, fake, full_sibling, tmp_path):
    """A shared full sibling with a dump of its voalack schema, an ACK sent and confirmed after the dump,
    projected notes, and the anchor inventoried (owners contained and quiescent)."""
    effect_id = _effect(client, app, instance)
    sib = full_sibling()
    dump = tmp_path / "shared.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    drain(sib)
    return sib, dump, _close_and_inventory(sib, instance, fake, [owner])


# --- Coexistence 3a S3a staging (design review) ---------------------------------------------------------------------
# Real restore is refused in S3a and S3b and is re-proved only in S3c. A converted test keeps its name, states its S2
# oracle and now witnesses the staged refusal: after every earlier validation, before any database change, the journal
# holding only its 'begin' record. The original S2 records stay in the S2 packet; these are not proof of the restore.
STAGED = "restore is staged"


def _state(sib):
    return (_q(sib.dsn, "SELECT md5(string_agg(a::text, '|' ORDER BY a.id)) FROM public.alerts a")[0][0],
            _q(sib.dsn, "SELECT md5(string_agg(n::text, '|' ORDER BY n.id)) FROM public.notes n")[0][0],
            _q(sib.dsn, "SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger "
                        "WHERE tgrelid = 'public.alerts'::regclass AND NOT tgisinternal ORDER BY 1"),
            _q(sib.dsn, "SELECT p.oid::regprocedure::text, md5(p.prosrc) FROM pg_proc p JOIN pg_namespace n "
                        "ON n.oid = p.pronamespace WHERE n.nspname = 'voalack' ORDER BY 1"),
            all_publications(sib), publication_catalog(sib), _files(sib.anchor))


def _staged_refused(sib, dump, inventory_sha, journal, fault=None):
    """restore_shared refuses as staged; no step point is reached and nothing in the sibling changes."""
    before, reached = _state(sib), []

    def hook(at):
        reached.append(at)
        if fault:
            fault(at)
    with pytest.raises(RestoreRefused, match=STAGED):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), fault=hook,
                                layout="shared")
    assert reached == []
    assert recovery.RestoreJournal(str(journal), inventory_sha).steps() == ["begin"]
    assert _contract(sib.dsn) == [] and list(_q(sib.dsn, "SELECT voalack_guard.inventory_problems()")[0][0]) == []
    assert _state(sib) == before


@contextmanager
def _sibling_guard_disabled(sib, why):
    """[lab, disposable sibling, DISCLOSED BYPASS] The trusted-superuser bypass on a throwaway sibling copy, only to
    create a drifted state whose refusal is the witness. The drift is deliberately left in place (the sibling is
    discarded); the event triggers are re-enabled if they still exist. Never a permit or a recovery operation."""
    assert why
    for name in GUARD_EVENT_TRIGGERS:
        _q(sib.dsn, f"ALTER EVENT TRIGGER {name} DISABLE", fetch=False)
    try:
        yield
    finally:
        for name in GUARD_EVENT_TRIGGERS:
            if _q(sib.dsn, "SELECT 1 FROM pg_event_trigger WHERE evtname = %s", (name,)):
                _q(sib.dsn, f"ALTER EVENT TRIGGER {name} ENABLE", fetch=False)


def test_lab_capture_trigger_matches_the_approved_contract(app):
    """The constants of the contract against the freshly applied lab schema (PostgreSQL major bound)."""
    actual = sql("SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t WHERE t.tgrelid = 'public.alerts'::regclass "
                 "AND t.tgname = 'voalack_capture_ack'")[0][0]
    _evidence("capture-triggerdef.json", {"actual": actual, "approved": recovery.CAPTURE_TRIGGERDEF,
                                          "version": sql("SELECT version()")[0][0]})
    assert actual == recovery.CAPTURE_TRIGGERDEF
    assert _contract(DSN) == []
    version = sql("SELECT current_setting('server_version_num')::int / 10000")[0][0]
    assert version == 18
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        assert recovery.cross_schema_dependencies(cur) == recovery.ALLOWED_DEPENDENCIES   # 3a: four approved


def test_bare_restore_fails_in_the_shared_layout(client, app, instance, fake, full_sibling, tmp_path):
    """Baseline regression (why the procedure changed): the unchanged command, exit status and SQL error."""
    _effect(client, app, instance)
    sib = full_sibling()
    dump = tmp_path / "bare.dump"
    sib.dump(dump)
    done = subprocess.run(["pg_restore", "--clean", "--if-exists", "-d", sib.dsn, str(dump)],
                          capture_output=True, text=True)
    with open(dump, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    _evidence("shared-bare-restore.json", {"command": "pg_restore --clean --if-exists -d <sibling> <dump>",
                                           "dump_sha256": digest, "returncode": done.returncode,
                                           "stderr_tail": done.stderr[-3000:],
                                           "version": sql("SELECT version()")[0][0]})
    assert done.returncode != 0
    assert "depends on function voalack.capture_ack()" in done.stderr


def test_the_procedure_restores_validates_and_recovers(client, app, instance, fake, full_sibling, tmp_path):
    """S2 oracle: begin, detached, restored, recreated, validated; contract, publications, alerts and notes unchanged;
    replay 'already_complete'; recover and reopen. Re-proved in S3c. S3a: staged refusal, twice (a replay is refused
    the same way), and recovery stays closed on the unvalidated journal."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    _staged_refused(sib, dump, inventory_sha, journal)
    _staged_refused(sib, dump, inventory_sha, journal)
    _recover_refused(sib, _review(sib, inventory_sha, dump), str(journal), r"not validated \(last step begin\)",
                     fake, instance)
    _evidence("shared-restore-staged-journal.json", recovery.RestoreJournal(str(journal), inventory_sha).entries())


@pytest.mark.parametrize("point", ["after_detach", "after_restore", "before_recreate"])
def test_a_crash_leaves_recovery_closed_and_a_rerun_completes(client, app, instance, fake, full_sibling, tmp_path,
                                                             point):
    """S2 oracle: a crash at the step point leaves the trigger detached and recovery closed; a rerun completes.
    Re-proved in S3c. S3a: the refusal precedes every step point, so the crash is never reached and nothing is
    detached; recovery stays closed."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()

    def crash(at):
        if at == point:
            raise SystemExit(f"lab: supervisor killed at {at}")
    _staged_refused(sib, dump, inventory_sha, journal, fault=crash)
    _recover_refused(sib, _review(sib, inventory_sha, dump), str(journal), "not validated", fake, instance)


def test_a_failed_restore_is_never_success_and_a_retry_completes(client, app, instance, fake, full_sibling, tmp_path):
    """S2 oracle: an extra object makes pg_restore fail (journaled restore_failed, trigger detached, recovery refused);
    once fixed, a retry completes. Re-proved in S3c. S3a: with the same extra object, the staged refusal comes first;
    nothing is detached or restored, and the retry is refused the same way."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    _q(sib.dsn, "CREATE TABLE voalack.lab_extra (x int)", fetch=False)
    _staged_refused(sib, dump, inventory_sha, journal)
    with pytest.raises(recovery.AnchorConflict, match="not validated"):
        recovery.recover(sib.anchor, sib.dsn, _review(sib, inventory_sha, dump), layout="shared", journal_dir=str(journal))
    _q(sib.dsn, "DROP TABLE voalack.lab_extra", fetch=False)
    _staged_refused(sib, dump, inventory_sha, journal)


def test_the_backup_is_bound_to_the_inventory(client, app, instance, fake, full_sibling, tmp_path):
    """S2 oracle kept: once a restore began for this inventory, another backup is refused ('bound to another backup').
    S3a: the first run is the staged refusal (its 'begin' binds the backup); the binding refusal precedes staging."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    _staged_refused(sib, dump, inventory_sha, journal)
    other = tmp_path / "other.dump"
    sib.dump(other)
    with pytest.raises(RestoreRefused, match="bound to another backup"):
        recovery.restore_shared(sib.anchor, sib.dsn, str(other), inventory_sha, str(journal), layout="shared")


@pytest.mark.parametrize("drift", ["extra_dependency", "altered_trigger", "disabled_trigger", "absent_unjournaled",
                                   "second_trigger"])
def test_unexpected_state_is_refused_before_any_change(client, app, instance, fake, full_sibling, tmp_path, drift):
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    statement = {
        "extra_dependency": "CREATE VIEW public.lab_effects AS SELECT effect_id FROM voalack.effects",
        "altered_trigger": "DROP TRIGGER voalack_capture_ack ON public.alerts; CREATE TRIGGER voalack_capture_ack "
                           "AFTER UPDATE ON public.alerts FOR EACH ROW EXECUTE FUNCTION voalack.capture_ack()",
        "disabled_trigger": "ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack",
        "absent_unjournaled": "DROP TRIGGER voalack_capture_ack ON public.alerts",
        "second_trigger": "CREATE TRIGGER lab_second AFTER INSERT ON public.alerts FOR EACH ROW "
                          "EXECUTE FUNCTION voalack.capture_ack()",
    }[drift]
    if drift == "extra_dependency":
        _q(sib.dsn, statement, fetch=False)
    else:
        # Coexistence 3a S3a (amended openly): the enabled guard refuses creating this drift; the precheck oracle is
        # then witnessed on a drift made under the disclosed sibling bypass.
        with pytest.raises(psycopg2.Error, match="protected inventory"):
            _q(sib.dsn, statement, fetch=False)
        with _sibling_guard_disabled(sib, f"create {drift} drift to witness the precheck"):
            _q(sib.dsn, statement, fetch=False)
    triggers = _q(sib.dsn, "SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger "
                           "WHERE tgrelid = 'public.alerts'::regclass AND NOT tgisinternal ORDER BY 1")
    with pytest.raises(RestoreRefused) as refused:
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
    assert STAGED not in str(refused.value)                       # 3a: the precheck refusal precedes the staging
    assert "detached" not in recovery.RestoreJournal(str(journal), inventory_sha).steps()
    assert _q(sib.dsn, "SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger "
                       "WHERE tgrelid = 'public.alerts'::regclass AND NOT tgisinternal ORDER BY 1") == triggers


# --- the actual Alerta route while the trigger is absent (lab database, step-level) ----------------------

def test_an_eligible_ack_without_the_capture_trigger_fails_honestly_and_rolls_back(client, app):
    alert_id = new_alert(client)
    before = (status(alert_id), sql("SELECT history FROM alerts WHERE id = %s", (alert_id,))[0][0])
    counts = (intents(alert_id), captures(alert_id), sql("SELECT count(*) FROM voalack.effects")[0][0])
    # Coexistence 3a S3a (amended openly): the detach/recreate steps run under the disclosed lab bypass (predicate
    # evidence, not normal recovery); the enabled guard refuses them otherwise.
    with guard_bypassed("step-level witness: an ACK while the capture trigger is absent"):
        _absent_ack(client, alert_id, before, counts)
    assert _contract(DSN) == []
    r = ack(client, alert_id)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert status(alert_id)[0] == "ack" and intents(alert_id) == 1 and captures(alert_id) == 1


def _absent_ack(client, alert_id, before, counts):
    recovery.detach_capture_trigger(DSN)
    try:
        assert _contract(DSN) == ["capture trigger absent"]
        r = ack(client, alert_id)
        # Coexistence 3a S2 (amended openly): refused at the gate, before staging ('protections not intact'); before
        # 3a the ACK failed later at capture ('capture could not be recorded'). Either way nothing is kept.
        assert r.status_code == 503 and "protections not intact" in r.get_data(as_text=True), r.status_code
        assert (status(alert_id), sql("SELECT history FROM alerts WHERE id = %s", (alert_id,))[0][0]) == before
        assert (intents(alert_id), captures(alert_id), sql("SELECT count(*) FROM voalack.effects")[0][0]) == counts
    finally:
        recovery.recreate_capture_trigger(DSN)


def _slow_ack(app, faults, alert_id, out, seconds=1.5):
    """An eligible ACK whose transaction stays open after its alert update (post_action sleeps)."""
    faults("slow", _Hook("slow", post_action=lambda a, act, t: time.sleep(seconds)))

    def run():
        out["response"] = app.test_client().put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"},
                                                headers=basic(OPERATOR))
    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _ddl_waiting():
    return sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
               "WHERE NOT l.granted AND l.relation = 'public.alerts'::regclass AND a.usename = 'lab_admin'")[0][0]


@pytest.mark.parametrize("step", ["detach", "recreate"])
def test_an_ack_in_flight_at_a_trigger_step_commits_or_rolls_back_consistently(client, app, faults, step):
    """[native] At detach, the DDL waits for the in-flight ACK transaction (observed on pg_locks) and the ACK
    commits with its capture. At recreation (triggers absent), the ACK is refused at the gate before it updates
    the alert (coexistence 3a S2), so nothing waits and nothing is kept. Each actual outcome is recorded."""
    # Coexistence 3a S3a (amended openly): each step runs under a labelled lab permit row (test_coexist_s3_guard.
    # lab_permit: predicate evidence, never a production permit; open_permit refuses in S3a). The guard stays enabled,
    # so the ACK passes the gate and the detach really waits for it. (Under the guard bypass the gate refuses every ACK
    # up front; without a permit the detach waits and is then refused.)
    from conftest import inventory_problems
    from test_coexist_s3_guard import lab_permit
    step_permit = {"detach": ("detach",), "recreate": ("recreate", '{"drop": []}')}[step]
    assert inventory_problems() == []                                       # the guard is intact and enabled
    assert sql("SELECT count(*) FROM pg_event_trigger WHERE evtname = ANY(%s) AND evtenabled = 'O'",
               (list(GUARD_EVENT_TRIGGERS),))[0][0] == 2
    alert_id = new_alert(client)
    # Coexistence 3a S3b (amended openly): a permit admits DDL only from its window's registered coordinator backend,
    # so each step runs recovery.detach/recreate_capture_trigger's exact statements on the lab permit's own planted
    # connection (_lab_step); the in-flight race and its observation are unchanged.
    if step == "recreate":
        with lab_permit("detach") as lab:
            _lab_step(lab, "detach")
    out = {}
    try:
        with lab_permit(*step_permit) as lab:
            _inflight(app, faults, step, alert_id, out, lab)
    finally:
        if _contract(DSN) == ["capture trigger absent"]:
            with lab_permit("recreate", '{"drop": []}') as lab:
                _lab_step(lab, "recreate")
    # every lab permit is closed and the inventory is exactly restored
    assert sql("SELECT count(*) FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL")[0][0] == 0
    assert inventory_problems() == []
    _inflight_outcome(step, alert_id, out)


def _lab_step(lab, step, lock_timeout_ms=5000):
    """[lab] recovery.detach_capture_trigger / recreate_capture_trigger's exact statements, committed, on the lab
    permit's planted coordinator connection (S3b: only the registered backend acts under a permit)."""
    with lab.conn.cursor() as cur:
        cur.execute(f"SET lock_timeout = {int(lock_timeout_ms)}")
        if step == "detach":
            cur.execute(f"DROP TRIGGER {recovery.CAPTURE_TRIGGER} ON public.alerts RESTRICT")
            for name in recovery.PROTECTION_TRIGGERS:
                cur.execute(f"DROP TRIGGER IF EXISTS {name} ON public.alerts RESTRICT")
        else:
            cur.execute(recovery.approved_trigger_ddl())
            for ddl in recovery.approved_protection_ddl():
                cur.execute(ddl)
    lab.conn.commit()


def _inflight(app, faults, step, alert_id, out, lab):
    thread = _slow_ack(app, faults, alert_id, out)
    time.sleep(0.5)                                                     # inside post_action
    worker = threading.Thread(target=_lab_step, args=(lab, step, 10000))
    worker.start()
    waited = False
    for _ in range(40):
        if _ddl_waiting():
            waited = True
            break
        time.sleep(0.025)
    thread.join(10)
    worker.join(10)
    out["waited"] = waited
    out["after_step"] = _contract(DSN)                                    # the step's exact outcome


def _inflight_outcome(step, alert_id, out):
    waited = out["waited"]
    response = out["response"]
    outcome = {"step": step, "ddl_waited": waited, "status_code": response.status_code,
               "alert_status": status(alert_id)[0], "intents": intents(alert_id), "captures": captures(alert_id)}
    _evidence(f"shared-inflight-{step}.json", outcome)
    if step == "detach":
        # the ACK was admitted by the enabled gate and in flight; the detach waited for it, then dropped the four
        assert waited, outcome
        assert (response.status_code, outcome["alert_status"], outcome["captures"]) == (200, "ack", 1), outcome
        assert out["after_step"] == ["capture trigger absent"], out
    else:
        # Coexistence 3a S2 (amended openly): with the triggers detached and committed, the gate refuses up front
        # ('protections not intact') before the ACK updates the alert, so there is no in-flight ACK transaction for
        # the recreation to wait on. The outcome stays consistent: refused, alert open, nothing captured.
        assert response.status_code == 503 and outcome["alert_status"] != "ack", outcome
        assert "protections not intact" in response.get_data(as_text=True), outcome
        assert (outcome["intents"], outcome["captures"]) == (0, 0), outcome
        assert out["after_step"] == [], out                               # the recreate created all four
    assert _contract(DSN) == []


# --- the restore journal as a recovery gate (D10) -------------------------------------------------------

def _recover_refused(sib, review, journal, match, fake, instance):
    """recover and reopen refuse; no owner can acquire, the projector stays paused."""
    with pytest.raises(recovery.AnchorConflict, match=match):
        recovery.recover(sib.anchor, sib.dsn, review, layout="shared", journal_dir=journal)
    assert recovery.Anchor(sib.anchor).head().phase == "inventoried"
    with pytest.raises(recovery.AnchorInvalid):
        _owner(sib, instance, fake, owner_id="lab-not-yet")
    try:                                                                   # nothing is projected:
        assert drain(sib)[-1]["outcome"] == "paused"                       # the gate pauses, or
    except verifier.NotReady as exc:                                       # readiness refuses first
        assert "relation_owner_drift" in str(exc)                          # (the failed restore's leftover)
    assert fake.counts["receipts"] == 1                                    # only the ACK sent before the close


@pytest.mark.parametrize("state", ["incomplete", "failed", "mismatched_backup", "missing", "torn"])
def test_a_valid_trigger_does_not_authorize_an_unvalidated_restore(client, app, instance, fake, full_sibling,
                                                                   tmp_path, state):
    """S2 oracle: with the trigger valid, recovery still refuses an incomplete, failed, other-backup, missing or torn
    journal. Re-proved in S3c. S3a: every restore is staged-refused, so the journal holds only 'begin'; recovery
    refuses 'not validated' (the other-backup check follows validation and is re-proved in S3c), a missing journal and
    a torn tail as before."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    review_dump = dump
    if state == "failed":
        _q(sib.dsn, "CREATE TABLE voalack.lab_extra (x int)", fetch=False)
    _staged_refused(sib, dump, inventory_sha, journal)
    if state == "torn":
        with open(recovery.RestoreJournal(str(journal), inventory_sha).path, "ab") as handle:
            handle.write(b'{"step":"validated"')
    if state == "mismatched_backup":
        review_dump = tmp_path / "other.dump"
        sib.dump(review_dump)
    assert _contract(sib.dsn) == []                                       # the trigger itself is as approved
    match = {"incomplete": "not validated", "failed": "not validated", "mismatched_backup": "not validated",
             "missing": "needs its validated restore journal", "torn": "torn tail"}[state]
    _recover_refused(sib, _review(sib, inventory_sha, review_dump),
                     None if state == "missing" else str(journal), match, fake, instance)
    if state == "torn":
        with pytest.raises(recovery.JournalCorrupt, match="torn tail"):
            recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")


def test_an_out_of_order_journal_is_refused(client, app, instance, fake, full_sibling, tmp_path):
    """S2 oracle kept (journal after a detach, then 'validated' appended). S3a: the journal after the staged refusal
    holds 'begin' only; 'validated' appended directly after it is out of order the same way."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    _staged_refused(sib, dump, inventory_sha, journal)
    with open(recovery.RestoreJournal(str(journal), inventory_sha).path, "ab") as handle:
        handle.write(recovery.canonical({"step": "validated", "at": "2026-10-08T00:00:00.000000+00:00"}) + b"\n")
    with pytest.raises(recovery.JournalCorrupt, match="out of order"):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
    _recover_refused(sib, _review(sib, inventory_sha, dump), str(journal), "out of order", fake, instance)


def test_a_concurrent_run_is_refused(client, app, instance, fake, full_sibling, tmp_path):
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    with recovery.RestoreJournal(str(journal), inventory_sha).exclusive():
        with pytest.raises(RestoreRefused, match="another restore"):
            recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
    assert _contract(sib.dsn) == [] and not recovery.RestoreJournal(str(journal), inventory_sha).exists()


def test_a_committed_detach_without_its_journal_entry_is_manual_review(client, app, instance, fake, full_sibling,
                                                                      tmp_path):
    """Commit ambiguity: the drop committed but its journal entry is missing; never inferred as done."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    with pytest.raises(psycopg2.Error, match="protected inventory"):     # 3a S3a: the enabled guard refuses it
        recovery.detach_capture_trigger(sib.dsn)
    with _sibling_guard_disabled(sib, "commit a detach without its journal entry"):
        recovery.detach_capture_trigger(sib.dsn)
    with pytest.raises(RestoreRefused, match="did not record detaching"):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
    assert recovery.RestoreJournal(str(journal), inventory_sha).steps() == ["begin"]
    with pytest.raises(recovery.AnchorConflict, match="capture trigger absent"):
        recovery.recover(sib.anchor, sib.dsn, _review(sib, inventory_sha, dump), layout="shared",
                         journal_dir=str(journal))


@pytest.mark.parametrize("case", ["shared_without_alerts", "voalack_only_with_alerts"])
def test_the_layout_is_declared_never_inferred(client, app, instance, fake, sibling, full_sibling, tmp_path, case):
    _effect(client, app, instance)
    sib = sibling() if case == "shared_without_alerts" else full_sibling()
    layout = "shared" if case == "shared_without_alerts" else "voalack_only"
    dump = tmp_path / "layout.dump"
    sib.dump(dump)
    inventory_sha = _close_and_inventory(sib, instance, fake, [])
    journal = tmp_path / "journal"
    journal.mkdir()
    match = "public.alerts is missing" if case == "shared_without_alerts" else "Alerta's tables are present"
    with pytest.raises(RestoreRefused, match=match):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout=layout)
    with pytest.raises(recovery.AnchorConflict, match=match):
        recovery.recover(sib.anchor, sib.dsn, _review(sib, inventory_sha, dump), layout=layout, journal_dir=str(journal))


def test_a_replay_after_validation_rechecks_and_refuses_drift(client, app, instance, fake, full_sibling, tmp_path):
    """S2 oracle: after a validated restore, a replay rechecks and refuses drift (RestoreFailed 'not validated').
    Re-proved in S3c. S3a: the restore is staged-refused; drift made afterwards (disclosed sibling bypass) is refused by
    the precheck ahead of the staging, and recovery stays closed."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    _staged_refused(sib, dump, inventory_sha, journal)
    with _sibling_guard_disabled(sib, "disable the capture trigger after the staged refusal"):
        _q(sib.dsn, "ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack", fetch=False)
    with pytest.raises(RestoreRefused, match="not as declared"):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
    _recover_refused(sib, _review(sib, inventory_sha, dump), str(journal), "not as declared", fake, instance)


@pytest.mark.parametrize("guard", ["disabled", "missing"])
def test_s3a_a_recognised_installation_without_its_guard_is_still_refused(client, app, instance, fake, full_sibling,
                                                                          tmp_path, guard):
    """Coexistence 3a S3a (new): missing protections never confer restore permission. With the guard's event
    triggers disabled the precheck refuses (the shared inventory reports them); with the guard schema gone the
    staging still refuses (the lifetime schema marks a 3a installation). Nothing is detached either way."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    with _sibling_guard_disabled(sib, f"a recognised 3a installation with its guard {guard}"):
        if guard == "missing":
            _q(sib.dsn, "DROP SCHEMA voalack_guard CASCADE", fetch=False)
        triggers = _q(sib.dsn, "SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger "
                               "WHERE tgrelid = 'public.alerts'::regclass AND NOT tgisinternal ORDER BY 1")
        with pytest.raises(RestoreRefused, match="not as declared" if guard == "disabled" else STAGED):
            recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
        assert "detached" not in recovery.RestoreJournal(str(journal), inventory_sha).steps()
        assert _q(sib.dsn, "SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger "
                           "WHERE tgrelid = 'public.alerts'::regclass AND NOT tgisinternal ORDER BY 1") == triggers


def test_recover_refuses_a_shared_declaration_without_alerts(client, app, instance, fake, sibling, tmp_path):
    """The recovery gate itself (no restore attempted): a database declared shared that has no
    public.alerts is refused by recover; it never takes the Voalack-only branch."""
    _effect(client, app, instance)
    sib = sibling()
    inventory_sha = _close_and_inventory(sib, instance, fake, [])
    review = recovery.write_review(sib.anchor, {"ref": "lab review", "backup_id": "none", "backup_sha256": None,
                                                "inventory_sha256": inventory_sha, "decision": "adopt"})
    with pytest.raises(recovery.AnchorConflict, match="declared shared, but public.alerts is missing"):
        recovery.recover(sib.anchor, sib.dsn, review, layout="shared", journal_dir=str(tmp_path))
    assert recovery.Anchor(sib.anchor).head().phase == "inventoried"


# --- bounded hashing of the backup (PR review finding) ----------------------------------------------------

@pytest.mark.parametrize("size", [0, 1, recovery.HASH_CHUNK, 2 * recovery.HASH_CHUNK + 12345])
def test_backup_digest_is_exact_for_empty_and_multi_chunk_files(tmp_path, size):
    data = os.urandom(size)
    path = tmp_path / "dump.bin"
    path.write_bytes(data)
    assert recovery.file_sha256(str(path)) == hashlib.sha256(data).hexdigest()


def test_backup_digest_never_reads_without_a_bound(tmp_path, monkeypatch):
    """Every read is bounded by HASH_CHUNK; an unbounded read() (the whole dump at once) fails the test."""
    import builtins
    path = tmp_path / "dump.bin"
    path.write_bytes(os.urandom(3 * recovery.HASH_CHUNK + 7))
    sizes = []
    real_open = builtins.open

    class Bounded:
        def __init__(self, handle):
            self.handle = handle

        def read(self, size=-1):
            assert size is not None and 0 < size <= recovery.HASH_CHUNK, size
            sizes.append(size)
            return self.handle.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.handle.close()

    monkeypatch.setattr(builtins, "open", lambda p, mode="r", *a, **k:
                        Bounded(real_open(p, mode, *a, **k)) if str(p) == str(path) else real_open(p, mode, *a, **k))
    digest = recovery.file_sha256(str(path))
    monkeypatch.undo()
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest() and len(sizes) == 5


# --- F5: resumed and completed journals stay staged on a recognised installation --------------------------------------

def _lab_journal(sib, dump, inventory_sha, journal, layout, steps):
    """[lab journal construction, labelled] A valid, bound restore journal prefix written through RestoreJournal with
    exactly the begin fields restore_shared writes; no restore step was performed by it."""
    with psycopg2.connect(sib.dsn) as conn, conn.cursor() as cur:
        publications = recovery._publication_digest(cur)
    j = recovery.RestoreJournal(str(journal), inventory_sha)
    j.append("begin", inventory_sha256=inventory_sha, backup_sha256=recovery.file_sha256(str(dump)), layout=layout,
             contract=recovery.contract_digest(), publications=publications, anchor=recovery._anchor_digest(sib.anchor))
    for step in steps:
        j.append(step, **({"returncode": 0} if step == "restored" else {}))
    return j


def _journal_sha(j):
    with open(j.path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _triggers(sib):
    return _q(sib.dsn, "SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger "
                       "WHERE tgrelid = 'public.alerts'::regclass AND NOT tgisinternal ORDER BY 1")


@pytest.mark.parametrize("case", ["shared-detached", "shared-restored", "shared-recreated", "lost-guard-restored"])
def test_s3a_a_resumed_journal_is_staged(client, app, instance, fake, full_sibling, tmp_path, case):
    """A valid bound journal prefix (resume after detached/restored/recreated) on a recognised 3a installation is
    refused by the staging after the earlier refusals and before any hook, change or journal append. The trigger state
    matches the prefix (absent after detached/restored: detached under the disclosed sibling bypass); lost-guard has the
    guard schema dropped as well (the lifetime marker still recognises it)."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    steps = {"shared-detached": ["detached"], "shared-restored": ["detached", "restored"],
             "shared-recreated": ["detached", "restored", "recreated"],
             "lost-guard-restored": ["detached", "restored"]}[case]
    if "recreated" not in steps:
        with _sibling_guard_disabled(sib, f"construct the trigger state of a resumed {case} journal"):
            recovery.detach_capture_trigger(sib.dsn)
            if case == "lost-guard-restored":
                _q(sib.dsn, "DROP SCHEMA voalack_guard CASCADE", fetch=False)
    j = _lab_journal(sib, dump, inventory_sha, journal, "shared", steps)
    before, triggers, reached = _journal_sha(j), _triggers(sib), []
    with pytest.raises(RestoreRefused, match=STAGED):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal),
                                fault=lambda at: reached.append(at), layout="shared")
    assert reached == [] and _journal_sha(j) == before and _triggers(sib) == triggers


def test_s3a_a_resumed_voalack_only_journal_is_staged(client, app, instance, fake, sibling, tmp_path):
    """The Voalack-only layout (a 3a-era voalack schema; protections_intact marks it): a bound 'restored' prefix is
    refused by the staging before validation, the journal unchanged."""
    _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "vo.dump"
    sib.dump(dump)
    inventory_sha = _close_and_inventory(sib, instance, fake, [])
    journal = tmp_path / "journal"
    journal.mkdir()
    j = _lab_journal(sib, dump, inventory_sha, journal, "voalack_only", ["restored"])
    before, reached = _journal_sha(j), []
    with pytest.raises(RestoreRefused, match=STAGED):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal),
                                fault=lambda at: reached.append(at), layout="voalack_only")
    assert reached == [] and _journal_sha(j) == before


def test_s3a_a_completed_journal_confers_neither_restore_nor_recovery(client, app, instance, fake, full_sibling,
                                                                       tmp_path):
    """A complete bound journal (begin..validated) on a recognised installation: restore_shared's replay is staged,
    and recover() refuses after all its journal checks pass; nothing changes, the anchor stays inventoried."""
    sib, dump, inventory_sha = _inventoried(client, app, instance, fake, full_sibling, tmp_path)
    journal = tmp_path / "journal"
    journal.mkdir()
    j = _lab_journal(sib, dump, inventory_sha, journal, "shared", ["detached", "restored", "recreated", "validated"])
    review = _review(sib, inventory_sha, dump)                # written before the snapshot (an anchor document)
    before, state = _journal_sha(j), _state(sib)
    with pytest.raises(RestoreRefused, match=STAGED):
        recovery.restore_shared(sib.anchor, sib.dsn, str(dump), inventory_sha, str(journal), layout="shared")
    with pytest.raises(recovery.AnchorConflict, match="recovery from a restored backup is staged"):
        recovery.recover(sib.anchor, sib.dsn, review, layout="shared", journal_dir=str(journal))
    assert _journal_sha(j) == before and _state(sib) == state
    assert recovery.Anchor(sib.anchor).head().phase == "inventoried"


# --- F5 residual: recognised Voalack-only backup recovery and reopen stay staged ---------------------------------------

def _voalack_only_inventoried(client, app, instance, fake, sibling, tmp_path):
    _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "vo-only.dump"
    sib.dump(dump)
    inventory_sha = _close_and_inventory(sib, instance, fake, [])
    return sib, dump, inventory_sha


def test_s3a_a_recognised_voalack_only_backup_recovery_is_staged(client, app, instance, fake, sibling, tmp_path):
    """A recognised (3a-era) Voalack-only installation: recover() with a review naming a backup is refused as staged
    before any anchor or database change; the anchor stays inventoried. (Recovery without a backup stays admitted:
    its own controls are the existing no-backup recover tests.)"""
    sib, dump, inventory_sha = _voalack_only_inventoried(client, app, instance, fake, sibling, tmp_path)
    review = _review(sib, inventory_sha, dump)
    before = (_files(sib.anchor), _q(sib.dsn, "SELECT epoch, phase, head_seq, head_sha256 FROM voalack.recovery_epoch"))
    with pytest.raises(recovery.AnchorConflict, match="recovery from a restored backup is staged"):
        recovery.recover(sib.anchor, sib.dsn, review, layout="voalack_only")
    assert recovery.Anchor(sib.anchor).head().phase == "inventoried"
    assert (_files(sib.anchor), _q(sib.dsn, "SELECT epoch, phase, head_seq, head_sha256 FROM voalack.recovery_epoch")) \
        == before


def test_s3a_a_recognised_voalack_only_backup_reopen_is_staged(client, app, instance, fake, sibling, tmp_path):
    """reopen() shares the gate. [lab anchor construction, labelled] A recovering line naming a backup is appended
    through the anchor's own Supervisor, as a completed recover would leave it, without any adoption. reopen() is
    refused as staged before its adoption lookup, manifest write or anchor append: anchor and database unchanged."""
    sib, dump, inventory_sha = _voalack_only_inventoried(client, app, instance, fake, sibling, tmp_path)
    review = _review(sib, inventory_sha, dump)
    head = recovery.Anchor(sib.anchor).head()
    with open(dump, "rb") as handle:
        backup_sha = hashlib.sha256(handle.read()).hexdigest()
    recovery.Supervisor(sib.anchor).append((head.seq, head.sha256), "recovering", inventory_sha256=inventory_sha,
                                           backup_id=f"lab-dump:{os.path.basename(str(dump))}",
                                           backup_sha256=backup_sha, review_sha256=review, review_ref="lab review")
    before = (_files(sib.anchor), _q(sib.dsn, "SELECT epoch, phase, head_seq, head_sha256 FROM voalack.recovery_epoch"))
    with pytest.raises(recovery.AnchorConflict, match="recovery from a restored backup is staged"):
        recovery.reopen(sib.anchor, sib.dsn, layout="voalack_only")
    assert (_files(sib.anchor), _q(sib.dsn, "SELECT epoch, phase, head_seq, head_sha256 FROM voalack.recovery_epoch")) \
        == before
