"""Coexistence 3a S3b: containment, the write-ahead journal with effect receipts, reconciliation and release (r8 section
11; S3b delta r2 + r3, concurred 78f1861c).

Every test runs in its own database (fresh install of the current source) with CONNECT revoked from PUBLIC, so the
containment set K = W union C is exactly the lab logins created here: role connection limits are cluster-wide, and
the session's other databases, logins and the Alerta app are never contained. Teardown restores every lab login's
prior limit and drops the database, even when a test fails.

[lab] The no-restore driver below is the labelled S3b profile: it runs the installed step functions with a journaled
'lab' gap where the S3c restore will be. It is test-tree code, never a production path; the production restore stays
refused before any window (test_production_restore_still_refuses_before_any_window)."""
import json
import uuid

import psycopg2
import pytest

from conftest import DSN
from test_t04_s3a_upgrade import STUB_ALERTA
from voalack import recovery, schema

SOURCE = "0" * 64
PRIORS = {"writer": -1, "reader": 7, "member": -1, "setrole": 3, "heldwriter": 5}


class Crash(Exception):
    """[lab] A simulated coordinator death at a hook point."""


def _q(dsn, statement, args=None, fetch=True):
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(statement, args)
        return cur.fetchall() if fetch else None


def _attestation(name, sysid):
    """The canonical Q4 operator attestation (voalack-recovery-attestation/v1), lab values."""
    return {"schema": "voalack-recovery-attestation/v1", "actor": "lab operator",
            "basis": "lab: no services run in this database", "attested_at": "2026-10-14T00:00:00Z",
            "stopped": {"alerta_application": {"stopped": True, "held_stopped": True,
                                               "detail": "lab: no Alerta application runs for this database"},
                        "housekeeping": {"stopped": True, "held_stopped": True, "detail": "lab: no housekeeping"},
                        "job_runner": {"stopped": True, "held_stopped": True, "detail": "lab: no job runner"}},
            "database": name, "system_identifier": str(sysid)}


@pytest.fixture
def rec():
    """A fresh database with the current source installed, CONNECT revoked from PUBLIC, three alerts, and lab logins:
    writer (W and C), reader (C only), member (W by membership, C), setrole (W by SET ROLE only, C), heldwriter (W and C;
    a test may revoke its CONNECT), and a NOLOGIN group (never contained). Yields a namespace; teardown restores the
    lab logins' limits, drops the database and the roles."""
    tag = uuid.uuid4().hex[:8]
    name = f"voalack_rec_{tag}"
    roles = {k: f"rec_{k}_{tag}" for k in PRIORS}
    group = f"rec_group_{tag}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    cur = admin.cursor()
    cur.execute(f"CREATE DATABASE {name}")
    cur.execute(f"REVOKE CONNECT ON DATABASE {name} FROM PUBLIC")
    dsn = DSN.rsplit("/", 1)[0] + "/" + name
    with psycopg2.connect(dsn) as conn, conn.cursor() as c:
        c.execute(STUB_ALERTA)
    conn = psycopg2.connect(dsn)
    schema.apply(conn)
    conn.commit()
    conn.close()
    cur.execute(f"CREATE ROLE {group} NOLOGIN")
    for key, role in roles.items():
        cur.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'lab-only-rec' CONNECTION LIMIT {PRIORS[key]}"
                    + (" NOINHERIT" if key == "setrole" else ""))
        cur.execute(f"GRANT CONNECT ON DATABASE {name} TO {role}")
    cur.execute(f"GRANT {group} TO {roles['member']}")
    cur.execute(f"GRANT {group} TO {roles['setrole']}")
    with psycopg2.connect(dsn) as conn, conn.cursor() as c:
        c.execute(f"GRANT USAGE ON SCHEMA public TO {group}, {roles['writer']}, {roles['heldwriter']}, {roles['reader']}")
        c.execute(f"GRANT SELECT, INSERT, UPDATE ON public.alerts TO {group}, {roles['writer']}, {roles['heldwriter']}")
        c.execute(f"GRANT SELECT ON public.alerts TO {roles['reader']}")
        for i in range(3):
            c.execute("INSERT INTO public.alerts (id, status, resource, event, environment, origin, create_time) "
                      "VALUES (%s, 'open', %s, 'lab-event', 'Production', 'lab', now())", (f"rec-alert-{i}", f"res-{i}"))
    sysid = _q(dsn, "SELECT system_identifier FROM pg_control_system()")[0][0]
    attestation = _attestation(name, sysid)
    ns = type("Rec", (), {})()
    ns.name, ns.dsn, ns.roles, ns.group, ns.attestation = name, dsn, roles, group, attestation
    ns.role_dsn = lambda key: dsn.replace("lab_admin:lab-only-admin", f"{roles[key]}:lab-only-rec")
    try:
        yield ns
    finally:
        for key, role in roles.items():
            cur.execute(f"ALTER ROLE {role} CONNECTION LIMIT {PRIORS[key]}")
        cur.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        for role in list(roles.values()) + [group]:
            cur.execute(f"DROP ROLE IF EXISTS {role}")
        admin.close()


def _limits(rec):
    rows = _q(rec.dsn, "SELECT rolname, rolconnlimit FROM pg_roles WHERE rolname = ANY (%s)", (list(rec.roles.values()),))
    return {k: dict(rows)[r] for k, r in rec.roles.items()}


def _journal(rec, window):
    return _q(rec.dsn, "SELECT seq, kind, step, intent_seq FROM voalack_guard.recovery_journal WHERE window_id = %s "
                       "ORDER BY seq", (window,))


def lab_no_restore(coordinator):
    """[lab] The labelled S3b no-restore sequence: every installed step, with the journaled lab gap after detach."""
    for step in recovery.S3B_STEPS:
        coordinator.step(step)
        if step == "detach":
            coordinator.lab_gap()


def _open(rec, hook=None):
    return recovery.Coordinator.open(rec.dsn, SOURCE, rec.attestation, hook=hook)


# --- production stays refused; the lab window end to end ---------------------------------------------------------------

def test_production_restore_still_refuses_before_any_window(rec):
    before = _limits(rec)
    with pytest.raises(recovery.RestoreRefused):
        recovery._refuse_staged_restore(rec.dsn)
    assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.recovery_windows")[0][0] == 0
    assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.maintenance_permits")[0][0] == 0
    assert _limits(rec) == before


def test_the_containment_set_is_writers_and_connect_logins_only(rec):
    """K = W union C, logins only: the NOLOGIN group is never listed; member (membership) and setrole (SET ROLE only)
    are writers; reader is CONNECT only. Exact priors recorded. (groupinventory witness.)"""
    snap = _q(rec.dsn, "SELECT voalack_guard.containment_snapshot()")[0][0]
    k = {e["name"]: (e["w"], e["c"], e["limit"]) for e in snap["k"]}
    r = rec.roles
    assert k == {r["writer"]: (True, True, -1), r["reader"]: (False, True, 7), r["member"]: (True, True, -1),
                 r["setrole"]: (True, True, 3), r["heldwriter"]: (True, True, 5)}, k
    assert rec.group not in k


def test_the_no_restore_lab_window_runs_end_to_end(rec):
    held = psycopg2.connect(rec.role_dsn("writer"))
    coordinator = _open(rec)
    try:
        lab_no_restore(coordinator)
        coordinator.close_window()
    finally:
        coordinator.close()
    with pytest.raises(psycopg2.Error):                               # the held writer session was terminated
        held.cursor().execute("SELECT 1")
    window = _q(rec.dsn, "SELECT max(window_id) FROM voalack_guard.recovery_windows")[0][0]
    kinds = [(k, s) for _, k, s, _ in _journal(rec, window)]
    steps = [s for k, s in kinds if k == "seal"]
    assert steps == list(recovery.S3B_STEPS), kinds
    assert ("lab", None) in kinds and kinds[0] == ("open", None) and kinds[-1] == ("close", None)
    assert _limits(rec) == PRIORS                                     # exact priors back
    assert _q(rec.dsn, "SELECT voalack_guard.inventory_problems()")[0][0] == []
    assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL")[0][0] == 0
    probe = _q(rec.dsn, "SELECT evidence FROM voalack_guard.recovery_journal WHERE window_id = %s AND kind = 'seal' "
                        "AND step = 'close'", (window,))[0][0]
    assert probe["message"] == ('voalack: DDL refused, protected inventory would change: '
                                '{"differs public_trigger voalack_capture_ack"}') and probe["sqlstate"] == "P0001", probe
    assert probe["rolled_back"] is True and probe["trigger_enabled_after"] is True, probe


# --- witnesses for the five S3b mutants -------------------------------------------------------------------------------

def test_every_connect_login_is_contained(rec):
    """connectsubset: after the contained seal every member of K, including the CONNECT-only reader, is at limit 0.
    q4: if the contain step is refused (connectsubset, sealbeforecommit), the rolled-back state is observed from a
    fresh connection before cleanup, and its evidence is attached to the same exception as a note before the bare
    re-raise; a failed or missing observation fails here with an AssertionError instead."""
    coordinator = _open(rec)
    try:
        try:
            coordinator.step("contain")
        except recovery.RecoveryClosed as refused:
            refused.add_note(_contain_rolled_back(rec, coordinator.window_id))
            raise
        assert set(_limits(rec).values()) == {0}, _limits(rec)
    finally:
        coordinator.close()


def _contain_rolled_back(rec, window):
    """After a refused contain effect, from fresh connections: exactly one committed contain intent for the window;
    its recorded K is exactly the five lab logins with their exact priors; no receipt and no seal for that intent;
    every member of K at its recorded prior limit. Returns the positive evidence line."""
    intents = _q(rec.dsn, "SELECT seq, prior FROM voalack_guard.recovery_journal WHERE window_id = %s "
                          "AND kind = 'intent' AND step = 'contain'", (window,))
    assert len(intents) == 1, intents
    seq, prior = intents[0]
    recorded = {e["name"]: e["limit"] for e in prior["k"]}
    assert len(recorded) == len(prior["k"]), prior
    assert recorded == {rec.roles[k]: PRIORS[k] for k in PRIORS}, recorded
    receipts = _q(rec.dsn, "SELECT count(*) FROM voalack_guard.recovery_effects WHERE window_id = %s "
                           "AND intent_seq = %s", (window, seq))[0][0]
    seals = _q(rec.dsn, "SELECT count(*) FROM voalack_guard.recovery_journal WHERE window_id = %s AND kind = 'seal' "
                        "AND intent_seq = %s", (window, seq))[0][0]
    now = dict(_q(rec.dsn, "SELECT rolname::text, rolconnlimit FROM pg_roles WHERE rolname = ANY (%s)",
                  (list(recorded),)))
    assert (receipts, seals, now) == (0, 0, recorded), (receipts, seals, now)
    return (f"rollback observed: window {window} contain intent {seq}; receipts 0; seals 0; "
            f"K at recorded priors {json.dumps(sorted(recorded.items()))}")


def test_release_before_close_is_refused_by_the_journal_grammar(rec):
    """releasebeforeclose: after validate, a release intent is not the next step (close is)."""
    coordinator = _open(rec)
    try:
        for step in recovery.S3B_STEPS[:5]:
            coordinator.step(step)
            if step == "detach":
                coordinator.lab_gap()
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator.begin("release")
        assert "release is not the next step" in str(exc.value), exc.value
        assert set(_limits(rec).values()) == {0}
    finally:
        coordinator.close()


def test_a_seal_inside_its_effect_transaction_is_refused(rec):
    """sealbeforecommit: appending the seal inside T_effect, after the receipt, is refused (the receipt's xid is the
    caller's own transaction) and nothing commits."""
    coordinator = _open(rec)
    try:
        coordinator.step("contain")
        seq = coordinator.begin("detach")
        conn = coordinator.conn
        with conn.cursor() as cur:
            cur.execute("SELECT voalack_guard.open_permit(%s, %s)", (coordinator.window_id, seq))
            for name in [recovery.CAPTURE_TRIGGER] + list(recovery.PROTECTION_TRIGGERS):
                cur.execute(f"DROP TRIGGER IF EXISTS {name} ON public.alerts RESTRICT")
            cur.execute("SELECT voalack_guard.record_effect(%s, %s)", (coordinator.window_id, seq))
            with pytest.raises(psycopg2.Error) as exc:
                cur.execute("SELECT voalack_guard.seal_step(%s, %s)", (coordinator.window_id, seq))
        conn.rollback()
        assert "cannot share its effect's transaction" in str(exc.value), exc.value
        assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.recovery_effects WHERE intent_seq = %s", (seq,))[0][0] == 0
        assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.maintenance_permits")[0][0] == 0
    finally:
        coordinator.close()


def test_termination_is_confirmed(rec, monkeypatch):
    """noterminateconfirm: a session that survives termination keeps the window closed with the confirmation
    message (a no-op termination for the held writer, simulated in the lab)."""
    held = psycopg2.connect(rec.role_dsn("writer"))
    held_pid = held.get_backend_pid()
    real = recovery._terminate_backend
    monkeypatch.setattr(recovery, "_terminate_backend",
                        lambda cur, pid: None if pid == held_pid else real(cur, pid))
    coordinator = _open(rec)
    try:
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator.step("contain")
        assert "sessions remain after termination" in str(exc.value), exc.value
        assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.recovery_journal WHERE kind = 'seal'")[0][0] == 0
    finally:
        coordinator.close()
        held.close()


# --- receipts: lost response and rolled-back effect ---------------------------------------------------------------------

def test_a_committed_effect_whose_seal_was_lost_is_sealed_on_resume(rec):
    def hook(point):
        if point == "detach:after_effect":
            raise Crash(point)
    coordinator = _open(rec, hook)
    coordinator.step("contain")
    with pytest.raises(Crash):
        coordinator.step("detach")
    window = coordinator.window_id
    coordinator.close()                                                # the coordinator is gone
    resumed = recovery.Coordinator.resume(rec.dsn, window, SOURCE)
    try:
        assert resumed.classify()["state"] == "seal"
        assert resumed.reconcile() == "detach sealed"
        kinds = [k for _, k, _, _ in _journal(rec, window)]
        assert kinds.count("retire") == 1 and kinds.count("register") == 2, kinds
    finally:
        resumed.close()


def test_an_effect_that_rolled_back_is_rerun_on_resume(rec):
    def hook(point):
        if point == "detach:before_receipt":
            raise Crash(point)
    coordinator = _open(rec, hook)
    coordinator.step("contain")
    with pytest.raises(Crash):
        coordinator.step("detach")
    window = coordinator.window_id
    coordinator.close()                                                # rolls the effect transaction back
    assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.maintenance_permits")[0][0] == 0
    resumed = recovery.Coordinator.resume(rec.dsn, window, SOURCE)
    try:
        assert resumed.classify()["state"] == "redo"
        assert resumed.reconcile() == "detach re-run and sealed"
    finally:
        resumed.close()


# --- identity: exact backend binding and its prerequisite ----------------------------------------------------------------

def test_a_window_needs_the_identity_reader_prerequisite(rec):
    """open_window refuses unless voalack_guard_owner can read backend identities (pg_read_all_stats): without it the
    protector could not compare the coordinator's exact backend start, and an unreadable identity never matches."""
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    try:
        admin.cursor().execute("REVOKE pg_read_all_stats FROM voalack_guard_owner")
        with pytest.raises(recovery.RecoveryClosed) as exc:
            _open(rec)
        assert "voalack_guard_owner must have pg_read_all_stats" in str(exc.value), exc.value
        assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.recovery_windows")[0][0] == 0
    finally:
        admin.cursor().execute("GRANT pg_read_all_stats TO voalack_guard_owner")
        admin.close()


def test_another_backend_of_the_executor_role_cannot_act_under_the_permit(rec):
    """Under the window's open permit, a second superuser backend of the same executor role (not the registered
    coordinator) is refused by the protector; the coordinator's own DDL is the admitted control (the detach step)."""
    coordinator = _open(rec)
    try:
        coordinator.step("contain")
        coordinator.step("detach")
        other = psycopg2.connect(rec.dsn)
        try:
            with pytest.raises(psycopg2.Error) as exc:
                other.cursor().execute("CREATE TRIGGER voalack_alert_lifetime AFTER INSERT ON public.alerts "
                                       "FOR EACH ROW EXECUTE FUNCTION voalack.alert_lifetime()")
            assert "belongs to its registered coordinator" in str(exc.value), exc.value
        finally:
            other.close()
    finally:
        coordinator.close()


# --- K = W union C: a held writer whose CONNECT was revoked (W minus C) ----------------------------------------------

def test_a_held_writer_without_connect_is_contained_and_released(rec):
    held = psycopg2.connect(rec.role_dsn("heldwriter"))
    _q(rec.dsn, f"REVOKE CONNECT ON DATABASE {rec.name} FROM {rec.roles['heldwriter']}", fetch=False)
    snap = _q(rec.dsn, "SELECT voalack_guard.containment_snapshot()")[0][0]
    entry = next(e for e in snap["k"] if e["name"] == rec.roles["heldwriter"])
    assert (entry["w"], entry["c"], entry["limit"]) == (True, False, 5), entry
    coordinator = _open(rec)
    try:
        coordinator.step("contain")
        with pytest.raises(psycopg2.Error):
            held.cursor().execute("SELECT 1")                         # terminated, never used after containment
        assert _limits(rec)["heldwriter"] == 0
        for step in recovery.S3B_STEPS[1:]:
            coordinator.step(step)
            if step == "detach":
                coordinator.lab_gap()
        assert _limits(rec)["heldwriter"] == 5
    finally:
        coordinator.close()
        held.close()


# --- the release boundary: returning clients ------------------------------------------------------------------------

def test_a_client_returning_before_the_release_seal_works_under_normal_protection(rec):
    seen = {}

    def hook(point):
        if point == "release:after_effect":
            writer = psycopg2.connect(rec.role_dsn("writer"))
            try:
                with writer.cursor() as cur:
                    cur.execute("INSERT INTO public.alerts (id, status, resource, event, environment, origin, "
                                "create_time) VALUES ('rec-returning', 'open', 'r', 'lab-event', 'Production', 'lab', now())")
                writer.commit()
                with pytest.raises(psycopg2.Error) as exc:
                    writer.cursor().execute("DROP TRIGGER voalack_alert_lifetime ON public.alerts")
                seen["ddl"] = str(exc.value)
            finally:
                writer.close()
    coordinator = _open(rec, hook)
    try:
        lab_no_restore(coordinator)
    finally:
        coordinator.close()
    assert "must be owner" in seen["ddl"] or "DDL refused" in seen["ddl"], seen
    assert _limits(rec) == PRIORS
    assert _q(rec.dsn, "SELECT count(*) FROM public.alerts WHERE id = 'rec-returning'")[0][0] == 1


# --- serialization: takeover and appends ----------------------------------------------------------------------------

def test_takeover_is_refused_while_the_coordinator_is_connected(rec):
    coordinator = _open(rec)
    try:
        with pytest.raises(recovery.RecoveryClosed) as exc:
            recovery.Coordinator.resume(rec.dsn, coordinator.window_id, SOURCE)
        assert "is still connected" in str(exc.value), exc.value
    finally:
        coordinator.close()


def test_two_simultaneous_takeovers_register_once(rec):
    """After the coordinator has gone, two replacements race: the window row lock serializes them, and the second,
    deciding after the wait, sees the first registered and connected, and is refused."""
    import threading
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.close()
    first = psycopg2.connect(rec.dsn)
    with first.cursor() as cur:
        cur.execute("SELECT voalack_guard.register_backend(%s, %s)", (window, SOURCE))     # holds the window row lock, uncommitted
    outcome = {}

    def second():
        conn = psycopg2.connect(rec.dsn)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT voalack_guard.register_backend(%s, %s)", (window, SOURCE))
            conn.commit()
            outcome["second"] = "registered"
        except psycopg2.Error as exc:
            outcome["second"] = str(exc)
        finally:
            conn.close()
    t = threading.Thread(target=second)
    t.start()
    t.join(2)
    assert t.is_alive(), "the second takeover did not wait for the window lock"
    first.commit()
    t.join(30)
    try:
        assert "is still connected" in outcome["second"], outcome
        kinds = [k for _, k, _, _ in _journal(rec, window)]
        assert kinds.count("register") == 2 and kinds.count("retire") == 1, kinds
    finally:
        first.close()


def test_competing_and_stale_appends_are_refused(rec):
    coordinator = _open(rec)
    other = psycopg2.connect(rec.dsn)
    try:
        seq = coordinator.begin("contain")
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator.begin("contain")                               # a second intent while one is unsealed
        assert "still unsealed" in str(exc.value), exc.value
        with pytest.raises(psycopg2.Error) as exc2:
            other.cursor().execute("SELECT voalack_guard.record_effect(%s, %s)", (coordinator.window_id, seq))
        other.rollback()
        assert "not the registered coordinator" in str(exc2.value), exc2.value
        coordinator.effect("contain", seq)
        coordinator.seal("contain", seq)
        with pytest.raises(recovery.RecoveryClosed) as exc3:
            coordinator._call("stale seal", "SELECT voalack_guard.seal_step(%s, %s)", (coordinator.window_id, seq))
        assert "is not the window's latest unsealed" in str(exc3.value), exc3.value
    finally:
        other.close()
        coordinator.close()


# --- abandon never erases a hold ------------------------------------------------------------------------------------

def _operator(rec, query, args):
    conn = psycopg2.connect(rec.dsn)
    try:
        with conn.cursor() as cur:
            cur.execute(query, args)
            row = cur.fetchone()
        conn.commit()
        return row[0]
    except psycopg2.Error as exc:
        conn.rollback()
        return str(exc)
    finally:
        conn.close()


def _settle_priors(rec):
    for key, role in rec.roles.items():
        _q(rec.dsn, f"ALTER ROLE {role} CONNECTION LIMIT {PRIORS[key]}", fetch=False)


def _dispose(rec, window, decision):
    return _operator(rec, "SELECT voalack_guard.record_disposition(%s, 'lab operator', 'lab basis', %s)", (window, decision))


def test_abandon_needs_the_permit_revoked_first_and_a_settled_window(rec):
    """Operator order (review 7d13602a): the exemption is closed before any limit returns; abandon then still refuses
    while normal protection is missing (the detached triggers), so the window stays an active, unresolved hold."""
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.step("contain")
    coordinator.step("detach")
    try:
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator._call("own", "SELECT voalack_guard.record_disposition(%s, 'me', 'b', 'abandon')", (window,))
        assert "cannot record its own window's disposition" in str(exc.value), exc.value
    finally:
        coordinator.close()
    refused = _dispose(rec, window, "abandon")
    assert "permit is still open (revoke it first)" in refused, refused
    _dispose(rec, window, "revoke_permit")
    assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL")[0][0] == 0
    _settle_priors(rec)
    refused = _dispose(rec, window, "abandon")
    assert "not settled" in refused and "missing public_trigger" in refused, refused
    assert "already active" in _operator(rec, "SELECT voalack_guard.open_window(%s, %s::jsonb)",
                                         (SOURCE, json.dumps(rec.attestation)))


def test_limits_restored_before_the_revocation_refuse_abandon(rec):
    """Order: a revocation recorded only after the limits returned is not effective custody; abandon refuses and the
    window stays an active hold."""
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.step("contain")
    coordinator.step("detach")
    coordinator.close()
    _settle_priors(rec)                                                # wrong order: limits first
    _dispose(rec, window, "revoke_permit")
    refused = _dispose(rec, window, "abandon")
    assert "no committed permit revocation is recorded while containment held" in refused, refused
    revoke = _q(rec.dsn, "SELECT evidence FROM voalack_guard.recovery_journal WHERE window_id = %s AND kind = "
                         "'disposition' ORDER BY seq DESC LIMIT 1", (window,))[0][0]
    assert revoke["decision"] == "revoke_permit" and revoke["checked"]["contained"] is False, revoke


def test_a_revocation_in_the_same_transaction_does_not_count(rec):
    """Transaction boundary (review 94308a5d): revoke, restore every limit and abandon in ONE operator transaction:
    the uncommitted revocation is not committed custody; abandon refuses and nothing commits."""
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.step("contain")
    coordinator.step("detach")
    coordinator.close()
    conn = psycopg2.connect(rec.dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT voalack_guard.record_disposition(%s, 'lab operator', 'lab basis', 'revoke_permit')",
                        (window,))
            for key, role in rec.roles.items():
                cur.execute(f"ALTER ROLE {role} CONNECTION LIMIT {PRIORS[key]}")
            with pytest.raises(psycopg2.Error) as exc:
                cur.execute("SELECT voalack_guard.record_disposition(%s, 'lab operator', 'lab basis', 'abandon')",
                            (window,))
        assert "no committed permit revocation is recorded while containment held" in str(exc.value), exc.value
    finally:
        conn.rollback()
        conn.close()
    assert set(_limits(rec).values()) == {0}                           # nothing of that transaction committed
    assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL")[0][0] == 1


def test_a_revocation_inside_a_savepoint_does_not_count(rec):
    """Review 9dce333b: a revocation inserted inside a savepoint has its own subtransaction xid, but its top-level
    transaction has not committed; abandon refuses."""
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.step("contain")
    coordinator.step("detach")
    coordinator.close()
    conn = psycopg2.connect(rec.dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT revoke_sp")
            cur.execute("SELECT voalack_guard.record_disposition(%s, 'lab operator', 'lab basis', 'revoke_permit')",
                        (window,))
            cur.execute("RELEASE SAVEPOINT revoke_sp")
            cur.execute("SAVEPOINT restore_sp")
            for key, role in rec.roles.items():
                cur.execute(f"ALTER ROLE {role} CONNECTION LIMIT {PRIORS[key]}")
            with pytest.raises(psycopg2.Error) as exc:
                cur.execute("SELECT voalack_guard.record_disposition(%s, 'lab operator', 'lab basis', 'abandon')",
                            (window,))
        assert "no committed permit revocation is recorded while containment held" in str(exc.value), exc.value
    finally:
        conn.rollback()
        conn.close()
    assert set(_limits(rec).values()) == {0}


def _blocked_by(observer_dsn, waiter_pid):
    return _q(observer_dsn, "SELECT pg_blocking_pids(%s)", (waiter_pid,))[0][0]


def test_a_concurrent_restoration_cannot_commit_before_the_revocation(rec):
    """Restoration first (requested 9dce333b): the restorer's uncommitted ALTER ROLE holds ROW EXCLUSIVE on pg_authid;
    the revoker's SHARE lock is BLOCKED BY the restorer (pg_blocking_pids, observed while waiting). After the restorer
    commits, the revoker decides on the committed restoration: contained = false, so abandon refuses."""
    import threading
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.step("contain")
    coordinator.step("detach")
    coordinator.close()
    restorer = psycopg2.connect(rec.dsn)
    with restorer.cursor() as cur:
        for key, role in rec.roles.items():
            cur.execute(f"ALTER ROLE {role} CONNECTION LIMIT {PRIORS[key]}")      # uncommitted
    revoker = psycopg2.connect(rec.dsn)
    result = {}

    def revoke():
        try:
            with revoker.cursor() as cur:
                cur.execute("SELECT voalack_guard.record_disposition(%s, 'lab operator', 'lab basis', 'revoke_permit')",
                            (window,))
            revoker.commit()
            result["ok"] = True
        except psycopg2.Error as exc:
            result["error"] = str(exc)
    t = threading.Thread(target=revoke)
    t.start()
    blockers = []
    for _ in range(100):
        blockers = _blocked_by(rec.dsn, revoker.get_backend_pid())
        if blockers:
            break
        t.join(0.05)
    assert blockers == [restorer.get_backend_pid()], blockers         # the revocation waits on the restoration
    assert t.is_alive()
    restorer.commit()
    restorer.close()
    t.join(30)
    revoker.close()
    assert result == {"ok": True}, result
    revoke_ev = _q(rec.dsn, "SELECT evidence FROM voalack_guard.recovery_journal WHERE window_id = %s AND kind = "
                            "'disposition' ORDER BY seq DESC LIMIT 1", (window,))[0][0]
    assert revoke_ev["decision"] == "revoke_permit" and revoke_ev["checked"]["contained"] is False, revoke_ev
    refused = _dispose(rec, window, "abandon")
    assert "no committed permit revocation is recorded while containment held" in refused, refused


def test_a_restoration_waits_for_the_revocation_to_commit(rec):
    """Revocation first (requested cbee1d9a): the revoker's uncommitted disposition holds SHARE on pg_authid; the
    restorer's ALTER ROLE is BLOCKED BY the revoker (pg_blocking_pids, observed while waiting) until the revocation
    commits. With protection restored (the window ran through recreate) and priors back, abandon is admitted."""
    import threading
    coordinator = _open(rec)
    window = coordinator.window_id
    for step in recovery.S3B_STEPS[:4]:
        coordinator.step(step)
        if step == "detach":
            coordinator.lab_gap()
    coordinator.close()
    revoker = psycopg2.connect(rec.dsn)
    with revoker.cursor() as cur:
        cur.execute("SELECT voalack_guard.record_disposition(%s, 'lab operator', 'lab basis', 'revoke_permit')",
                    (window,))                                          # uncommitted, holds SHARE on pg_authid
    restorer = psycopg2.connect(rec.dsn)
    result = {}

    def restore():
        try:
            with restorer.cursor() as cur:
                for key, role in rec.roles.items():
                    cur.execute(f"ALTER ROLE {role} CONNECTION LIMIT {PRIORS[key]}")
            restorer.commit()
            result["ok"] = True
        except psycopg2.Error as exc:
            result["error"] = str(exc)
    t = threading.Thread(target=restore)
    t.start()
    blockers = []
    for _ in range(100):
        blockers = _blocked_by(rec.dsn, restorer.get_backend_pid())
        if blockers:
            break
        t.join(0.05)
    assert blockers == [revoker.get_backend_pid()], blockers           # the restoration waits on the revocation
    assert t.is_alive() and set(_limits(rec).values()) == {0}          # nothing restored while it waits
    revoker.commit()
    revoker.close()
    t.join(30)
    restorer.close()
    assert result == {"ok": True}, result
    revoke_ev = _q(rec.dsn, "SELECT evidence FROM voalack_guard.recovery_journal WHERE window_id = %s AND kind = "
                            "'disposition' ORDER BY seq DESC LIMIT 1", (window,))[0][0]
    assert revoke_ev["checked"]["contained"] is True and revoke_ev["xact"].isdigit(), revoke_ev
    assert _limits(rec) == PRIORS
    _dispose(rec, window, "abandon")
    kinds = [k for _, k, _, _ in _journal(rec, window)]
    assert kinds[-2:] == ["disposition", "close"], kinds


def test_a_revocation_without_its_transaction_identity_never_counts(rec):
    """Review cbee1d9a: an unavailable status for a valid, trigger-derived xact is not the same as missing evidence. A
    revoke record planted [lab: session_replication_role = replica, raw corruption by a trusted superuser] with
    contained = true but no xact never counts as a committed revocation; abandon refuses."""
    coordinator = _open(rec)
    window = coordinator.window_id
    for step in recovery.S3B_STEPS[:4]:
        coordinator.step(step)
        if step == "detach":
            coordinator.lab_gap()
    coordinator.close()
    _q(rec.dsn, "UPDATE voalack_guard.maintenance_permits SET closed_at = clock_timestamp() WHERE window_id = %s "
                "AND closed_at IS NULL", (window,), fetch=False)       # the one-way close, without a revoke record
    conn = psycopg2.connect(rec.dsn)
    with conn.cursor() as cur:
        cur.execute("SET session_replication_role = replica")
        cur.execute("INSERT INTO voalack_guard.recovery_journal (window_id, seq, kind, evidence, pid, backend_start) "
                    "SELECT %s, max(seq) + 1, 'disposition', %s::jsonb, 0, now() FROM voalack_guard.recovery_journal "
                    "WHERE window_id = %s", (window, json.dumps({"actor": "x", "basis": "y", "decision": "revoke_permit",
                                                                  "checked": {"contained": True}}), window))
        cur.execute("SET session_replication_role = origin")
    conn.commit()
    conn.close()
    _settle_priors(rec)
    refused = _dispose(rec, window, "abandon")
    assert "no committed permit revocation is recorded while containment held" in refused, refused


def test_a_settled_window_is_abandoned_and_a_successor_contains(rec):
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.step("contain")
    coordinator.close()
    assert "role" in _dispose(rec, window, "abandon")                  # limits still 0: not settled
    _dispose(rec, window, "revoke_permit")
    _settle_priors(rec)
    _dispose(rec, window, "abandon")
    kinds = [k for _, k, _, _ in _journal(rec, window)]
    assert kinds[-2:] == ["disposition", "close"], kinds
    successor = _open(rec)
    try:
        successor.step("contain")
        assert set(_limits(rec).values()) == {0}
    finally:
        successor.close()


# --- reserved seals: substituted, stale and missing evidence ----------------------------------------------------------

def test_a_directly_inserted_seal_runs_its_own_checks(rec):
    """F1 (review 7d13602a): the seal row's insert trigger is the enforcement point. A directly inserted validate seal
    with a forged, correctly shaped tag runs the real validation and carries the trigger's own evidence; the same insert
    after the lifetime data changed is refused; another backend cannot insert it; no generic journal helper exists."""
    coordinator = _open(rec)
    try:
        for step in recovery.S3B_STEPS[:4]:
            coordinator.step(step)
            if step == "detach":
                coordinator.lab_gap()
        seq = coordinator.begin("validate")
        w = coordinator.window_id
        forged = json.dumps({"producer": "validate_window/v1", "intent_seq": seq})
        insert = ("INSERT INTO voalack_guard.recovery_journal (window_id, seq, kind, step, intent_seq, evidence, pid, "
                  "backend_start) VALUES (%s, 1, 'seal', 'validate', %s, %s::jsonb, 0, now()) RETURNING seq")
        other = psycopg2.connect(rec.dsn)
        try:
            with pytest.raises(psycopg2.Error) as exc:
                other.cursor().execute(insert, (w, seq, forged))
            assert "not the registered coordinator" in str(exc.value), exc.value
        finally:
            other.close()
        _q(rec.dsn, "INSERT INTO public.alerts (id, status, resource, event, environment, origin, create_time) "
                    "VALUES ('rec-forge', 'open', 'veeamone:rec', 'VeeamOneAlarm', 'Production', 'lab', now())", fetch=False)
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator._call("direct validate seal", insert, (w, seq, forged))
        assert "validation fails" in str(exc.value) and "lifetime data changed" in str(exc.value), exc.value
        assert _q(rec.dsn, "SELECT count(*) FROM pg_proc WHERE proname IN ('journal_append', 'validate_window', "
                           "'close_and_probe') AND pronamespace = 'voalack_guard'::regnamespace")[0][0] == 0
    finally:
        coordinator.close()


def test_a_directly_inserted_seal_carries_the_triggers_evidence(rec):
    coordinator = _open(rec)
    try:
        for step in recovery.S3B_STEPS[:4]:
            coordinator.step(step)
            if step == "detach":
                coordinator.lab_gap()
        seq = coordinator.begin("validate")
        n = coordinator._call("direct validate seal",
                              "INSERT INTO voalack_guard.recovery_journal (window_id, seq, kind, step, intent_seq, "
                              "evidence, pid, backend_start) VALUES (%s, 1, 'seal', 'validate', %s, %s::jsonb, 0, now()) "
                              "RETURNING seq", (coordinator.window_id, seq,
                                                json.dumps({"producer": "validate_window/v1", "intent_seq": seq})))
        evidence, pid = _q(rec.dsn, "SELECT evidence, pid FROM voalack_guard.recovery_journal WHERE window_id = %s "
                                    "AND seq = %s", (coordinator.window_id, n))[0]
        assert evidence["validated_by"] == "journal_insert_guard/v1" and "producer" not in evidence, evidence
        assert pid == coordinator.conn.get_backend_pid()
    finally:
        coordinator.close()


def test_a_forged_receipt_is_refused_or_rebound(rec):
    coordinator = _open(rec)
    try:
        coordinator.step("contain")
        seq = coordinator.begin("detach")
        forged = ("INSERT INTO voalack_guard.recovery_effects (window_id, intent_seq, effect_xid, effect, pid, backend_start) "
                  "VALUES (%s, %s, '1'::xid8, '{\"forged\": true}'::jsonb, 0, now())")
        with pytest.raises(recovery.RecoveryClosed) as exc:              # no detach effect yet: refused
            coordinator._call("forged receipt", forged, (coordinator.window_id, seq))
        assert "the detach effect does not hold" in str(exc.value), exc.value
        with pytest.raises(recovery.RecoveryClosed) as exc:              # another intent
            coordinator._call("forged receipt", forged, (coordinator.window_id, seq - 1))
        assert "is not the window's latest unsealed intent" in str(exc.value), exc.value
    finally:
        coordinator.close()


def test_direct_permit_writes_outside_the_intents_are_refused(rec):
    coordinator = _open(rec)
    try:
        coordinator.step("contain")
        w = coordinator.window_id
        seq = _q(rec.dsn, "SELECT max(seq) FROM voalack_guard.recovery_journal WHERE window_id = %s", (w,))[0][0]
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator._call("permit insert", "INSERT INTO voalack_guard.maintenance_permits (executor, phase, window_id, "
                                               "intent_seq) VALUES (session_user, 'recreate', %s, %s)", (w, seq))
        assert "only under the window's current detach intent" in str(exc.value), exc.value
        coordinator.step("detach")
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator._call("phase update", "UPDATE voalack_guard.maintenance_permits SET phase = 'recreate' "
                                              "WHERE window_id = %s", (w,))
        assert "exact compare-and-set" in str(exc.value), exc.value
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator._call("permit delete", "DELETE FROM voalack_guard.maintenance_permits WHERE window_id = %s", (w,))
        assert "append-only" in str(exc.value), exc.value
    finally:
        coordinator.close()


def test_resume_refuses_another_source_identity(rec):
    coordinator = _open(rec)
    window = coordinator.window_id
    coordinator.close()
    with pytest.raises(recovery.RecoveryClosed) as exc:
        recovery.Coordinator.resume(rec.dsn, window, "1" * 64)
    assert "approved source identity does not match" in str(exc.value), exc.value


# --- gap table rows -------------------------------------------------------------------------------------------------

def test_a_lost_contain_response_is_sealed_after_termination(rec):
    held = psycopg2.connect(rec.role_dsn("writer"))

    def hook(point):
        if point == "contain:after_effect":
            raise Crash(point)
    coordinator = _open(rec, hook)
    with pytest.raises(Crash):
        coordinator.step("contain")
    window = coordinator.window_id
    coordinator.close()
    resumed = recovery.Coordinator.resume(rec.dsn, window, SOURCE)
    try:
        assert resumed.reconcile() == "contain sealed"
        with pytest.raises(psycopg2.Error):
            held.cursor().execute("SELECT 1")
    finally:
        resumed.close()
        held.close()


def test_an_effect_without_its_receipt_stays_unexplained(rec):
    def hook(point):
        if point == "contain:after_intent":
            raise Crash(point)
    coordinator = _open(rec, hook)
    with pytest.raises(Crash):
        coordinator.step("contain")
    window = coordinator.window_id
    coordinator.close()
    for role in rec.roles.values():                                    # an outside actor applies the target
        _q(rec.dsn, f"ALTER ROLE {role} CONNECTION LIMIT 0", fetch=False)
    resumed = recovery.Coordinator.resume(rec.dsn, window, SOURCE)
    try:
        with pytest.raises(recovery.RecoveryClosed) as exc:
            resumed.reconcile()
        assert "an effect without its receipt" in str(exc.value), exc.value
    finally:
        resumed.close()


def test_a_release_effect_rolled_back_is_rerun(rec):
    def hook(point):
        if point == "release:before_receipt":
            raise Crash(point)
    coordinator = _open(rec, hook)
    with pytest.raises(Crash):
        lab_no_restore(coordinator)
    window = coordinator.window_id
    coordinator.close()
    assert set(_limits(rec).values()) == {0}                           # the release transaction rolled back
    resumed = recovery.Coordinator.resume(rec.dsn, window, SOURCE)
    try:
        assert resumed.reconcile() == "release re-run and sealed"
        assert _limits(rec) == PRIORS
    finally:
        resumed.close()


@pytest.mark.parametrize("change", ["limit", "new-login", "lifetime"])
def test_a_change_inside_the_window_keeps_it_closed(rec, change):
    coordinator = _open(rec)
    extra = f"rec_extra_{uuid.uuid4().hex[:6]}"
    try:
        coordinator.step("contain")
        if change == "limit":
            _q(rec.dsn, f"ALTER ROLE {rec.roles['reader']} CONNECTION LIMIT 7", fetch=False)
        elif change == "new-login":
            _q(rec.dsn, f"CREATE ROLE {extra} LOGIN", fetch=False)
            _q(rec.dsn, f"GRANT CONNECT ON DATABASE {rec.name} TO {extra}", fetch=False)
        else:
            # a Veeam ONE-class alert opens a lifetime (voalack.alert_lifetime): the lifetime data changes
            _q(rec.dsn, "INSERT INTO public.alerts (id, status, resource, event, environment, origin, create_time) "
                        "VALUES ('rec-inside', 'open', 'veeamone:rec', 'VeeamOneAlarm', 'Production', 'lab', now())",
               fetch=False)
        with pytest.raises(recovery.RecoveryClosed) as exc:
            coordinator.step("detach")
        want = {"limit": "is not 0", "new-login": "CONNECT login set changed", "lifetime": "lifetime data changed"}
        assert want[change] in str(exc.value), exc.value
        assert _q(rec.dsn, "SELECT count(*) FROM voalack_guard.maintenance_permits")[0][0] == 0
    finally:
        coordinator.close()
        if change == "new-login":
            _q(rec.dsn, f"REVOKE CONNECT ON DATABASE {rec.name} FROM {extra}", fetch=False)
            _q(rec.dsn, f"DROP ROLE IF EXISTS {extra}", fetch=False)


@pytest.mark.parametrize("ddl", [
    "CREATE OR REPLACE FUNCTION voalack_guard.receipt_binding(p_window bigint, p_intent_seq bigint) RETURNS jsonb "
    "LANGUAGE sql STABLE AS $$ SELECT '{}'::jsonb $$",
    "DROP FUNCTION voalack_guard.receipt_binding(bigint, bigint)",
    "ALTER FUNCTION voalack_guard.receipt_binding(bigint, bigint) SECURITY DEFINER",
    "GRANT EXECUTE ON FUNCTION voalack_guard.receipt_binding(bigint, bigint) TO PUBLIC",
    "ALTER FUNCTION voalack_guard.receipt_binding(bigint, bigint) RESET search_path",
], ids=["body", "drop", "security", "acl", "config"])
def test_receipt_binding_cannot_be_tampered_with_or_removed(rec, ddl):
    """Review 351768d6: receipt_binding(bigint, bigint) is a protected function. Outside any permit, a superuser's
    body replacement, drop, security, ACL or configuration change is refused by the guard, and the function is
    unchanged afterwards."""
    before = _q(rec.dsn, "SELECT md5(prosrc), prosecdef, proacl::text, proconfig::text FROM pg_proc "
                         "WHERE oid = to_regprocedure('voalack_guard.receipt_binding(bigint,bigint)')")
    with pytest.raises(psycopg2.Error) as exc:
        _q(rec.dsn, ddl, fetch=False)
    assert "protected inventory would change" in str(exc.value), exc.value
    assert _q(rec.dsn, "SELECT md5(prosrc), prosecdef, proacl::text, proconfig::text FROM pg_proc "
                       "WHERE oid = to_regprocedure('voalack_guard.receipt_binding(bigint,bigint)')") == before
    assert _q(rec.dsn, "SELECT voalack_guard.inventory_problems()")[0][0] in (None, [])


def test_the_installed_guard_schema_holds_exactly_the_protected_functions(rec):
    """Review e42dfa12 (S3b condition; the general schema-function census is deferred): on an installed guard, every
    function in voalack_guard is a listed protected function and there is exactly one per name, so every guard call
    (all made with exact bigint, text or jsonb arguments) resolves to the protected function and no unlisted overload
    can capture it."""
    from test_coexist_s3_guard import PROTECTED_FUNCTIONS
    installed = [r[0] for r in _q(rec.dsn, "SELECT p.oid::regprocedure::text FROM pg_proc p "
                                           "WHERE p.pronamespace = 'voalack_guard'::regnamespace ORDER BY 1")]
    listed = sorted(f for f in PROTECTED_FUNCTIONS if f.startswith("voalack_guard."))
    assert sorted(installed) == listed, sorted(set(installed) ^ set(listed))
    names = [f.split("(")[0] for f in installed]
    assert len(names) == len(set(names)), sorted(n for n in set(names) if names.count(n) > 1)


def _without(d, key):
    return {k: v for k, v in d.items() if k != key}


def _component(**changes):
    def mutate(a):
        a = json.loads(json.dumps(a))
        a["stopped"]["housekeeping"].update(changes)
        return a
    return mutate


ATTESTATION_NEGATIVES = {
    "timestamp-missing": lambda a: _without(a, "attested_at"),
    "timestamp-null": lambda a: {**a, "attested_at": None},
    "timestamp-empty": lambda a: {**a, "attested_at": ""},
    "timestamp-invalid": lambda a: {**a, "attested_at": "2026-13-40T25:61:00Z"},
    "timestamp-word": lambda a: {**a, "attested_at": "now"},
    "timestamp-infinity": lambda a: {**a, "attested_at": "infinity"},
    "timestamp-number": lambda a: {**a, "attested_at": 1760400000},
    "actor-number": lambda a: {**a, "actor": 7},
    "actor-object": lambda a: {**a, "actor": {"name": "x"}},
    "actor-blank": lambda a: {**a, "actor": "  "},
    "basis-bool": lambda a: {**a, "basis": True},
    "basis-null": lambda a: {**a, "basis": None},
    "schema-missing": lambda a: _without(a, "schema"),
    "schema-other": lambda a: {**a, "schema": "voalack-recovery-attestation/v0"},
    "extra-key": lambda a: {**a, "note": "x"},
    "stopped-array": lambda a: {**a, "stopped": ["alerta", "housekeeping", "job runner"]},
    "stopped-null-entry": lambda a: {**a, "stopped": {**a["stopped"], "job_runner": None}},
    "stopped-empty-entry": lambda a: {**a, "stopped": {**a["stopped"], "job_runner": {}}},
    "stopped-string-entry": lambda a: {**a, "stopped": {**a["stopped"], "job_runner": "stopped"}},
    "component-missing": lambda a: {**a, "stopped": _without(a["stopped"], "housekeeping")},
    "component-extra": lambda a: {**a, "stopped": {**a["stopped"], "mailer": a["stopped"]["job_runner"]}},
    "component-not-stopped": _component(stopped=False),
    "component-not-held": _component(held_stopped="true"),
    "component-detail-blank": _component(detail=""),
    "component-detail-number": _component(detail=3),
    "database-other": lambda a: {**a, "database": "postgres"},
    "database-number": lambda a: {**a, "database": 5},
    "system-other": lambda a: {**a, "system_identifier": "1"},
    "system-number": lambda a: {**a, "system_identifier": int(a["system_identifier"])},
    "not-object": lambda a: ["actor", "basis"],
}


@pytest.mark.parametrize("case", sorted(ATTESTATION_NEGATIVES))
def test_an_incomplete_or_mistyped_attestation_refuses_before_anything_commits(rec, case):
    """Review 81d9912b F1 (Q4): the canonical attestation schema is enforced at the ordinary admitted write path. Each
    malformed attestation is refused before any window, journal record, registration or permit exists, and no role
    limit changes. (The attestation is an operator assertion: it observes no service and authorizes nothing.)"""
    bad = ATTESTATION_NEGATIVES[case](rec.attestation)
    with pytest.raises(psycopg2.Error) as exc:
        _q(rec.dsn, "SELECT voalack_guard.open_window(%s, %s::jsonb)", (SOURCE, json.dumps(bad)), fetch=False)
    assert "the operator attestation is missing, incomplete, mistyped or bound to another database/cluster" \
        in str(exc.value), (case, exc.value)
    for table in ("recovery_windows", "recovery_journal", "executor_backends", "recovery_effects",
                  "maintenance_permits"):
        assert _q(rec.dsn, f"SELECT count(*) FROM voalack_guard.{table}")[0][0] == 0, (case, table)
    assert _limits(rec) == PRIORS, case
    with pytest.raises(recovery.RecoveryClosed) as exc2:                 # the coordinator path refuses the same way
        recovery.Coordinator.open(rec.dsn, SOURCE, bad)
    assert "the operator attestation is missing" in str(exc2.value), (case, exc2.value)
    for table in ("recovery_windows", "recovery_journal", "executor_backends", "recovery_effects",
                  "maintenance_permits"):                                # review a178ba6f: the same oracle here
        assert _q(rec.dsn, f"SELECT count(*) FROM voalack_guard.{table}")[0][0] == 0, (case, "coordinator", table)
    assert _limits(rec) == PRIORS, case


def test_the_canonical_attestation_opens_a_window(rec):
    """The valid v1 attestation is admitted and recorded exactly as given."""
    coordinator = _open(rec)
    stored = _q(rec.dsn, "SELECT attestation FROM voalack_guard.recovery_windows WHERE window_id = %s",
                (coordinator.window_id,))[0][0]
    assert stored == rec.attestation
    coordinator.close()


# --- q4: the contain receipt's predicate on the unmutated source -------------------------------------------------------

def test_a_contain_receipt_with_a_connect_only_login_above_zero_is_refused(rec):
    """The receipt (effects_insert_guard) refuses a contain effect that limited only the writers: inside the
    uncommitted effect the writers really are at 0 and the CONNECT-only reader is still at 7; the refusal names it;
    after the rollback, fresh connections see the committed intent, no receipt, no seal and every prior limit."""
    coordinator = _open(rec)
    try:
        seq = coordinator.begin("contain")
        conn = coordinator.conn
        writers = [rec.roles[k] for k in ("writer", "member", "setrole", "heldwriter")]
        with conn.cursor() as cur:
            for role in writers:
                cur.execute(f"ALTER ROLE {role} CONNECTION LIMIT 0")
            cur.execute("SELECT rolname::text, rolconnlimit FROM pg_roles WHERE rolname = ANY (%s)",
                        (writers + [rec.roles["reader"]],))
            inside = dict(cur.fetchall())
            assert inside == {**{r: 0 for r in writers}, rec.roles["reader"]: 7}, inside
            with pytest.raises(psycopg2.Error) as exc:
                cur.execute("SELECT voalack_guard.record_effect(%s, %s)", (coordinator.window_id, seq))
        conn.rollback()
        assert "the contain effect does not hold" in str(exc.value), exc.value
        assert f"contained role {rec.roles['reader']} limit 7 is not 0" in str(exc.value), exc.value
        evidence = _contain_rolled_back(rec, coordinator.window_id)
        assert f"contain intent {seq};" in evidence, evidence
    finally:
        coordinator.close()
