"""T04 S3c corrections after review 217ee214 (F1-F3) and design review 051f7b70 (R1-R7).

Native PostgreSQL waits and restores in the guest; the provider is a loopback fake (synthetic).
Astra's original probes stay unchanged in test_t04_s3c_review_probes_ea8c30a.py; these cases cover
the remaining boundaries the reviews named. Counts: logins, reads, revokes, ACK connects and writes,
provider receipts and effects.
"""
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import uuid

import psycopg2
import pytest

from test_t04_s2_sender import _effect, fake, instance  # noqa: F401
from test_t04_s3c_recovery import _net, _owner, _q, _sql_as_sender, sibling  # noqa: F401
from test_t04_s3c_restore import (_cleanup, _close_and_inventory, _contain, _contain_copied_rows, _holds,
                                  _maintenance, _recur, _reopen, _restore_and_recover, _settler_dsn,
                                  _staged_restore_and_recover, _staged_state)
from voalack import recovery, settler
from voalack.recovery import Anchor, AnchorInvalid, Supervisor
from voalack.sender import FakeOneTransport, OwnerSession, OwnerStopped


def _waiting(sib, fragment, user="lab_sender", seconds=3):
    limit = time.monotonic() + seconds
    while time.monotonic() < limit:
        if _q(sib.dsn, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename = %s "
                       "AND wait_event_type = 'Lock' AND query LIKE %s", (user, f"%{fragment}%"))[0][0] == 1:
            return True
        time.sleep(0.01)
    return False


def _close_anchor_only(sib):
    head = Anchor(sib.anchor).head()
    return Supervisor(sib.anchor).append((head.seq, head.sha256), "closed")


def _open_anchor_only(sib):
    """The anchor half of a reopen (manifest and open line) without the database's open: a crash point."""
    recovering = Anchor(sib.anchor).head()
    line = recovering.line
    adoption = _q(sib.dsn, "SELECT input_sha256 FROM voalack.recovery_adoptions WHERE epoch = %s",
                  (recovering.epoch,))[0][0]
    manifest = Supervisor(sib.anchor).write_document("adoption", recovery.canonical(
        {"v": 1, "epoch": recovering.epoch, "recovering_seq": recovering.seq, "recovering_sha256": recovering.sha256,
         "inventory_sha256": line["inventory_sha256"], "review_sha256": line["review_sha256"],
         "backup_id": line["backup_id"], "backup_sha256": line["backup_sha256"], "adoption_input_sha256": adoption}))
    return Supervisor(sib.anchor).append((recovering.seq, recovering.sha256), "open", adoption_sha256=manifest)


# --- F1 / R4: no provider operation after a native wait without the final local check ---------------

@pytest.mark.parametrize("operation", ["revoke", "apply_once"])
@pytest.mark.parametrize("close", [False, True])
def test_every_fenced_operation_rechecks_the_anchor_after_a_native_epoch_wait(client, app, instance, fake,
                                                                              sibling, operation, close):
    """[native] recovery_epoch is held FOR UPDATE while the operation's database fence waits; the
    anchor alone is closed meanwhile (the supported crash interval before the database close)."""
    effect_id = _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    owner.login()
    before = _net(owner, fake) + (owner.transport.counts["revokes"],)
    locker = psycopg2.connect(sib.dsn)
    locker.cursor().execute("SELECT 1 FROM voalack.recovery_epoch FOR UPDATE")
    result = {}

    def run():
        try:
            result["value"] = getattr(owner, operation)(*([effect_id] if operation == "apply_once" else []))
        except OwnerStopped as exc:
            result["stopped"] = str(exc)
    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert _waiting(sib, "check_owner")
        if close:
            _close_anchor_only(sib)
    finally:
        locker.commit()
        locker.close()
    worker.join(10)
    after = _net(owner, fake) + (owner.transport.counts["revokes"],)
    if close:
        assert owner.stopped == "anchor_changed" and after == before, (result, before, after)
    else:
        assert owner.stopped is None and after != before                       # positive control


def test_s3a_staged_maintenance_recovery_read_rechecks_the_anchor_after_a_native_wait(client, app, instance, fake,
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


def test_a_stopped_owner_is_never_reacquired(client, app, instance, fake, sibling):
    _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    owner.stop("lab: stopped")
    with pytest.raises(OwnerStopped):
        owner.acquire()
    assert owner.stopped == "lab: stopped"


# --- F2 / R6: an open head keeps its documents ------------------------------------------------------

def _reopened(client, app, instance, fake, sibling):
    effect_id = _effect(client, app, instance)
    sib = sibling()
    prior = _owner(sib, instance, fake)
    sha = _close_and_inventory(sib, instance, fake, [prior])
    _restore_and_recover(sib, sha)
    head = _reopen(sib, instance, fake)
    return effect_id, sib, head


@pytest.mark.parametrize("defect", ["delete_manifest", "tamper_manifest", "tamper_review", "tamper_inventory",
                                    "control"])
def test_open_head_validates_manifest_review_and_inventory(client, app, instance, fake, sibling, defect):
    effect_id, sib, head = _reopened(client, app, instance, fake, sibling)
    fresh = _owner(sib, instance, fake, owner_id="lab-fresh")
    manifest = os.path.join(sib.anchor, f"adoption-{head.line['adoption_sha256']}.json")
    if defect != "control":
        kind = defect.split("_")[1]
        name = manifest if kind == "manifest" else os.path.join(
            sib.anchor, next(n for n in sorted(os.listdir(sib.anchor)) if n.startswith(kind + "-")))
        if defect.startswith("delete"):
            os.remove(name)
        else:
            os.chmod(name, 0o644)
            with open(name, "ab") as handle:
                handle.write(b" ")
    try:
        result = fresh.apply_once(effect_id)
    except OwnerStopped as exc:
        result = {"outcome": "stopped", "reason": str(exc)}
    if defect == "control":
        assert result["outcome"] == "confirmed" and fake.counts["receipts"] == 1
        document = json.loads(open(manifest, "rb").read())
        assert (document["recovering_seq"], document["epoch"]) == (head.seq - 1, head.epoch)
        assert document["adoption_input_sha256"] == _q(
            sib.dsn, "SELECT input_sha256 FROM voalack.recovery_adoptions WHERE epoch = %s", (head.epoch,))[0][0]
    else:
        assert fresh.stopped == "anchor_changed" and fake.counts["receipts"] == 0, result
        with pytest.raises(AnchorInvalid):
            Anchor(sib.anchor).head()


def test_reopen_reruns_with_the_same_manifest_and_refuses_another(client, app, instance, fake, sibling):
    _effect_id, sib, head = _reopened(client, app, instance, fake, sibling)
    assert recovery.reopen(sib.anchor, sib.dsn, layout="voalack_only") == head                        # exact replay after a crash
    recovering = Anchor(sib.anchor).heads()[-2]
    other = Supervisor(sib.anchor).write_document("adoption", recovery.canonical(
        {"v": 1, "epoch": head.epoch, "recovering_seq": recovering.seq, "recovering_sha256": recovering.sha256,
         "inventory_sha256": recovering.line["inventory_sha256"], "review_sha256": recovering.line["review_sha256"],
         "backup_id": "none", "backup_sha256": None, "adoption_input_sha256": "f" * 64}))
    with pytest.raises(recovery.AnchorConflict):
        Supervisor(sib.anchor).append((recovering.seq, recovering.sha256), "open", adoption_sha256=other)


def test_s3a_staged_review_binds_the_dump_bytes(client, app, instance, fake, sibling, tmp_path):
    _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "snap.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    sha = _close_and_inventory(sib, instance, fake, [owner])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, sha, dump, fake=fake)
    with pytest.raises(ValueError):                                            # a label without its bytes (kept)
        recovery.write_review(sib.anchor, {"ref": "x", "backup_id": "lab-dump", "backup_sha256": None,
                                           "inventory_sha256": sha, "decision": "adopt"})


# --- F3 / R2: repeated recovery keeps every protection and its proof ---------------------------------

def test_s3a_staged_two_restores_keep_the_hold_proof_and_still_settle(client, app, instance, fake, sibling, tmp_path):
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "before.dump"
    sib.dump(dump)
    original = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    assert original.apply_once(first)["outcome"] == "uncertain"
    fake.script["ack"] = "success"
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, _close_and_inventory(sib, instance, fake, [original]), dump, fake=fake)


def test_s3a_staged_a_permanent_effect_block_survives_a_second_restore(client, app, instance, fake, sibling, tmp_path):
    """R2: recovery 1 blocks a resurrected completed effect; recovery 2 restores a snapshot without
    that block whose facts equal the inventory's; the block is carried, so the effect never sends."""
    effect_id = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "queued.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, _close_and_inventory(sib, instance, fake, [owner]), dump, fake=fake)


def test_no_restore_cycles_carry_active_holds(client, app, instance, fake, sibling):
    first = _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    assert owner.apply_once(first)["outcome"] == "uncertain"
    fake.script["ack"] = "success"
    for n in (1, 2):
        _restore_and_recover(sib, _close_and_inventory(sib, instance, fake, [owner]))
        _reopen(sib, instance, fake)
        owner = _owner(sib, instance, fake, owner_id=f"lab-cycle-{n}")
    active = [h for h in _holds(sib, instance) if h[1] == "active"]
    assert active and all(h[2][0]["state"] == "uncertain" for h in active)
    assert active[-1][3][0]["quiescence"] is not None and active[-1][3][0]["cleanup"] is not None


# --- R1: closed-phase cleanup covers sessions never registered -----------------------------------------

def test_s3a_staged_a_late_login_after_the_close_is_covered_only_by_the_credential_cleanup(client, app, instance, fake,
                                                                                 sibling, tmp_path):
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "before.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    assert owner.apply_once(first)["outcome"] == "uncertain"
    fake.script["ack"] = "success"
    owner.revoke()
    fake.script["login_delay"] = 1.0
    result = {}

    def late_login():
        try:
            owner.login()
        except OwnerStopped as exc:
            result["stopped"] = str(exc)
    worker = threading.Thread(target=late_login)
    worker.start()
    time.sleep(0.3)                                                             # the login request is pending
    recovery.close(sib.anchor, sib.dsn)
    worker.join(10)
    fake.script["login_delay"] = 0.0
    assert result["stopped"] == "session_unregistered"                         # never registered, never used
    unregistered = [t for t, c in fake.issued.items() if t in fake.sessions]
    assert len(unregistered) == 1                                              # live at the provider
    _contain(sib, instance, owner, fake)                                        # registered sessions only
    assert [t for t in unregistered if t in fake.sessions]                      # still live after that
    credential = _q(sib.dsn, "SELECT credential_ref FROM voalack.instance_config WHERE instance_id = %s",
                    (instance,))[0][0]
    stale = {"revoke": {"status": 200, "credential": credential, "observed_at": "2026-10-06T00:00:00+00:00"},
             "executing": {"status": 200, "scope": "credential", "credential": credential, "live": 1, "executing": 0,
                           "observed_at": "2026-10-06T00:00:01+00:00"}, "basis": "lab"}
    with pytest.raises(psycopg2.errors.RaiseException, match="no live or executing"):
        _q(sib.dsn, "SELECT voalack.record_recovery_cleanup(%s, %s, %s::jsonb)", (instance, credential, json.dumps(stale)))
    _cleanup(sib, instance, fake)
    assert not [t for t in unregistered if t in fake.sessions]                  # revoked by the cleanup
    _contain_copied_rows(sib, instance)
    head = recovery.inventory(sib.anchor, sib.dsn)
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, head.line["inventory_sha256"], dump, fake=fake)


def test_s3a_staged_hold_release_refuses_without_the_credential_cleanup(client, app, instance, fake, sibling, tmp_path):
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "before.dump"
    sib.dump(dump)
    owner = _owner(sib, instance, fake)
    fake.script["ack"] = "close_before_body"
    owner.apply_once(first)
    fake.script["ack"] = "success"
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, _close_and_inventory(sib, instance, fake, [owner], cleanup=False), dump, fake=fake)


# --- R3: only exactly covered guards are released; containment is not invented ------------------------

def test_s3a_staged_settlement_keeps_a_guard_whose_attempt_no_longer_matches(client, app, instance, fake, sibling, tmp_path):
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "started.dump"
    owner = _owner(sib, instance, fake, hooks={"after_start": lambda _: sib.dump(dump)})
    fake.script["ack"] = "close_before_body"
    sent = owner.apply_once(first)
    fake.script["ack"] = "success"
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, _close_and_inventory(sib, instance, fake, [owner]), dump, fake=fake)


def test_s3a_staged_settlement_releases_an_exactly_matching_restored_guard(client, app, instance, fake, sibling, tmp_path):
    """Positive control for F4/R3: the restored guard's attempt carries every frozen identity of the
    member; settlement releases that guard and makes its effect BLOCKED (neutral, never QUEUED)."""
    first = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "started.dump"
    owner = _owner(sib, instance, fake, hooks={"after_start": lambda _: sib.dump(dump)})
    fake.script["ack"] = "close_before_body"
    sent = owner.apply_once(first)
    fake.script["ack"] = "success"
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, _close_and_inventory(sib, instance, fake, [owner]), dump, fake=fake)


def test_s3a_staged_adoption_records_unknown_containment_for_uncovered_restored_owners(client, app, instance, fake, sibling,
                                                                            tmp_path):
    _effect(client, app, instance)
    sib = sibling()
    restored_owner = _owner(sib, instance, fake)
    dump = tmp_path / "with-owner.dump"
    sib.dump(dump)
    restored_owner.stop("lab")
    _q(sib.dsn, "SELECT voalack.record_containment(%s, %s, %s::jsonb)",
       (instance, restored_owner.generation, json.dumps({"process_stopped": True, "no_requests_executing": True,
                                                         "basis": "lab"})), fetch=False)
    later = _owner(sib, instance, fake, owner_id="lab-later")
    sha = _close_and_inventory(sib, instance, fake, [later])
    recovery.restore_permitted(sib.anchor, sha)
    sib.restore(dump)
    _q(sib.dsn, "ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC", fetch=False)
    # [native] conflicting lineage: a restored active owner identity the inventory never saw.
    stranger = str(uuid.uuid4())
    _q(sib.dsn, "UPDATE voalack.session_owners SET incarnation = %s WHERE instance_id = %s", (stranger, instance),
       fetch=False)
    digest = hashlib.sha256(dump.read_bytes()).hexdigest()
    review = recovery.write_review(sib.anchor, {"ref": "lab review", "backup_id": "lab-dump", "backup_sha256": digest,
                                                "inventory_sha256": sha, "decision": "adopt"})
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    before = _staged_state(sib, fake)
    with pytest.raises(recovery.AnchorConflict, match="recovery from a restored backup is staged"):
        recovery.recover(sib.anchor, sib.dsn, review, layout="voalack_only")
    assert recovery.Anchor(sib.anchor).head().phase == "inventoried"
    assert _staged_state(sib, fake) == before


# --- R4: an older permit under recovery protection never sends ------------------------------------------

def test_an_older_permit_under_recovery_protection_is_held_at_consume(client, app, instance, fake, sibling):
    effect_id = _effect(client, app, instance)
    sib = sibling()
    key = _q(sib.dsn, "SELECT effect_key, action_id::text FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0]

    def protect(_):
        # T04 S4 (disclosed fixture amendment): lab DML on an event source pins the epoch row first
        _q(sib.dsn, "SELECT voalack._pin_epoch(); "
                    "INSERT INTO voalack.recovered_effects (effect_key, action_id, adoption_id) VALUES (%s, %s, 0)",
           key, fetch=False)
    owner = _owner(sib, instance, fake, hooks={"after_preflight": protect})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("refused", "held:recovered")
    assert _q(sib.dsn, "SELECT state, permit_state FROM voalack.attempts WHERE attempt_id = %s",
              (result["attempt_id"],)) == [("uncertain", "revoked")]
    assert (owner.transport.phase_counts["ack_connects"], fake.counts["receipts"]) == (0, 0)
    owner.login()
    assert owner.stopped is None                                                # legitimate journal progress


# --- R5: the journal's partial order --------------------------------------------------------------------

@pytest.mark.parametrize("regression", ["terminal_effect", "guard_without_settlement", "other_guard"])
def test_journal_refuses_terminal_and_disposition_regressions(client, app, instance, fake, sibling, regression):
    first = _effect(client, app, instance, occurrence_ref="lab-occ-j-a")
    second = _effect(client, app, instance, occurrence_ref="lab-occ-j-b")
    sib = sibling()
    owner = _owner(sib, instance, fake)
    if regression == "terminal_effect":
        attempt = owner.apply_once(first)["attempt_id"]
        # T04 S4 (disclosed fixture amendment): lab DML on an effect's state pins the epoch row first
        statement = "SELECT voalack._pin_epoch(); UPDATE voalack.effects SET state = 'QUEUED' WHERE effect_id = %s"
        args = (first,)
    elif regression == "guard_without_settlement":
        fake.script["ack"] = "close_after_body"
        attempt = owner.apply_once(first)["attempt_id"]
        fake.script["ack"] = "success"
        statement = "DELETE FROM voalack.target_guards WHERE attempt_id = %s"
        args = (attempt,)
    else:
        fake.script["ack"] = "close_after_body"
        attempt = owner.apply_once(first)["attempt_id"]
        fake.script["ack"] = "success"
        statement = ("UPDATE voalack.target_guards SET attempt_id = (SELECT a.attempt_id FROM voalack.attempts a "
                     "WHERE a.effect_id = %s LIMIT 1) WHERE attempt_id = %s")
        _q(sib.dsn, "INSERT INTO voalack.attempts (attempt_id, effect_id, action_id, instance_id, credential_ref, "
                    "provider_contract, config_revision, owner_generation, incarnation, target_kind, target_id, "
                    "request_bytes, request_sha256, permit_state, state) SELECT gen_random_uuid(), e.effect_id, "
                    "e.action_id, a.instance_id, a.credential_ref, a.provider_contract, a.config_revision, 1, "
                    "gen_random_uuid(), a.target_kind, a.target_id, 'x'::bytea, encode(sha256('x'::bytea), 'hex'), "
                    "'unconsumed', 'started' FROM voalack.effects e, voalack.attempts a WHERE e.effect_id = %s "
                    "AND a.attempt_id = %s", (second, attempt), fetch=False)
        args = (second, attempt)
    owner.login()
    assert owner.stopped is None                                                # legitimate progress first
    _q(sib.dsn, statement, args, fetch=False)                                   # [native] admin regression
    with pytest.raises(OwnerStopped, match="journal_regression"):
        owner.login()


def test_journal_freezes_an_aborted_consume_and_refuses_its_regression(client, app, instance, fake, sibling):
    """An aborted consume (eligibility lost after the preflight) freezes a revoked permit and keeps the
    owner running; the same attempt shown started again stops it."""
    effect_id = _effect(client, app, instance)
    sib = sibling()

    def revoke_policy(_):
        _q(sib.dsn, "UPDATE voalack.authorization_policy_active SET policy_revision = 999", fetch=False)
    owner = _owner(sib, instance, fake, hooks={"after_preflight": revoke_policy})
    result = owner.apply_once(effect_id)
    assert result["reason"] == "aborted:policy_revoked"
    assert owner.journal[result["attempt_id"]]["progress"] == "aborted"
    assert _q(sib.dsn, "SELECT state, permit_state FROM voalack.attempts WHERE attempt_id = %s",
              (result["attempt_id"],)) == [("aborted_before_dispatch", "revoked")]
    owner.login()
    assert owner.stopped is None                                                # legitimate progress
    _q(sib.dsn, "UPDATE voalack.attempts SET state = 'started', permit_state = 'unconsumed', settled_at = NULL "
                "WHERE attempt_id = %s", (result["attempt_id"],), fetch=False)  # [native] admin regression
    with pytest.raises(OwnerStopped, match="journal_regression"):
        owner.login()


# --- R7: a real unprivileged worker; genuine upgrade rollback ------------------------------------------

def test_an_unprivileged_worker_delivers_but_cannot_write_the_anchor(client, app, instance, fake, sibling):
    effect_id = _effect(client, app, instance)
    sib = sibling()
    base = tempfile.mkdtemp(prefix="voalack-anchor-worker-", dir="/tmp")
    os.chmod(base, 0o755)
    anchor_dir = os.path.join(base, "anchor")
    shutil.copytree(sib.anchor, anchor_dir)
    os.chmod(anchor_dir, 0o755)
    for name in os.listdir(anchor_dir):
        os.chmod(os.path.join(anchor_dir, name), 0o444 if name != recovery.LOCK else 0o600)
    pid = os.fork()
    if pid == 0:                                                                # [file] a worker as uid nobody
        code = 1
        try:
            os.setgid(65534)
            os.setuid(65534)
            owner = OwnerSession(sib.sender, instance, "lab-nobody", FakeOneTransport(fake.url),
                                 anchor=Anchor(anchor_dir))
            owner.acquire()
            delivered = owner.apply_once(effect_id)["outcome"] == "confirmed"
            try:
                head = Anchor(anchor_dir).head()
                Supervisor(anchor_dir).append((head.seq, head.sha256), "closed")
            except PermissionError:
                code = 0 if delivered else 3
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert Anchor(anchor_dir).head().seq == 1 and fake.counts["receipts"] == 1
    shutil.rmtree(base)
