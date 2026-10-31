"""T04 S3c: the external recovery anchor, the epoch gate, the close barrier and the live journal
(spec r1, milestone M1; design response 1dae56ab C2, C3, C6, C7).

Native PostgreSQL in the guest; the provider is a loopback fake (synthetic). Witnesses that close
the anchor or restore a database run against a sibling database (a copy of the lab database's
Voalack schema made with pg_dump/pg_restore) with its own anchor directory; the session's lab
database and anchor stay open. Labels: [native] real PostgreSQL transactions, roles and restores;
[fake] fake-provider behaviour; [file] the anchor directory. Every delivery case counts adapter
dispatch entries, ACK connects and writes, provider receipts and effects, logins and reads.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from typing import NamedTuple

import psycopg2
import psycopg2.extras
import pytest

from conftest import DSN, LAB_ANCHOR_DIR, sql
from test_t04_s2_sender import _effect, fake, instance  # noqa: F401
from voalack import recovery, schema, sender, settler, verifier
from voalack.recovery import Anchor, AnchorConflict, AnchorInvalid, Supervisor
from voalack.sender import FakeOneTransport, OwnerSession

SENDER_LOGIN = "lab_sender:lab-only-sender"
SETTLER_LOGIN = "lab_settler:lab-only-settler"
S3B_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "schema_s3b_35ab5c7.sql")


def _dsn(name, login=None):
    dsn = DSN.rsplit("/", 1)[0] + "/" + name
    return dsn.replace("lab_admin:lab-only-admin", login) if login else dsn


def _admin(statement):
    conn = psycopg2.connect(DSN)
    conn.autocommit = True
    try:
        conn.cursor().execute(statement)
    finally:
        conn.close()


def _run(args):
    done = subprocess.run(args, capture_output=True, text=True)
    assert done.returncode == 0, (args[0], done.returncode, done.stderr[-2000:])
    return done


def _q(dsn, statement, args=(), fetch=True):
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(statement, args)
        return cur.fetchall() if fetch else None


class Sibling(NamedTuple):
    name: str
    dsn: str          # lab administrator
    sender: str       # lab_sender login
    anchor: str       # its own anchor directory

    def dump(self, path):
        _run(["pg_dump", "-Fc", "-n", "voalack", "-f", str(path), self.dsn])

    def restore(self, path):
        """[native] database-only restore of the Voalack schema (drops and recreates its objects)."""
        _run(["pg_restore", "--clean", "--if-exists", "-d", self.dsn, str(path)])

    def phase(self):
        return _q(self.dsn, "SELECT epoch, phase, head_seq, head_sha256 FROM voalack.recovery_epoch")


@pytest.fixture
def sibling(app, tmp_path):
    """Factory: a copy of the lab database's Voalack schema in a new database, with a copy of the lab
    anchor (the same genesis the copied recovery_epoch row names)."""
    made = []

    def make():
        name = f"voalack_s3c_{uuid.uuid4().hex[:8]}"
        dump = tmp_path / f"{name}-base.dump"
        # T04 S4 (disclosed fixture amendment): the base copy also holds the protected publication schema,
        # which the supported restore (Sibling.restore, -n voalack only) leaves untouched.
        _run(["pg_dump", "-Fc", "-n", "voalack", "-n", "voalack_publication", "-f", str(dump), DSN])
        _admin(f"CREATE DATABASE {name}")
        made.append(name)
        dsn = _dsn(name)
        _run(["pg_restore", "-d", dsn, str(dump)])
        # Default privileges are per database: the same global revoke as the lab installation.
        _q(dsn, "ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC", fetch=False)
        anchor_dir = tmp_path / f"{name}-anchor"
        shutil.copytree(LAB_ANCHOR_DIR, anchor_dir)
        return Sibling(name, dsn, _dsn(name, SENDER_LOGIN), str(anchor_dir))
    yield make
    for name in made:
        _admin(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


def _owner(sib, instance, provider, **kwargs):
    owner = OwnerSession(sib.sender, instance, kwargs.pop("owner_id", "lab-s3c-owner"),
                         FakeOneTransport(provider.url), anchor=Anchor(sib.anchor), **kwargs)
    owner.acquire()
    return owner


def _net(owner, provider):
    """(dispatch entries, ACK connects, ACK writes, receipts, effects, logins, reads)."""
    return (owner.counts["dispatch_entries"], owner.transport.phase_counts["ack_connects"],
            owner.transport.counts["ack_writes"], provider.counts["receipts"], provider.counts["effects"],
            owner.transport.counts["logins"], owner.transport.counts["reads"])


def _sql_as_sender(sib, statement, args):
    with psycopg2.connect(sib.sender) as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(statement, args)
        return cur.fetchone()


CAPTURED = "2026-10-06T00:00:00+00:00"


def _lab_inventory(closed, captured=CAPTURED):
    """[file] A schema-valid (synthetic, empty) inventory bound to a closed line."""
    lists = ("attempts", "cleanups", "containment", "effects", "guards", "owners", "provider_sessions",
             "quiescence", "recovered_effects", "recovered_holds", "settlements")
    return json.dumps({"format": "voalack-inventory/2", "epoch": closed.epoch, "head_seq": closed.seq,
                       "head_sha256": closed.sha256, "captured_at": captured, "recovery_history": {},
                       **{k: [] for k in lists}}).encode()


def _chain(directory):
    """[file] A valid five-line chain through every phase with its linked documents (supervisor writes only)."""
    sup = Supervisor(directory)
    genesis = sup.append(None, "open", bootstrap=True)
    closed = sup.append((genesis.seq, genesis.sha256), "closed")
    inv = sup.write_document("inventory", _lab_inventory(closed))
    inventoried = sup.append((closed.seq, closed.sha256), "inventoried", inventory_sha256=inv,
                             inventory_file=f"inventory-{inv}.json", captured_at=CAPTURED)
    review = recovery.write_review(directory, {"ref": "lab review", "backup_id": "lab-backup",
                                               "backup_sha256": "d" * 64, "inventory_sha256": inv, "decision": "adopt"})
    recovering = sup.append((inventoried.seq, inventoried.sha256), "recovering", inventory_sha256=inv,
                            backup_id="lab-backup", backup_sha256="d" * 64, review_sha256=review,
                            review_ref="lab review")
    manifest = sup.write_document("adoption", recovery.canonical(
        {"v": 1, "epoch": 2, "recovering_seq": recovering.seq, "recovering_sha256": recovering.sha256,
         "inventory_sha256": inv, "review_sha256": review, "backup_id": "lab-backup", "backup_sha256": "d" * 64,
         "adoption_input_sha256": "a" * 64}))
    reopened = sup.append((recovering.seq, recovering.sha256), "open", adoption_sha256=manifest)
    return [genesis, closed, inventoried, recovering, reopened]


# --- the anchor: reader fails closed, writer is exact --------------------------------------------

def test_anchor_chain_through_every_phase_and_exact_writer(tmp_path):
    heads = _chain(str(tmp_path))
    assert [(h.seq, h.epoch, h.phase) for h in heads] == [(1, 1, "open"), (2, 1, "closed"), (3, 1, "inventoried"),
                                                          (4, 2, "recovering"), (5, 2, "open")]
    assert Anchor(str(tmp_path)).head() == heads[-1]
    data = (tmp_path / recovery.LOG).read_bytes()
    assert all(recovery.canonical(json.loads(line)) == line for line in data.splitlines())
    assert oct(os.stat(tmp_path / recovery.LOG).st_mode & 0o777) == "0o444"           # [file] read-only bytes
    sup = Supervisor(str(tmp_path))
    with pytest.raises(AnchorConflict):                                                 # stale expected head
        sup.append((heads[3].seq, heads[3].sha256), "closed")
    duplicate = sup.append((heads[3].seq, heads[3].sha256), "open", adoption_sha256=heads[-1].line["adoption_sha256"])
    assert duplicate == heads[-1] and (tmp_path / recovery.LOG).read_bytes() == data   # exact duplicate only
    with pytest.raises(AnchorConflict):
        sup.append((heads[3].seq, heads[3].sha256), "open", adoption_sha256="b" * 64)  # conflicting replay
    with pytest.raises(AnchorInvalid):
        sup.append((heads[-1].seq, heads[-1].sha256), "inventoried", inventory_sha256="c" * 64,
                   inventory_file="inventory-" + "c" * 64 + ".json", captured_at="x")   # open -> inventoried
    with pytest.raises(AnchorConflict):
        sup.append(None, "open", bootstrap=True)                                        # second genesis
    assert (tmp_path / recovery.LOG).read_bytes() == data


def _rewrite(directory, transform):
    path = os.path.join(directory, recovery.LOG)
    os.chmod(path, 0o644)
    with open(path, "rb") as handle:
        data = handle.read()
    with open(path, "wb") as handle:
        handle.write(transform(data))


def _relink(lines):
    """Re-chain edited lines (so only the intended defect remains)."""
    out, prev = [], None
    for line in lines:
        if prev is not None and "prev" in line:
            line["prev"] = prev
        raw = recovery.canonical(line)
        prev = hashlib.sha256(raw).hexdigest()
        out.append(raw)
    return b"\n".join(out) + b"\n"


def _broken_chain(data):
    lines = [json.loads(raw) for raw in data.splitlines()]
    lines[2]["prev"] = "0" * 64                                     # no re-linking: the chain itself breaks
    return b"\n".join(recovery.canonical(line) for line in lines) + b"\n"


def _skip_close(data):
    """Genesis followed directly by an inventoried line (re-numbered and re-linked)."""
    lines = [json.loads(raw) for raw in data.splitlines()][:3]
    del lines[1]
    lines[1]["seq"] = 2
    return _relink(lines)


def _edit_line(index, edit):
    def transform(data):
        lines = [json.loads(raw) for raw in data.splitlines()]
        edit(lines[index])
        return _relink(lines)
    return transform


CORRUPTIONS = {
    "extra_field": _edit_line(1, lambda line: line.update(note="x")),
    "missing_field": _edit_line(1, lambda line: line.pop("at")),
    "unknown_phase": _edit_line(1, lambda line: line.update(phase="paused")),
    "bootstrap_phase_later": _edit_line(1, lambda line: line.update(phase="bootstrap")),
    "seq_gap": _edit_line(1, lambda line: line.update(seq=3)),
    "epoch_jump_at_close": _edit_line(1, lambda line: line.update(epoch=2)),
    "bool_version": _edit_line(1, lambda line: line.update(v=True)),
    "transition_not_allowed": _skip_close,
    "recovery_other_inventory": _edit_line(3, lambda line: line.update(inventory_sha256="d" * 64)),
    "bad_adoption_digest": _edit_line(4, lambda line: line.update(adoption_sha256="XYZ")),
    "broken_chain": _broken_chain,
    "non_canonical": lambda data: data.replace(b'"phase":"closed"', b'"phase": "closed"', 1),
    "duplicate_key": lambda data: data.replace(b'"phase":"closed"', b'"phase":"closed","phase":"closed"', 1),
    "no_final_newline": lambda data: data[:-1],
    "empty": lambda data: b"",
    "oversized": lambda data: data + b" " * recovery.MAX_BYTES,
    "too_many_lines": lambda data: b"{}\n" * (recovery.MAX_LINES + 1),
    "binary": lambda data: b"\xff\xfe\n",
}


@pytest.mark.parametrize("defect", sorted(CORRUPTIONS))
def test_anchor_reader_fails_closed(tmp_path, defect):
    _chain(str(tmp_path))
    _rewrite(str(tmp_path), CORRUPTIONS[defect])
    with pytest.raises(AnchorInvalid):                                                  # never a valid prefix
        Anchor(str(tmp_path)).head()


def test_anchor_reader_fails_closed_on_missing_files_and_links(tmp_path):
    heads = _chain(str(tmp_path / "a"))
    os.remove(tmp_path / "a" / recovery.LOG)
    with pytest.raises(AnchorInvalid):                                                  # no anchor at all
        Anchor(str(tmp_path / "a")).head()
    _chain(str(tmp_path / "b"))
    target = tmp_path / "b" / recovery.LOG
    os.rename(target, tmp_path / "b" / "real.log")
    os.symlink(tmp_path / "b" / "real.log", target)
    with pytest.raises(AnchorInvalid):                                                  # O_NOFOLLOW
        Anchor(str(tmp_path / "b")).head()
    # A head that names an inventory or review document requires the exact bytes.
    sup = Supervisor(str(tmp_path / "c"))
    g = sup.append(None, "open", bootstrap=True)
    c = sup.append((g.seq, g.sha256), "closed")
    inv = sup.write_document("inventory", _lab_inventory(c))
    sup.append((c.seq, c.sha256), "inventoried", inventory_sha256=inv, inventory_file=f"inventory-{inv}.json",
               captured_at=CAPTURED)
    doc = tmp_path / "c" / f"inventory-{inv}.json"
    os.chmod(doc, 0o644)
    doc.write_bytes(_lab_inventory(c, captured="2026-10-06T00:00:01+00:00"))
    with pytest.raises(AnchorInvalid):
        Anchor(str(tmp_path / "c")).head()
    os.remove(doc)
    with pytest.raises(AnchorInvalid):
        Anchor(str(tmp_path / "c")).head()
    assert heads[0].phase == "open"


def test_worker_has_read_only_access_to_the_anchor():
    base = tempfile.mkdtemp(prefix="voalack-anchor-uid-", dir="/tmp")
    os.chmod(base, 0o755)
    directory = os.path.join(base, "anchor")
    Supervisor(directory).append(None, "open", bootstrap=True)
    pid = os.fork()
    if pid == 0:                                                                        # [file] as uid nobody
        code = 1
        try:
            os.setgid(65534)
            os.setuid(65534)
            head = Anchor(directory).head()
            try:
                open(os.path.join(directory, recovery.LOG), "ab").close()
            except PermissionError:
                try:
                    Supervisor(directory).append((head.seq, head.sha256), "closed")
                except PermissionError:
                    code = 0 if head.phase == "open" else 3
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert Anchor(directory).head().seq == 1
    shutil.rmtree(base)


# --- acquisition at the exact head --------------------------------------------------------------

def test_acquisition_requires_the_exact_open_head(client, app, instance, fake, sibling, tmp_path):
    _effect(client, app, instance)
    sib = sibling()
    other = str(tmp_path / "other-anchor")
    Supervisor(other).append(None, "open", bootstrap=True)                              # another genesis
    with pytest.raises(psycopg2.errors.RaiseException, match="anchor head does not match"):
        OwnerSession(sib.sender, instance, "lab-wrong", FakeOneTransport(fake.url), anchor=Anchor(other)).acquire()
    head = Anchor(sib.anchor).head()
    args = (instance, "lab-direct", str(uuid.uuid4()), head.epoch, head.seq, head.sha256)
    with pytest.raises(psycopg2.errors.RaiseException, match="anchor head does not match"):
        _sql_as_sender(sib, "SELECT voalack.acquire_owner(%s, %s, %s, %s, %s, %s, 'maintenance')", args)
    with pytest.raises(psycopg2.errors.RaiseException, match="unknown owner mode"):
        _sql_as_sender(sib, "SELECT voalack.acquire_owner(%s, %s, %s, %s, %s, %s, 'other')", args)
    with pytest.raises(psycopg2.errors.RaiseException, match="anchor head does not match"):
        _sql_as_sender(sib, "SELECT voalack.acquire_owner(%s, %s, %s, %s, %s, %s, 'ordinary')",
                       args[:3] + (head.epoch + 1, head.seq, head.sha256))
    assert _q(sib.dsn, "SELECT to_regprocedure('voalack.acquire_owner(text, text, uuid)')")[0][0] is None
    _q(sib.dsn, "DELETE FROM voalack.recovery_epoch", fetch=False)                       # [native] no row
    with pytest.raises(psycopg2.errors.RaiseException, match="not initialized"):
        _owner(sib, instance, fake)
    _q(sib.dsn, "SELECT voalack.initialize_recovery(%s, %s::jsonb)", (head.sha256, json.dumps({"basis": "lab"})),
       fetch=False)
    owner = _owner(sib, instance, fake)                                                 # positive control
    assert owner.head == (head.seq, head.sha256)
    assert _q(sib.dsn, "SELECT acquired_epoch, acquired_head_sha256, mode FROM voalack.session_owners "
                       "WHERE instance_id = %s", (instance,)) == [(1, head.sha256, "ordinary")]


def test_initialization_is_explicit_single_and_replay_exact(app, sibling, tmp_path):
    sib = sibling()
    head = Anchor(sib.anchor).head()
    assert _q(sib.dsn, "SELECT voalack.initialize_recovery(%s, %s::jsonb)",
              (head.sha256, json.dumps({"basis": "lab"})))[0][0] == "already_initialized"
    with pytest.raises(psycopg2.errors.RaiseException, match="already initialized"):
        _q(sib.dsn, "SELECT voalack.initialize_recovery(%s, %s::jsonb)", ("e" * 64, json.dumps({"basis": "lab"})))
    _q(sib.dsn, "DELETE FROM voalack.recovery_epoch", fetch=False)
    for bad in ({"no": "basis"}, None):
        with pytest.raises(psycopg2.errors.RaiseException, match="genesis line digest"):
            _q(sib.dsn, "SELECT voalack.initialize_recovery(%s, %s::jsonb)",
               (head.sha256, json.dumps(bad) if bad else None))
    fresh = str(tmp_path / "fresh-anchor")
    new = recovery.bootstrap(fresh, sib.dsn, {"basis": "lab bootstrap"})
    assert sib.phase() == [(1, "open", 1, new.sha256)]
    assert recovery.bootstrap(fresh, sib.dsn, {"basis": "lab bootstrap"}) == new         # exact replay
    with pytest.raises(psycopg2.errors.RaiseException, match="already initialized"):     # another genesis
        recovery.bootstrap(str(tmp_path / "other-anchor"), sib.dsn, {"basis": "lab bootstrap"})
    assert sib.phase() == [(1, "open", 1, new.sha256)]


# --- the close barrier and the SQL gate -----------------------------------------------------------

def test_close_stops_the_owner_and_every_sql_gate(client, app, instance, fake, sibling):
    effect_id = _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    owner.login()
    closed = recovery.close(sib.anchor, sib.dsn)
    assert (closed.seq, closed.phase) == (2, "closed") and sib.phase() == [(1, "closed", 2, closed.sha256)]
    before = _net(owner, fake)
    # Both halves are closed: the database fence refuses first (F1 order: database, then anchor last).
    with pytest.raises(sender.OwnerStopped, match="epoch_changed"):                      # refused at the first fence
        owner.apply_once(effect_id)
    assert owner.stopped == "epoch_changed" and _net(owner, fake) == before            # no provider operation
    ids = (instance, owner.generation, owner.incarnation)
    assert _sql_as_sender(sib, "SELECT voalack.check_owner(%s, %s, %s) AS s", ids)["s"] in ("epoch_changed", "suspended")
    attempt = str(uuid.uuid4())
    started = _sql_as_sender(sib, "SELECT * FROM voalack.start_attempt(%s, %s, %s, %s, %s)", (attempt, effect_id) + ids)
    assert started["outcome"] == "owner_fenced"                                         # [native] the SQL gate
    assert _sql_as_sender(sib, "SELECT voalack.register_session(%s, %s, %s, %s) AS o",
                          ("f" * 64,) + ids)["o"] in ("epoch_changed", "owner_fenced")
    with pytest.raises(AnchorInvalid, match="closed"):
        _owner(sib, instance, fake, owner_id="lab-fresh")                                # closed: no acquisition
    assert recovery.close(sib.anchor, sib.dsn) == closed                                 # idempotent re-run
    assert _q(sib.dsn, "SELECT voalack.close_recovery(%s, %s, %s)", (1, 2, closed.sha256))[0][0] == "already_closed"
    assert sql("SELECT phase FROM voalack.recovery_epoch")[0][0] == "open"               # the lab database is untouched


def test_check_owner_reports_epoch_changed_distinctly(client, app, instance, fake, sibling):
    _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake)
    ids = (instance, owner.generation, owner.incarnation)
    head = Anchor(sib.anchor).head()
    _q(sib.dsn, "SELECT voalack.close_recovery(1, 2, %s)", ("c" * 64,), fetch=False)    # database only
    assert _sql_as_sender(sib, "SELECT voalack.check_owner(%s, %s, %s) AS s", ids)["s"] == "epoch_changed"
    with pytest.raises(sender.OwnerStopped, match="epoch_changed"):                       # the anchor is still open
        owner.login()
    assert owner.stopped == "epoch_changed" and owner.transport.counts["logins"] == 0
    assert Anchor(sib.anchor).head() == head


RACE_POINTS = {
    # point: (hook, expected outcome, reason, ACK connects). The close is complete (anchor and database),
    # so the database checks, which run before the final anchor check (F1), refuse first.
    "after_start": ("after_start", "held", "epoch_changed", 0),             # before login and preflight
    "after_preflight": ("after_preflight", "refused", "aborted:owner_fenced", 0),   # consume refused by SQL
    "before_send": ("before_send", "held", "owner_fenced", 0),              # final authority after consume
    "after_connect": ("after_connect", "held", "owner_fenced", 1),          # connected, nothing written
}


@pytest.mark.parametrize("point", sorted(RACE_POINTS))
def test_close_racing_a_worker_that_checked_open(client, app, instance, fake, sibling, point):
    hook, outcome, reason, connects = RACE_POINTS[point]
    effect_id = _effect(client, app, instance)
    sib = sibling()
    closes = []

    def close_now(*_):
        if not closes:
            closes.append(recovery.close(sib.anchor, sib.dsn))
    owner = _owner(sib, instance, fake, hooks={hook: close_now}, handoff_bound=5.0)
    owner.login()
    before = owner.transport.counts["logins"]
    result = owner.apply_once(effect_id)
    assert closes and (result["outcome"], result["reason"]) == (outcome, reason), result
    assert owner.transport.phase_counts["ack_connects"] == connects
    assert (owner.transport.counts["ack_writes"], fake.counts["receipts"], fake.counts["effects"]) == (0, 0, 0)
    assert owner.transport.counts["logins"] == before
    with pytest.raises(sender.OwnerStopped, match="epoch_changed|fenced"):              # latched or fenced at once
        owner.apply_once(effect_id)
    assert fake.counts["receipts"] == 0


def test_sql_gate_alone_refuses_after_a_database_close(client, app, instance, fake, sibling):
    """The anchor still reads open (the worker's check passes); the database phase alone refuses."""
    effect_id = _effect(client, app, instance)
    sib = sibling()
    owner = _owner(sib, instance, fake, handoff_bound=5.0, hooks={
        "before_send": lambda _: _q(sib.dsn, "SELECT voalack.close_recovery(1, 2, %s)", ("c" * 64,), fetch=False)})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "owner_fenced")
    assert (owner.transport.counts["ack_writes"], fake.counts["receipts"]) == (0, 0)
    assert _q(sib.dsn, "SELECT state, permit_state FROM voalack.attempts WHERE attempt_id = %s",
              (result["attempt_id"],)) == [("uncertain", "consumed")]                     # held, never released


def test_anchor_close_alone_stops_before_the_write(client, app, instance, fake, sibling):
    """A crash after the anchor line and before the database close: the database still admits the
    consume; the worker's anchor check refuses the send."""
    effect_id = _effect(client, app, instance)
    sib = sibling()
    genesis = Anchor(sib.anchor).head()
    owner = _owner(sib, instance, fake, hooks={
        "after_preflight": lambda _: Supervisor(sib.anchor).append((genesis.seq, genesis.sha256), "closed")})
    result = owner.apply_once(effect_id)
    assert (result["outcome"], result["reason"]) == ("held", "anchor_changed")
    assert (owner.transport.counts["ack_writes"], fake.counts["receipts"]) == (0, 0)
    assert sib.phase()[0][1] == "open"
    closed = recovery.close(sib.anchor, sib.dsn)                                         # re-run completes it
    assert sib.phase() == [(1, "closed", 2, closed.sha256)]


@pytest.mark.parametrize("point", ["write:anchor.log", "rename:anchor.log"])
def test_failed_close_publication_changes_nothing(client, app, instance, fake, sibling, point):
    effect_id = _effect(client, app, instance)
    sib = sibling()
    genesis = Anchor(sib.anchor).head()

    def fail(at):
        if at == point:
            raise OSError(f"lab: {at} failed")
    with pytest.raises(OSError, match="lab:"):
        recovery.close(sib.anchor, sib.dsn, supervisor=Supervisor(sib.anchor, fault=fail))
    assert Anchor(sib.anchor).head() == genesis and sib.phase()[0][1] == "open"          # nothing else ran
    owner = _owner(sib, instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"                         # positive control
    assert fake.counts["receipts"] == 1


# --- the live journal (C6) ------------------------------------------------------------------------

@pytest.mark.parametrize("snapshot", ["before_attempt", "started"])
def test_journal_stops_the_owner_after_an_unannounced_restore(client, app, instance, fake, sibling, tmp_path,
                                                              snapshot):
    """[native] pg_restore of an earlier dump under a live owner, with the anchor unchanged (an
    unannounced restore): the database again shows the effect QUEUED and the attempt missing, or the
    same attempt started with an unconsumed permit. The journal stops the owner before any provider
    operation; the database alone would allow a second send."""
    effect_id = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / "snapshot.dump"
    hooks = {"after_start": lambda _: sib.dump(dump)} if snapshot == "started" else {}
    owner = _owner(sib, instance, fake, hooks=hooks)
    if snapshot == "before_attempt":
        sib.dump(dump)
    first = owner.apply_once(effect_id)
    assert first["outcome"] == "confirmed" and fake.counts["receipts"] == 1
    sib.restore(dump)
    _q(sib.dsn, "ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC", fetch=False)
    restored = _q(sib.dsn, "SELECT state, permit_state FROM voalack.attempts WHERE attempt_id = %s",
                  (first["attempt_id"],))
    assert restored == ([] if snapshot == "before_attempt" else [("started", "unconsumed")])
    assert _q(sib.dsn, "SELECT state FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0][0] == "QUEUED"
    assert _sql_as_sender(sib, "SELECT voalack.check_owner(%s, %s, %s) AS s",
                          (instance, owner.generation, owner.incarnation))["s"] == "active"   # the database alone agrees
    before = _net(owner, fake)
    with pytest.raises(sender.OwnerStopped, match="journal_regression"):                 # the first fence
        owner.apply_once(effect_id)
    assert owner.stopped == "journal_regression" and _net(owner, fake) == before
    assert (fake.counts["receipts"], fake.counts["effects"]) == (1, 1)


def test_journal_accepts_legitimate_progress(client, app, instance, fake, sibling):
    """Positive control: known confirmed progress keeps the owner running (the S2, S3a and S3b
    suites exercise the uncertain, settled, not_sent and aborted progress under the journal)."""
    first = _effect(client, app, instance, occurrence_ref="lab-occ-j1")
    sib = sibling()
    owner = _owner(sib, instance, fake)
    assert owner.apply_once(first)["outcome"] == "confirmed"
    owner.login()
    assert owner.stopped is None and list(owner.journal.values())[0]["progress"] == "confirmed"


# --- privileges, readiness and upgrade (C7) -----------------------------------------------------------

@pytest.mark.parametrize("login", [SENDER_LOGIN, SETTLER_LOGIN, "lab_verifier:lab-only-verifier",
                                   "alerta:lab-only-synthetic"])
def test_recovery_administration_is_granted_to_no_runtime_role(app, login):
    dsn = DSN.replace("lab_admin:lab-only-admin", login)
    for statement in ("SELECT voalack.initialize_recovery(%s, '{}'::jsonb)" % ("'" + "a" * 64 + "'"),
                      "SELECT voalack.close_recovery(1, 2, '%s')" % ("a" * 64),
                      "SELECT voalack._epoch_pin(1, '%s', 'ordinary')" % ("a" * 64),
                      "UPDATE voalack.recovery_epoch SET phase = 'open'",
                      "INSERT INTO voalack.recovery_transitions (epoch, phase, head_seq, head_sha256, detail, "
                      "decided_by) VALUES (1, 'open', 1, 'x', '{}', 'x')"):
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            _q(dsn, statement)


@pytest.mark.parametrize("drift", [
    ("GRANT UPDATE ON voalack.recovery_epoch TO voalack_sender", "table_power"),
    ("GRANT EXECUTE ON FUNCTION voalack.close_recovery(bigint, integer, text) TO voalack_sender", "execute_drift"),
    ("GRANT SELECT ON voalack.recovery_transitions TO voalack_sender", "extra_read"),
])
def test_readiness_detects_recovery_privilege_drift(app, sibling, drift):
    sib = sibling()
    statement, condition = drift
    with psycopg2.connect(sib.sender) as conn:
        verifier.check_ready(conn, sender.SENDER)
    _q(sib.dsn, statement, fetch=False)
    with psycopg2.connect(sib.sender) as conn, pytest.raises(verifier.NotReady, match=condition):
        verifier.check_ready(conn, sender.SENDER)


@pytest.fixture
def s3b_db():
    name = f"voalack_s3b_{uuid.uuid4().hex[:8]}"
    _admin(f"CREATE DATABASE {name}")
    dsn = _dsn(name)
    try:
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("CREATE TYPE public.history AS (id text, event text, severity text, status text, value text, "
                        "text text, type text, update_time timestamp, \"user\" text, timeout integer); "
                        "CREATE TABLE public.alerts (id text PRIMARY KEY, customer text, status text, "
                        "history public.history[], "
                        # coexistence 3a: the columns the ownership class, lifetime and binding guard read
                        "resource text, event text, environment text, origin text, create_time timestamp)")
            cur.execute(open(S3B_SCHEMA).read())                     # the integrated 35ab5c7 installation
        yield dsn
    finally:
        _admin(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


def _seed_s3b(cur):
    """History as an S3b deployment leaves it: confirmed, uncertain, settled, not-sent (with its retry
    lineage and backoff), aborted-before-dispatch and queued effects, and owners in every state."""
    rows = {}
    for n, owner_state in enumerate(("active", "suspended", "contained", "free")):
        inst = f"up-{owner_state}"
        cur.execute("INSERT INTO voalack.instance_config VALUES (%s, %s, 'fake-one/v1', 1)", (inst, f"cred-{inst}"))
        cur.execute("INSERT INTO voalack.session_owners (instance_id, owner_generation, incarnation, owner_id, state, "
                    "bound_credential_ref, bound_config_revision, bound_provider_contract) "
                    "VALUES (%s, 1, %s, 'lab', %s, %s, 1, 'fake-one/v1')",
                    (inst, None if owner_state == "free" else str(uuid.uuid4()), owner_state, f"cred-{inst}"))
    for label, effect_state, attempt_state, permit, guard in (
            ("confirmed", "REMOTE_CONFIRMED", "confirmed", "consumed", None),
            ("uncertain", "UNCERTAIN", "uncertain", "consumed", "uncertain"),
            ("settled", "BLOCKED", "uncertain", "consumed", None),
            ("not_sent", "QUEUED", "not_sent", "consumed", None),
            ("aborted", "QUEUED", "aborted_before_dispatch", "revoked", None),
            ("queued", "QUEUED", None, None, None)):
        action = str(uuid.uuid4())
        cur.execute("INSERT INTO voalack.prepared_intents (action_id, alert_id, txid, actor_login, payload) "
                    "VALUES (%s, %s, 1, 'lab', '{}')", (action, f"alert-{label}"))
        cur.execute("INSERT INTO voalack.captures (action_id, alert_id, txid, history_user, history_time) "
                    "VALUES (%s, %s, 1, 'lab', now())", (action, f"alert-{label}"))
        cur.execute("INSERT INTO voalack.verifications (action_id, claim_epoch, verifier_version, deployment_id, "
                    "provider, outcome, reason, envelope_sha256, capture_fingerprint) VALUES (%s, 1, 'v', 'd', 'p', "
                    "'verified', 'ok', %s, %s) RETURNING verification_id", (action, "a" * 64, "b" * 64))
        verification = cur.fetchone()[0]
        cur.execute("INSERT INTO voalack.effects (effect_key, instance_id, target_id, action_id, verification_id, state) "
                    "VALUES (%s, 'up-contained', %s, %s, %s, %s) RETURNING effect_id",
                    (f"key-{label}", label, action, verification, effect_state))
        effect = cur.fetchone()[0]
        rows[label] = effect
        if attempt_state is None:
            continue
        attempt = str(uuid.uuid4())
        body = f"{label}-{attempt}".encode()
        incarnation = str(uuid.uuid4())
        cur.execute("INSERT INTO voalack.attempts (attempt_id, effect_id, action_id, instance_id, credential_ref, "
                    "provider_contract, config_revision, owner_generation, incarnation, target_kind, target_id, "
                    "request_bytes, request_sha256, permit_state, state, dispatched_at, settled_at) VALUES (%s, %s, %s, "
                    "'up-contained', 'cred-up-contained', 'fake-one/v1', 1, 1, %s, 'triggered_alarm', %s, %s, %s, %s, "
                    "%s, CASE WHEN %s THEN now() END, CASE WHEN %s THEN now() END)",
                    (attempt, effect, action, incarnation, label, psycopg2.Binary(body),
                     hashlib.sha256(body).hexdigest(), permit, attempt_state, permit == "consumed",
                     attempt_state in ("confirmed", "uncertain", "not_sent", "aborted_before_dispatch")))
        cur.execute("UPDATE voalack.effects SET attempt_count = 1 WHERE effect_id = %s", (effect,))
        if attempt_state == "not_sent":                              # retry lineage and durable backoff (S3a)
            cur.execute("UPDATE voalack.effects SET next_attempt_after = now() + interval '1 second', "
                        "retry_owner_generation = 1, retry_incarnation = %s WHERE effect_id = %s", (incarnation, effect))
        if guard:
            cur.execute("INSERT INTO voalack.target_guards VALUES ('up-contained', 'triggered_alarm', %s, %s, %s)",
                        (label, attempt, guard))
            cur.execute("UPDATE voalack.effects SET in_flight_attempt = %s WHERE effect_id = %s", (attempt, effect))
        if label == "settled":
            read = str(uuid.uuid4())
            cur.execute("INSERT INTO voalack.reconciliation_reads VALUES (%s, %s, %s, %s, %s, 'up-contained', "
                        "'triggered_alarm', %s, 1, %s, 2, %s, 'cred-up-contained', 1, 'fake-one/v1', now())",
                        (read, attempt, effect, action, hashlib.sha256(body).hexdigest(), label, incarnation,
                         str(uuid.uuid4())))
            cur.execute("INSERT INTO voalack.reconciliations (read_id, attempt_id, effect_id, action_id, request_sha256, "
                        "instance_id, target_kind, target_id, original_generation, original_incarnation, "
                        "reader_generation, reader_incarnation, credential_ref, config_revision, provider_contract, "
                        "reserved_at, classification, observation) SELECT read_id, attempt_id, effect_id, action_id, "
                        "request_sha256, instance_id, target_kind, target_id, original_generation, "
                        "original_incarnation, reader_generation, reader_incarnation, credential_ref, config_revision, "
                        "provider_contract, reserved_at, 'not_acked', '{}' FROM voalack.reconciliation_reads "
                        "WHERE read_id = %s RETURNING reconciliation_id", (read,))
            rec = cur.fetchone()[0]
            cur.execute("INSERT INTO voalack.settlements (decision_id, decision_input_sha256, attempt_id, effect_id, "
                        "action_id, request_sha256, instance_id, target_kind, target_id, original_generation, "
                        "original_incarnation, outcome, path, reconciliation_id, reader_generation, reader_incarnation, "
                        "reader_credential_ref, reader_config_revision, reader_provider_contract, holders, "
                        "quiescence_ids, prior_effect_state, prior_in_flight_attempt, prior_guard_state, effect_state, "
                        "decided_by, note) SELECT %s, %s, attempt_id, effect_id, action_id, request_sha256, instance_id, "
                        "target_kind, target_id, original_generation, original_incarnation, 'retired_after_quiescence', "
                        "'operator', reconciliation_id, reader_generation, reader_incarnation, credential_ref, "
                        "config_revision, provider_contract, '[]', '{}', 'UNCERTAIN', attempt_id, 'uncertain', "
                        "'BLOCKED', 'lab', '' FROM voalack.reconciliations WHERE reconciliation_id = %s",
                        (str(uuid.uuid4()), "c" * 64, rec))
    return rows


HISTORY = ("SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM (SELECT effect_id, effect_key, state || '/' || "
           "attempt_count || '/' || coalesce(next_attempt_after::text, '-') || '/' || coalesce(retry_owner_generation::text, "
           "'-') || '/' || coalesce(retry_incarnation::text, '-'), in_flight_attempt FROM voalack.effects "
           "UNION ALL SELECT NULL, attempt_id::text, state || permit_state || (dispatched_at IS NULL)::text || "
           "(settled_at IS NULL)::text || request_sha256, NULL FROM voalack.attempts "
           "UNION ALL SELECT NULL, attempt_id::text, state, NULL FROM voalack.target_guards "
           "UNION ALL SELECT settlement_id, decision_id::text, outcome, attempt_id FROM voalack.settlements "
           "UNION ALL SELECT owner_generation, instance_id, state, incarnation FROM voalack.session_owners) x")
CATALOG = ("SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (SELECT p.oid::regprocedure::text || ':' || md5(p.prosrc) AS x "
           "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'voalack' "
           "UNION ALL SELECT c.relname || '.' || a.attname || ':' || format_type(a.atttypid, a.atttypmod) FROM pg_class c "
           "JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_attribute a ON a.attrelid = c.oid "
           "WHERE n.nspname = 'voalack' AND a.attnum > 0 AND NOT a.attisdropped) y")


def test_upgrade_from_s3b_fences_every_existing_owner_until_bootstrap(s3b_db, tmp_path):
    with psycopg2.connect(s3b_db) as conn, conn.cursor() as cur:
        _seed_s3b(cur)
    before = _q(s3b_db, HISTORY)[0][0]
    for _ in range(2):                                               # upgrade, then repeated application
        with psycopg2.connect(s3b_db) as conn:
            schema.apply(conn)
        with psycopg2.connect(s3b_db.replace("lab_admin:lab-only-admin", SENDER_LOGIN)) as conn:
            verifier.check_ready(conn, sender.SENDER)
        with psycopg2.connect(s3b_db.replace("lab_admin:lab-only-admin", SETTLER_LOGIN)) as conn:
            verifier.check_ready(conn, settler.SETTLER)
    assert _q(s3b_db, HISTORY)[0][0] == before                       # history untouched
    assert _q(s3b_db, "SELECT count(*) FROM voalack.recovery_epoch")[0][0] == 0     # no silent bootstrap
    assert _q(s3b_db, "SELECT DISTINCT mode, acquired_epoch FROM voalack.session_owners") == [("ordinary", None)]
    active = _q(s3b_db, "SELECT owner_generation, incarnation::text FROM voalack.session_owners "
                        "WHERE instance_id = 'up-active'")[0]
    check = "SELECT voalack.check_owner('up-active', %s, %s)"
    assert _q(s3b_db, check, active)[0][0] == "epoch_changed"                # fenced until bootstrap
    head = recovery.bootstrap(str(tmp_path / "anchor"), s3b_db, {"basis": "lab upgrade bootstrap"})
    assert _q(s3b_db, check, active)[0][0] == "epoch_changed"                # and after: never acquired at it
    gen = _q(s3b_db.replace("lab_admin:lab-only-admin", SENDER_LOGIN),
             "SELECT voalack.acquire_owner('up-free', 'lab-new', %s, 1, 1, %s, 'ordinary')",
             (str(uuid.uuid4()), head.sha256))[0][0]
    assert gen == 2
    with pytest.raises(psycopg2.errors.RaiseException, match="not free or contained"):
        _q(s3b_db.replace("lab_admin:lab-only-admin", SENDER_LOGIN),
           "SELECT voalack.acquire_owner('up-active', 'lab-new', %s, 1, 1, %s, 'ordinary')",
           (str(uuid.uuid4()), head.sha256))
    rolled = psycopg2.connect(s3b_db)
    try:
        rolled.cursor().execute("DROP TABLE voalack.recovery_epoch CASCADE")    # lab: proves the table exists
        rolled.rollback()
    finally:
        rolled.close()


def test_s3c_migration_rolls_back_and_reapplies_on_s3b_history(s3b_db, tmp_path):
    """[native] F5/R7: the S3b->S3c migration applied inside one transaction and rolled back leaves the
    S3b catalog and history exactly as they were; reapplied and committed, it keeps the history, passes
    readiness, bootstraps only explicitly, and a later reapplication does not reset recovery state."""
    with psycopg2.connect(s3b_db) as conn, conn.cursor() as cur:
        _seed_s3b(cur)
    history, catalog = _q(s3b_db, HISTORY)[0][0], _q(s3b_db, CATALOG)[0][0]
    assert _q(s3b_db, "SELECT count(*) FROM voalack.attempts WHERE state IN ('not_sent', 'aborted_before_dispatch')")[0][0] == 2
    migration = psycopg2.connect(s3b_db)
    try:
        cur = migration.cursor()
        cur.execute(schema.full_sql())                             # the migration, not committed
        cur.execute("SELECT to_regclass('voalack.recovery_epoch') IS NOT NULL, "
                    "to_regprocedure('voalack.acquire_owner(text, text, uuid)') IS NULL")
        assert cur.fetchone() == (True, True)
        migration.rollback()
    finally:
        migration.close()
    assert _q(s3b_db, "SELECT to_regclass('voalack.recovery_epoch') IS NULL, "
                      "to_regprocedure('voalack.acquire_owner(text, text, uuid)') IS NOT NULL")[0] == (True, True)
    assert (_q(s3b_db, HISTORY)[0][0], _q(s3b_db, CATALOG)[0][0]) == (history, catalog)   # S3b exactly as it was
    with psycopg2.connect(s3b_db) as conn:                           # reapply and commit
        schema.apply(conn)
    assert _q(s3b_db, HISTORY)[0][0] == history and _q(s3b_db, CATALOG)[0][0] != catalog
    for login, profile in ((SENDER_LOGIN, sender.SENDER), (SETTLER_LOGIN, settler.SETTLER)):
        with psycopg2.connect(s3b_db.replace("lab_admin:lab-only-admin", login)) as conn:
            verifier.check_ready(conn, profile)
    assert _q(s3b_db, "SELECT count(*) FROM voalack.recovery_epoch")[0][0] == 0             # no silent bootstrap
    anchor = str(tmp_path / "anchor")
    recovery.bootstrap(anchor, s3b_db, {"basis": "lab upgrade bootstrap"})
    closed = recovery.close(anchor, s3b_db)
    transitions = _q(s3b_db, "SELECT count(*) FROM voalack.recovery_transitions")[0][0]
    with psycopg2.connect(s3b_db) as conn:                           # a later reapplication
        schema.apply(conn)
    assert _q(s3b_db, "SELECT epoch, phase, head_seq, head_sha256 FROM voalack.recovery_epoch") == \
        [(1, "closed", 2, closed.sha256)]                            # not reset
    assert _q(s3b_db, "SELECT count(*) FROM voalack.recovery_transitions")[0][0] == transitions
    assert _q(s3b_db, HISTORY)[0][0] == history
