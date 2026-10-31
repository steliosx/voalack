"""T04 S3c: the external recovery anchor (design 1dae56ab C1-C8, spec r1).

A supervisor-written, hash-chained log outside the Voalack database: ``<anchor_dir>/anchor.log``,
one canonical JSON object per line. Workers read it (``Anchor``); only the supervisor writes it
(``Supervisor``). A worker holds authority only for the exact head it acquired under; any change of
the head, and any read or validation failure, means closed. The chain detects malformed or spliced
content, not truncation to an earlier valid prefix (stated exclusion, U5).

Phases: ``open`` (epoch 1, bootstrap) -> ``closed`` (e) -> ``inventoried`` (e) -> ``recovering``
(e+1) -> ``open`` (e+1) -> ``closed`` ...
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Callable, NamedTuple, Optional

import psycopg2

LOG = "anchor.log"
LOCK = ".lock"
MAX_BYTES = 1 << 20
MAX_LINES = 4096
MAX_DOCUMENT_BYTES = 64 << 20
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_BASE = {"v", "seq", "epoch", "phase", "prev", "at"}
_FIELDS = {"bootstrap": {"bootstrap"}, "closed": set(),
           "inventoried": {"inventory_sha256", "inventory_file", "captured_at"},
           "recovering": {"inventory_sha256", "backup_id", "backup_sha256", "review_sha256", "review_ref"},
           "open": {"adoption_sha256"}}
# The phase a line may follow: genesis has no predecessor.
_AFTER = {"closed": ("open",), "inventoried": ("closed",), "recovering": ("inventoried",), "open": ("recovering",)}


class AnchorInvalid(RuntimeError):
    """The anchor is unreadable, malformed or inconsistent: treated as closed."""


class AnchorConflict(RuntimeError):
    """A supervisor transition does not follow the expected head."""


class Head(NamedTuple):
    seq: int
    sha256: str
    epoch: int
    phase: str
    line: dict


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise AnchorInvalid("duplicate key")
    return dict(pairs)


def _int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value, limit: int = 256) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit


_REVIEW_KEYS = {"v", "ref", "backup_id", "backup_sha256", "inventory_sha256", "decision"}
_MANIFEST_KEYS = {"v", "epoch", "recovering_seq", "recovering_sha256", "inventory_sha256", "review_sha256",
                  "backup_id", "backup_sha256", "adoption_input_sha256"}
_INVENTORY_KEYS = {"attempts", "captured_at", "cleanups", "containment", "effects", "epoch", "format", "guards",
                   "head_seq", "head_sha256", "owners", "provider_sessions", "quiescence", "recovered_effects",
                   "recovered_holds", "recovery_history", "settlements"}
_validated: dict = {}           # sha256 -> parsed document (content-addressed: same digest, same bytes)


def _hex64(value) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value))


def _backup_ok(backup_id, backup_sha256) -> bool:
    return _text(backup_id) and ((backup_id == "none") == (backup_sha256 is None)) and (
        backup_sha256 is None or _hex64(backup_sha256))


def _document(directory: str, kind: str, sha: str) -> dict:
    """A linked document: the exact bytes (re-read and hashed on every check), parsed and its
    schema validated once per digest."""
    data = _verify_document(directory, f"{kind}-{sha}.json", sha)
    if sha in _validated:
        return _validated[sha]
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AnchorInvalid(f"malformed {kind}: {type(exc).__name__}") from None
    if not isinstance(doc, dict):
        raise AnchorInvalid(f"malformed {kind}")
    if kind == "inventory":
        ok = (set(doc) == _INVENTORY_KEYS and doc["format"] == "voalack-inventory/2" and _int(doc["epoch"])
              and _int(doc["head_seq"]) and _hex64(doc["head_sha256"]) and isinstance(doc["captured_at"], str)
              and isinstance(doc["recovery_history"], dict)
              and all(isinstance(doc[k], list) for k in _INVENTORY_KEYS
                      - {"captured_at", "epoch", "format", "head_seq", "head_sha256", "recovery_history"}))
    elif kind == "review":
        ok = (canonical(doc) == data and set(doc) == _REVIEW_KEYS and doc["v"] == 1 and _int(doc["v"])
              and _text(doc["ref"]) and _backup_ok(doc["backup_id"], doc["backup_sha256"])
              and _hex64(doc["inventory_sha256"]) and doc["decision"] == "adopt")
    else:
        ok = (canonical(doc) == data and set(doc) == _MANIFEST_KEYS and doc["v"] == 1 and _int(doc["v"])
              and _int(doc["epoch"]) and _int(doc["recovering_seq"]) and _hex64(doc["recovering_sha256"])
              and _hex64(doc["inventory_sha256"]) and _hex64(doc["review_sha256"])
              and _backup_ok(doc["backup_id"], doc["backup_sha256"]) and _hex64(doc["adoption_input_sha256"]))
    if not ok:
        raise AnchorInvalid(f"{kind} document does not match its schema")
    _validated[sha] = doc
    return doc


def _check_inventory(directory: str, sha: str, epoch: int, heads: list) -> dict:
    """The inventory was taken at exactly the closed line of this epoch in this chain."""
    doc = _document(directory, "inventory", sha)
    closed = [h for h in heads if h.seq == doc["head_seq"]]
    if doc["epoch"] != epoch or not closed or closed[0].phase != "closed" or closed[0].sha256 != doc["head_sha256"] \
            or closed[0].epoch != epoch:
        raise AnchorInvalid("inventory is not bound to this chain's closed line")
    return doc


def _check_review(directory: str, recovering: dict) -> dict:
    doc = _document(directory, "review", recovering["review_sha256"])
    if (doc["ref"], doc["backup_id"], doc["backup_sha256"], doc["inventory_sha256"]) != (
            recovering["review_ref"], recovering["backup_id"], recovering["backup_sha256"],
            recovering["inventory_sha256"]):
        raise AnchorInvalid("review does not match the recovering line")
    return doc


def _check_line(line: dict, heads: list, directory: str, is_head: bool) -> None:
    prev = heads[-1] if heads else None
    phase = line.get("phase")
    genesis = prev is None
    kind = "bootstrap" if genesis else phase
    if not isinstance(phase, str) or (kind not in _AFTER and not genesis):
        raise AnchorInvalid("unknown phase")
    if set(line) != _BASE | _FIELDS[kind]:
        raise AnchorInvalid("unexpected or missing fields")
    if line["v"] != 1 or not _int(line["v"]) or not _int(line["seq"]) or not _int(line["epoch"]):
        raise AnchorInvalid("bad version or counters")
    if not _text(line["at"], 64):
        raise AnchorInvalid("bad timestamp")
    if genesis:
        if (line["seq"], line["epoch"], phase, line["prev"], line["bootstrap"]) != (1, 1, "open", None, True):
            raise AnchorInvalid("bad genesis")
        return
    if line["seq"] != prev.seq + 1 or line["prev"] != prev.sha256:
        raise AnchorInvalid("broken chain")
    if prev.phase not in _AFTER[phase]:
        raise AnchorInvalid("transition not allowed")
    if line["epoch"] != prev.epoch + (1 if phase == "recovering" else 0):
        raise AnchorInvalid("bad epoch")
    if phase == "inventoried":
        if not (isinstance(line["inventory_sha256"], str) and _HEX64.match(line["inventory_sha256"])
                and line["inventory_file"] == f"inventory-{line['inventory_sha256']}.json"
                and _text(line["captured_at"], 64)):
            raise AnchorInvalid("bad inventory fields")
    elif phase == "recovering":
        if not (line["inventory_sha256"] == prev.line["inventory_sha256"]
                and _backup_ok(line["backup_id"], line["backup_sha256"])
                and _hex64(line["review_sha256"]) and _text(line["review_ref"])):
            raise AnchorInvalid("bad recovery fields")
    elif phase == "open":
        if not _hex64(line["adoption_sha256"]):
            raise AnchorInvalid("bad adoption digest")
    if not is_head:
        return
    # The head's external dependencies, re-validated on every read (R6, F2): missing, tampered or
    # unlinked documents mean closed, including after the reopen.
    if phase == "inventoried":
        doc = _check_inventory(directory, line["inventory_sha256"], line["epoch"], heads)
        if doc["captured_at"] != line["captured_at"]:
            raise AnchorInvalid("inventory capture time does not match its line")
    elif phase == "recovering":
        _check_inventory(directory, line["inventory_sha256"], line["epoch"] - 1, heads)
        _check_review(directory, line)
    elif phase == "open":
        manifest = _document(directory, "adoption", line["adoption_sha256"])
        recovering = prev.line
        if (manifest["epoch"], manifest["recovering_seq"], manifest["recovering_sha256"], manifest["inventory_sha256"],
                manifest["review_sha256"], manifest["backup_id"], manifest["backup_sha256"]) != (
                line["epoch"], prev.seq, prev.sha256, recovering["inventory_sha256"], recovering["review_sha256"],
                recovering["backup_id"], recovering["backup_sha256"]):
            raise AnchorInvalid("adoption manifest does not match the recovering line")
        _check_inventory(directory, recovering["inventory_sha256"], line["epoch"] - 1, heads)
        _check_review(directory, recovering)


def _read_bounded(path: str, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise AnchorInvalid(f"unreadable: {type(exc).__name__}") from None
    try:
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise AnchorInvalid(f"unreadable: {type(exc).__name__}") from None
    if len(data) > limit:
        raise AnchorInvalid("oversized")
    return data


def _verify_document(directory: str, name: str, sha: str) -> bytes:
    data = _read_bounded(os.path.join(directory, name), MAX_DOCUMENT_BYTES)
    if hashlib.sha256(data).hexdigest() != sha:
        raise AnchorInvalid("document digest mismatch")
    return data


def _parse(directory: str, data: bytes) -> list:
    """All heads of a complete, valid chain (fails closed on anything else)."""
    if not data.endswith(b"\n"):
        raise AnchorInvalid("incomplete final line")
    raw_lines = data[:-1].split(b"\n")
    if len(raw_lines) > MAX_LINES:
        raise AnchorInvalid("too many lines")
    heads: list = []
    for index, raw in enumerate(raw_lines):
        try:
            line = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
        except (UnicodeDecodeError, ValueError) as exc:
            raise AnchorInvalid(f"malformed line: {type(exc).__name__}") from None
        if not isinstance(line, dict) or canonical(line) != raw:
            raise AnchorInvalid("non-canonical line")
        _check_line(line, heads, directory, index == len(raw_lines) - 1)
        heads.append(Head(line["seq"], hashlib.sha256(raw).hexdigest(), line["epoch"], line["phase"], line))
    return heads


class Anchor:
    """Read-only view of an anchor directory (workers)."""

    def __init__(self, directory: str):
        self.directory = os.path.abspath(directory)

    def heads(self) -> list:
        return _parse(self.directory, _read_bounded(os.path.join(self.directory, LOG), MAX_BYTES))

    def head(self) -> Head:
        return self.heads()[-1]

    def document(self, name: str, sha: str) -> bytes:
        return _verify_document(self.directory, name, sha)


def _fsync_dir(directory: str) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Supervisor:
    """The only writer. Serialized by an exclusive lock; every transition names the exact prior head."""

    def __init__(self, directory: str, fault: Optional[Callable[[str], None]] = None):
        self.directory = os.path.abspath(directory)
        self.fault = fault or (lambda point: None)     # lab: labelled crash/failure points

    @contextlib.contextmanager
    def _locked(self):
        os.makedirs(self.directory, mode=0o755, exist_ok=True)
        fd = os.open(os.path.join(self.directory, LOCK), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _write_atomic(self, name: str, data: bytes) -> None:
        tmp = os.path.join(self.directory, f".{name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, data)
            self.fault(f"write:{name}")
            os.fsync(fd)
            os.fchmod(fd, 0o444)
        finally:
            os.close(fd)
        self.fault(f"rename:{name}")
        os.replace(tmp, os.path.join(self.directory, name))
        _fsync_dir(self.directory)

    def write_document(self, kind: str, data: bytes) -> str:
        """Content-addressed inventory or review document (immutable once written)."""
        if kind not in ("inventory", "review", "adoption"):
            raise ValueError("unknown document kind")
        sha = hashlib.sha256(data).hexdigest()
        name = f"{kind}-{sha}.json"
        with self._locked():
            path = os.path.join(self.directory, name)
            if os.path.exists(path):
                if _read_bounded(path, MAX_DOCUMENT_BYTES) != data:
                    raise AnchorConflict("document exists with other bytes")
                return sha
            self._write_atomic(name, data)
        return sha

    def append(self, expected: Optional[tuple], phase: str, **fields) -> Head:
        """Append one transition after exactly ``expected`` = (seq, sha256), or None for genesis. An
        exact duplicate of the last transition returns its head; anything else that does not follow
        ``expected`` refuses."""
        with self._locked():
            path = os.path.join(self.directory, LOG)
            data = b"" if not os.path.exists(path) else _read_bounded(path, MAX_BYTES)
            heads = _parse(self.directory, data) if data else []
            current = (heads[-1].seq, heads[-1].sha256) if heads else None
            if current != expected:
                last = heads[-1] if heads else None
                previous = (heads[-2].seq, heads[-2].sha256) if len(heads) > 1 else None
                if (last is not None and previous == expected and last.phase == phase
                        and {k: v for k, v in last.line.items() if k not in _BASE} == fields):
                    return last                              # exact duplicate of the last transition
                raise AnchorConflict(f"anchor head {current} is not the expected {expected}")
            prev = heads[-1] if heads else None
            line = {"v": 1, "seq": (prev.seq + 1) if prev else 1,
                    "epoch": (prev.epoch + (1 if phase == "recovering" else 0)) if prev else 1,
                    "phase": phase, "prev": prev.sha256 if prev else None,
                    "at": datetime.now(timezone.utc).isoformat(), **fields}
            raw = canonical(line)
            _check_line(line, heads, self.directory, True)
            self._write_atomic(LOG, data + raw + b"\n")
            head = Anchor(self.directory).head()
            if (head.seq, head.sha256) != (line["seq"], hashlib.sha256(raw).hexdigest()):
                raise AnchorInvalid("read-back mismatch")
            return head


# -- supervised procedures (administrator DSN) ------------------------------------------------------

def bootstrap(directory: str, admin_dsn: str, evidence: dict, supervisor: Optional[Supervisor] = None) -> Head:
    """A new installation: the genesis line, then the database's explicit initialization."""
    sup = supervisor or Supervisor(directory)
    head = sup.append(None, "open", bootstrap=True)
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack.initialize_recovery(%s, %s::jsonb)", (head.sha256, json.dumps(evidence)))
    return head


def close(directory: str, admin_dsn: str, supervisor: Optional[Supervisor] = None) -> Head:
    """The barrier: the anchor's closed line first (published and read back), then the database. A
    failure to publish raises before anything else happens; re-running completes a partial close."""
    sup = supervisor or Supervisor(directory)
    head = Anchor(directory).head()
    if head.phase == "open":
        head = sup.append((head.seq, head.sha256), "closed")
    elif head.phase != "closed":
        raise AnchorConflict(f"cannot close from {head.phase}")
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack.close_recovery(%s, %s, %s)", (head.epoch, head.seq, head.sha256))
    return head


def inventory(directory: str, admin_dsn: str, supervisor: Optional[Supervisor] = None) -> Head:
    """After containment and quiescence: the database's complete ledger as an immutable document,
    bound by the anchor's inventoried line to the closed line it was taken under."""
    sup = supervisor or Supervisor(directory)
    head = Anchor(directory).head()
    if head.phase != "closed":
        raise AnchorConflict(f"cannot take the inventory from {head.phase}")
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack.recovery_inventory()::text")
        text = cur.fetchone()[0]
    document = json.loads(text)
    if (document["epoch"], document["head_seq"], document["head_sha256"]) != (head.epoch, head.seq, head.sha256):
        raise AnchorConflict("the database's closed line is not the anchor's")
    sha = sup.write_document("inventory", text.encode("utf-8"))
    return sup.append((head.seq, head.sha256), "inventoried", inventory_sha256=sha,
                      inventory_file=f"inventory-{sha}.json", captured_at=document["captured_at"])


def restore_permitted(directory: str, inventory_sha256: str) -> Head:
    """A restore command may run only while the anchor's head is the inventoried line naming exactly
    this inventory (the lab's guard in front of pg_restore)."""
    head = Anchor(directory).head()
    if head.phase != "inventoried" or head.line["inventory_sha256"] != inventory_sha256:
        raise AnchorConflict("restore is not permitted: the anchor is not inventoried with this inventory")
    return head


def write_review(directory: str, review: dict, supervisor: Optional[Supervisor] = None) -> str:
    """The administrator's review of a restored database: names the backup, the inventory and the
    decision to adopt (immutable, content-addressed)."""
    document = {"v": 1, **review}
    if not (set(document) == _REVIEW_KEYS and _text(document["ref"])
            and _backup_ok(document["backup_id"], document["backup_sha256"])
            and _hex64(document["inventory_sha256"]) and document["decision"] == "adopt"):
        raise ValueError("a review names its ref, the backup and its dump digest, the inventory and the decision to adopt")
    return (supervisor or Supervisor(directory)).write_document("review", canonical(document))


def recover(directory: str, admin_dsn: str, review_sha256: str, supervisor: Optional[Supervisor] = None, *,
            layout: str, journal_dir: Optional[str] = None) -> Head:
    """The recovering line for epoch e+1 (bound to the inventory, the backup and the review), then the
    database's adoption. Re-running after a crash completes the same step. T04 S4 (D9): ``layout`` is the
    supervisor's declaration ('shared' or 'voalack_only'); a shared database needs this inventory's
    validated restore journal (when the review names a backup) and the capture contract."""
    sup = supervisor or Supervisor(directory)
    anchor = Anchor(directory)
    heads = anchor.heads()
    head = heads[-1]
    if head.phase == "inventoried":
        inventoried = head
    elif head.phase == "recovering" and len(heads) > 1:
        inventoried = heads[-2]
    else:
        raise AnchorConflict(f"cannot recover from {head.phase}")
    inventory_sha = inventoried.line["inventory_sha256"]
    review = _document(directory, "review", review_sha256)
    if review["inventory_sha256"] != inventory_sha:
        raise AnchorConflict("the review names another inventory")
    _layout_gate(admin_dsn, layout, journal_dir, inventory_sha, review["backup_sha256"])   # T04 S4 (D9)
    head = sup.append((inventoried.seq, inventoried.sha256), "recovering", inventory_sha256=inventory_sha,
                      backup_id=review["backup_id"], backup_sha256=review["backup_sha256"],
                      review_sha256=review_sha256, review_ref=review["ref"])
    text = anchor.document(f"inventory-{inventory_sha}.json", inventory_sha).decode("utf-8")
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM voalack.adopt_recovery(%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)",
                    (head.epoch, head.seq, head.sha256, text, inventory_sha, review["backup_id"],
                     review["backup_sha256"], review_sha256, review["ref"]))
    return head


def reopen(directory: str, admin_dsn: str, supervisor: Optional[Supervisor] = None, *, layout: str,
           journal_dir: Optional[str] = None) -> Head:
    """The open line for the adopted epoch (bound to the adoption digest), then the database. Re-running
    after a crash completes the same step."""
    sup = supervisor or Supervisor(directory)
    heads = Anchor(directory).heads()
    recovering = heads[-1] if heads[-1].phase == "recovering" else heads[-2] if len(heads) > 1 else None
    if recovering is None or recovering.phase != "recovering" or heads[-1].phase not in ("recovering", "open"):
        raise AnchorConflict(f"cannot reopen from {heads[-1].phase}")
    _layout_gate(admin_dsn, layout, journal_dir, recovering.line["inventory_sha256"],   # T04 S4 (D9)
                 recovering.line["backup_sha256"])
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT input_sha256 FROM voalack.recovery_adoptions WHERE epoch = %s AND head_sha256 = %s",
                    (recovering.epoch, recovering.sha256))
        row = cur.fetchone()
    if row is None:
        raise AnchorConflict("the database has not adopted this recovering line")
    # The immutable external adoption manifest links the recovering line, inventory, review, backup
    # and the database's adoption input; the open line names it (R6, F2).
    line = recovering.line
    manifest = {"v": 1, "epoch": recovering.epoch, "recovering_seq": recovering.seq,
                "recovering_sha256": recovering.sha256, "inventory_sha256": line["inventory_sha256"],
                "review_sha256": line["review_sha256"], "backup_id": line["backup_id"],
                "backup_sha256": line["backup_sha256"], "adoption_input_sha256": row[0]}
    manifest_sha = sup.write_document("adoption", canonical(manifest))
    head = sup.append((recovering.seq, recovering.sha256), "open", adoption_sha256=manifest_sha)
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack.open_recovery(%s, %s, %s)", (head.epoch, head.seq, head.sha256))
    return head


# -- shared-database restore (T04 S4, supervisor procedure amendment D9) -------------------------------
#
# Voalack and Alerta share one database. Alerta's public.alerts carries Voalack's capture trigger, which
# depends on voalack.capture_ack(); a clean restore of the voalack schema cannot drop that function, so
# the bare restore command exits non-zero there. The supervisor procedure below detaches exactly that
# trigger (validated against the approved contract), runs the unchanged restore, recreates the trigger
# from the installed schema source and validates everything before recovery may continue. Each step is
# its own committed transaction and is journaled outside the database and the anchor; a crash or failure
# leaves the anchor inventoried and recover/reopen refusing until the procedure completes.

CAPTURE_TRIGGER = "voalack_capture_ack"
CAPTURE_TGTYPE = 17                                          # FOR EACH ROW (1) | UPDATE (16); AFTER
# pg_get_triggerdef of the approved trigger on the qualified PostgreSQL major (18).
CAPTURE_TRIGGERDEF = ("CREATE TRIGGER voalack_capture_ack AFTER UPDATE ON public.alerts FOR EACH ROW WHEN "
                      "(((old.history[1] IS DISTINCT FROM new.history[1]) AND (new.history[1].type = 'ack'::text) "
                      "AND (new.status = 'ack'::text))) EXECUTE FUNCTION voalack.capture_ack()")
DEFINER_CONFIG = ["search_path=pg_catalog, voalack, pg_temp"]
# The one permitted cross-schema dependency on the restored schema: (type, identity) -> (type, identity).
ALLOWED_DEPENDENCY = ("trigger", "voalack_capture_ack on public.alerts", "function", "voalack.capture_ack()")
# Coexistence 3a S2: the three ownership/lifetime protections on public.alerts, each with its exact form
# (tgtype bits: ROW 1, BEFORE 2, INSERT 4, DELETE 8, UPDATE 16, TRUNCATE 32), function and no WHEN/args.
# S2 is a non-integrable checkpoint: S3 replaces this presence/form check with the permit/journal design.
PROTECTION_TRIGGERS = {
    "voalack_alert_lifetime": (5, "voalack.alert_lifetime()"),            # AFTER INSERT, row
    "voalack_alert_ownership": (25, "voalack.alert_ownership()"),         # AFTER UPDATE OR DELETE, row
    "voalack_alert_no_truncate": (34, "voalack.alert_no_truncate()"),     # BEFORE TRUNCATE, statement
}
# The exact frozen definitions, as pg_get_triggerdef renders them here (table always qualified; the function
# qualified because voalack is not on this session's search_path). A constraint or deferrable trigger of the
# same name renders differently ("CREATE CONSTRAINT TRIGGER ... DEFERRABLE ...") and is refused.
PROTECTION_TRIGGERDEFS = {
    "voalack_alert_lifetime": "CREATE TRIGGER voalack_alert_lifetime AFTER INSERT ON public.alerts FOR EACH ROW "
                              "EXECUTE FUNCTION voalack.alert_lifetime()",
    "voalack_alert_ownership": "CREATE TRIGGER voalack_alert_ownership AFTER DELETE OR UPDATE ON public.alerts "
                               "FOR EACH ROW EXECUTE FUNCTION voalack.alert_ownership()",
    "voalack_alert_no_truncate": "CREATE TRIGGER voalack_alert_no_truncate BEFORE TRUNCATE ON public.alerts "
                                 "FOR EACH STATEMENT EXECUTE FUNCTION voalack.alert_no_truncate()",
}
ALLOWED_DEPENDENCIES = sorted([ALLOWED_DEPENDENCY] + [("trigger", f"{name} on public.alerts", "function", function)
                                                      for name, (_, function) in PROTECTION_TRIGGERS.items()])
RESTORE_STEPS = ("begin", "detached", "restore_failed", "restored", "recreated", "validated")


class RestoreRefused(RuntimeError):
    """The shared-database restore cannot start or continue from this state; nothing was changed."""


class RestoreFailed(RuntimeError):
    """A restore step failed; the procedure stays incomplete (recovery stays closed) until re-run."""


def _schema_source() -> str:
    from .schema import schema_sql
    return schema_sql()


def approved_trigger_ddl() -> str:
    """The CREATE TRIGGER statement of the capture trigger, from the installed schema source."""
    text = _schema_source()
    start = text.index("CREATE TRIGGER voalack_capture_ack")
    return text[start:text.index(";", start) + 1]


def approved_protection_ddl() -> list:
    """The CREATE TRIGGER statements of the three protection triggers, from the installed schema source."""
    text = _schema_source()
    out = []
    for name in PROTECTION_TRIGGERS:
        start = text.index(f"CREATE TRIGGER {name} ")
        out.append(text[start:text.index(";", start) + 1])
    return out


def approved_capture_source() -> str:
    """The body of voalack.capture_ack() as the installed schema source defines it."""
    text = _schema_source()
    head = text.index("CREATE OR REPLACE FUNCTION voalack.capture_ack()")
    start = text.index("$$", head) + 2
    return text[start:text.index("$$", start)]


def capture_contract(cur) -> list:
    """Problems with the capture trigger and its function against the approved contract (empty: as
    approved). Vacuous where public.alerts does not exist (a Voalack-only database)."""
    cur.execute("SELECT to_regclass('public.alerts') IS NOT NULL")
    if not cur.fetchone()[0]:
        return []
    cur.execute("SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE t.tgrelid = 'public.alerts'::regclass AND NOT t.tgisinternal "
                "AND (n.nspname = 'voalack' OR t.tgname = %s)", (CAPTURE_TRIGGER,))
    count = cur.fetchone()[0]
    cur.execute("SELECT t.tgtype, t.tgenabled, t.tgisinternal, t.tgconstraint::bigint, t.tgnargs, "
                "cardinality(t.tgattr::int2[]), t.tgfoid::regprocedure::text, pg_get_triggerdef(t.oid), "
                "p.prosecdef, pg_get_userbyid(p.proowner), p.proconfig, p.prosrc, "
                "p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) x "
                "                            WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE') "
                "FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid "
                "WHERE t.tgrelid = 'public.alerts'::regclass AND t.tgname = %s", (CAPTURE_TRIGGER,))
    row = cur.fetchone()
    if row is None:
        return ["capture trigger absent"] + (["other voalack triggers on public.alerts"] if count else [])
    (tgtype, enabled, internal, constraint, nargs, nattr, function, definition, secdef, owner, config,
     source, public_execute) = row
    problems = []
    if count != 1 + len(PROTECTION_TRIGGERS):
        problems.append("other voalack triggers on public.alerts")
    cur.execute("SELECT t.tgname, t.tgtype, t.tgenabled, t.tgnargs, cardinality(t.tgattr::int2[]), "
                "t.tgfoid::regprocedure::text, t.tgqual IS NULL, t.tgconstraint::bigint, t.tgdeferrable, "
                "t.tginitdeferred, pg_get_triggerdef(t.oid) FROM pg_trigger t "
                "WHERE t.tgrelid = 'public.alerts'::regclass AND t.tgname = ANY(%s)", (list(PROTECTION_TRIGGERS),))
    present = {r[0]: r[1:] for r in cur.fetchall()}
    for name, (p_tgtype, p_function) in PROTECTION_TRIGGERS.items():   # never rebind the capture row's names
        expected = (p_tgtype, "O", 0, 0, p_function, True, 0, False, False, PROTECTION_TRIGGERDEFS.get(name))
        if present.get(name) != expected:
            problems.append(f"protection trigger {name} absent or differs: {present.get(name)}")
    if (tgtype, enabled, internal, constraint, nargs, nattr) != (CAPTURE_TGTYPE, "O", False, 0, 0, 0):
        problems.append(f"capture trigger form {(tgtype, enabled, internal, constraint, nargs, nattr)}")
    if function != "voalack.capture_ack()":
        problems.append(f"capture trigger function {function}")
    if definition != CAPTURE_TRIGGERDEF:
        problems.append(f"capture trigger definition differs: {definition}")
    if not secdef or owner != "voalack_admin" or list(config or []) != DEFINER_CONFIG or public_execute:
        problems.append("capture function security differs")
    if source != approved_capture_source():
        problems.append("capture function source differs")
    # Coexistence 3a S3a (plan r2 P4): the same frozen inventory as protect(), the gate and the projector: the two
    # event triggers enabled, every protected function by digest/owner/security/proconfig/ACL, the guard and lifetime
    # objects. (Missing public triggers are reported above, specifically.)
    cur.execute("SELECT to_regprocedure('voalack_guard.inventory_problems()') IS NOT NULL")
    if cur.fetchone()[0]:
        cur.execute("SELECT voalack_guard.inventory_problems()")
        problems.extend(f"guard: {p}" for p in cur.fetchone()[0] if not p.startswith("missing public_trigger "))
    return problems


# The schema an object belongs to, from its own catalog row (pg_identify_object reports none for triggers,
# column defaults and rules); NULL for any other kind of object, which is then treated as outside.
_OWNING_SCHEMA = """
CASE {cls}
  WHEN 'pg_class'::regclass THEN (SELECT c.relnamespace FROM pg_class c WHERE c.oid = {obj})
  WHEN 'pg_proc'::regclass THEN (SELECT p.pronamespace FROM pg_proc p WHERE p.oid = {obj})
  WHEN 'pg_type'::regclass THEN (SELECT t.typnamespace FROM pg_type t WHERE t.oid = {obj})
  WHEN 'pg_constraint'::regclass THEN (SELECT k.connamespace FROM pg_constraint k WHERE k.oid = {obj})
  WHEN 'pg_trigger'::regclass THEN (SELECT c.relnamespace FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid
                                     WHERE g.oid = {obj})
  WHEN 'pg_attrdef'::regclass THEN (SELECT c.relnamespace FROM pg_attrdef a JOIN pg_class c ON c.oid = a.adrelid
                                     WHERE a.oid = {obj})
  WHEN 'pg_rewrite'::regclass THEN (SELECT c.relnamespace FROM pg_rewrite w JOIN pg_class c ON c.oid = w.ev_class
                                     WHERE w.oid = {obj})
END"""
_DEPENDENCIES = f"""
SELECT o.type, o.identity, r.type, r.identity
  FROM pg_depend d
  CROSS JOIN LATERAL (SELECT {_OWNING_SCHEMA.format(cls="d.classid", obj="d.objid")} AS ns) os
  CROSS JOIN LATERAL (SELECT {_OWNING_SCHEMA.format(cls="d.refclassid", obj="d.refobjid")} AS ns) rs
  CROSS JOIN LATERAL pg_identify_object(d.classid, d.objid, d.objsubid) o
  CROSS JOIN LATERAL pg_identify_object(d.refclassid, d.refobjid, d.refobjsubid) r
 WHERE d.deptype IN ('n', 'a')
   AND rs.ns = 'voalack'::regnamespace
   AND os.ns IS DISTINCT FROM 'voalack'::regnamespace
 ORDER BY 1, 2, 3, 4"""


def cross_schema_dependencies(cur) -> list:
    """Every object outside the voalack schema that depends on an object in it, as
    (type, identity, referenced type, referenced identity)."""
    cur.execute(_DEPENDENCIES)
    return [tuple(r) for r in cur.fetchall()]


def _recognised_3a(admin_dsn: str) -> bool:
    """Any coexistence 3a marker: the guard or lifetime schema, S2's protections_intact, or a guard event trigger."""
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT to_regnamespace('voalack_guard') IS NOT NULL OR to_regnamespace('voalack_lifetime') IS NOT NULL"
                    " OR to_regprocedure('voalack.protections_intact()') IS NOT NULL"
                    " OR EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname LIKE 'voalack%')")
        return cur.fetchone()[0]


def _refuse_staged_restore(admin_dsn: str) -> None:
    """Coexistence 3a S3a/S3b staging (design review): with the DDL guard installed, no maintenance permit can open
    (open_permit refuses until the S3b containment) and the admitted restore arrives only in S3c. So the restore is
    refused here, after every earlier validation and before its first database change; nothing is detached.
    Any coexistence 3a marker counts (the guard or lifetime schema, a guard event trigger, or S2's protections_intact),
    so a 3a installation whose guard is missing, partial, disabled or drifted is refused too: missing protections never
    confer restore permission. Only a historical pre-3a installation (no marker at all) proceeds as before."""
    if _recognised_3a(admin_dsn):
        raise RestoreRefused("restore is staged: the coexistence 3a restore arrives in S3c and no maintenance "
                             "permit can open before it; nothing was changed")


def detach_capture_trigger(admin_dsn: str, lock_timeout_ms: int = 5000) -> None:
    """Step: drop exactly the capture trigger (RESTRICT), committed in its own connection."""
    conn = psycopg2.connect(admin_dsn)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET lock_timeout = {int(lock_timeout_ms)}")
            cur.execute(f"DROP TRIGGER {CAPTURE_TRIGGER} ON public.alerts RESTRICT")
            for name in PROTECTION_TRIGGERS:                      # coexistence 3a S2: all four protections
                cur.execute(f"DROP TRIGGER IF EXISTS {name} ON public.alerts RESTRICT")
        conn.commit()
    finally:
        conn.close()


def recreate_capture_trigger(admin_dsn: str, lock_timeout_ms: int = 5000) -> None:
    """Step: create the capture trigger from the installed schema source (never from the live catalog),
    committed in its own connection; the trigger is enabled for ordinary sessions on creation."""
    conn = psycopg2.connect(admin_dsn)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET lock_timeout = {int(lock_timeout_ms)}")
            cur.execute(approved_trigger_ddl())
            for ddl in approved_protection_ddl():                 # coexistence 3a S2: all four protections
                cur.execute(ddl)
        conn.commit()
    finally:
        conn.close()


class JournalCorrupt(RuntimeError):
    """The restore journal is torn, corrupt or out of order: an unknown state for manual review."""


# The step grammar: begin once, first; then detach (again only while nothing was restored), failed
# restores, one restore, at most one recreate after it, and validated once, last.
_NEXT = {None: {"begin"}, "begin": {"detached", "restore_failed", "restored"}, "detached": {"detached", "restore_failed", "restored"},
         "restore_failed": {"restore_failed", "restored"}, "restored": {"recreated", "validated"},
         "recreated": {"validated"}, "validated": set()}


class RestoreJournal:
    """The supervisor's durable step record for one inventory: canonical JSON lines, each fsynced, in a
    supervisor-only directory outside the database, the restore set and the anchor. Read strictly: a torn
    tail (no final newline), an unparsable line or an out-of-order step is refused, never repaired."""

    def __init__(self, directory: str, inventory_sha256: str):
        self.directory = directory
        self.inventory = inventory_sha256
        self.path = os.path.join(directory, f"restore-{inventory_sha256}.jsonl")

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def entries(self) -> list:
        if not self.exists():
            return []
        with open(self.path, "rb") as handle:
            data = handle.read()
        if data and not data.endswith(b"\n"):
            raise JournalCorrupt("the restore journal has a torn tail")
        entries, last = [], None
        for raw in data.split(b"\n")[:-1]:
            try:
                entry = json.loads(raw, object_pairs_hook=_no_duplicates)
            except ValueError as exc:
                raise JournalCorrupt("the restore journal has an unparsable line") from exc
            if not isinstance(entry, dict) or entry.get("step") not in _NEXT.get(last, set()):
                raise JournalCorrupt(f"the restore journal is out of order after {last}")
            if entry["step"] == "begin" and entry.get("inventory_sha256") != self.inventory:
                raise JournalCorrupt("the restore journal names another inventory")
            entries.append(entry)
            last = entry["step"]
        return entries

    def steps(self) -> list:
        return [e["step"] for e in self.entries()]

    def append(self, step: str, **fields) -> None:
        steps = self.steps()
        if step not in _NEXT.get(steps[-1] if steps else None, set()):
            raise JournalCorrupt(f"step {step} cannot follow {steps[-1] if steps else 'nothing'}")
        record = {"step": step, "at": datetime.now(timezone.utc).isoformat(timespec="microseconds"), **fields}
        with open(self.path, "ab") as handle:
            handle.write(canonical(record) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(self.directory or ".")

    @contextlib.contextmanager
    def exclusive(self):
        """One supervisor run per inventory at a time (non-blocking: a concurrent run is refused)."""
        fd = os.open(os.path.join(self.directory, f"restore-{self.inventory}.lock"), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RestoreRefused("another restore of this inventory is running") from exc
            yield self
        finally:
            os.close(fd)


LAYOUTS = ("shared", "voalack_only")


def contract_digest() -> str:
    """The installed capture contract this procedure checks against (bound in the journal)."""
    return hashlib.sha256(canonical({"triggerdef": CAPTURE_TRIGGERDEF, "ddl": approved_trigger_ddl(),
                                     "source": approved_capture_source(), "tgtype": CAPTURE_TGTYPE,
                                     "config": DEFINER_CONFIG, "protection_ddl": approved_protection_ddl(),
                                     "protection_forms": {k: list(v) for k, v in PROTECTION_TRIGGERS.items()},
                                     "protection_defs": PROTECTION_TRIGGERDEFS})
                          ).hexdigest()


def _layout_state(cur, layout: str) -> list:
    """Problems with the database against the declared layout (empty: as declared and as approved)."""
    if layout not in LAYOUTS:
        raise ValueError(f"unknown layout {layout!r}")
    cur.execute("SELECT to_regclass('public.alerts') IS NOT NULL")
    alerts = cur.fetchone()[0]
    dependencies = cross_schema_dependencies(cur)
    if layout == "voalack_only":
        problems = ["declared Voalack-only, but Alerta's tables are present"] if alerts else []
        return problems + ([f"dependencies {dependencies}"] if dependencies else [])
    if not alerts:
        return ["declared shared, but public.alerts is missing"]
    problems = capture_contract(cur)
    expected = [] if problems[:1] == ["capture trigger absent"] else ALLOWED_DEPENDENCIES
    if sorted(dependencies) != sorted(expected):            # independent of the database collation
        problems.append(f"dependencies {dependencies}")
    return problems


def _layout_gate(admin_dsn: str, layout: str, journal_dir: Optional[str], inventory_sha256: str,
                 backup_sha256: Optional[str]) -> None:
    """recover/reopen (D9): the declared layout as approved and, for a shared database restored from a
    backup, this inventory's journal validated for exactly that backup, layout and installed contract,
    with the surviving publications unchanged since its begin."""
    with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
        problems = _layout_state(cur, layout)
        publications = _publication_digest(cur)
    if problems:
        raise AnchorConflict("the database is not as declared and approved: " + "; ".join(problems))
    if layout == "voalack_only":
        # Coexistence 3a staging (F5 residual): a Voalack-only recovery from a restored backup on a recognised 3a
        # installation is refused like the shared one, before any anchor or database change (the recovery of a
        # restore arrives in S3c). Recovery without a backup, and genuinely historical no-marker installations, keep
        # their own checks.
        if backup_sha256 is not None and _recognised_3a(admin_dsn):
            raise AnchorConflict("recovery from a restored backup is staged: the coexistence 3a restore and its "
                                 "recovery arrive in S3c")
        return
    journal = RestoreJournal(journal_dir, inventory_sha256) if journal_dir else None
    if backup_sha256 is None:
        if journal is not None and journal.exists():
            raise AnchorConflict("a restore journal exists for an inventory whose review names no backup")
        return
    if journal is None or not journal.exists():
        raise AnchorConflict("a shared database restored from a backup needs its validated restore journal")
    try:
        entries = journal.entries()
    except JournalCorrupt as exc:
        raise AnchorConflict(f"the restore journal is not usable: {exc}") from exc
    begin = entries[0]
    if entries[-1]["step"] != "validated":
        raise AnchorConflict(f"the restore is not validated (last step {entries[-1]['step']})")
    if (begin.get("backup_sha256"), begin.get("layout"), begin.get("contract")) != \
            (backup_sha256, "shared", contract_digest()):
        raise AnchorConflict("the restore journal is bound to another backup, layout or contract")
    if publications != begin.get("publications"):
        raise AnchorConflict("the surviving publications changed since the restore began")
    # Coexistence 3a staging: even a validated journal does not admit recovery from a restored backup on a 3a
    # installation (deferred to S3c); after every check above, so their refusals keep precedence.
    if _recognised_3a(admin_dsn):
        raise AnchorConflict("recovery from a restored backup is staged: the coexistence 3a restore and its recovery "
                             "arrive in S3c")


def _publication_digest(cur) -> str:
    cur.execute("SELECT to_regclass('voalack_publication.publications') IS NOT NULL")
    if not cur.fetchone()[0]:
        return "absent"
    cur.execute("SELECT md5(coalesce(string_agg(p::text, '|' ORDER BY p.note_id), '')) || ':' || count(*) "
                "FROM voalack_publication.publications p")
    return cur.fetchone()[0]


def _anchor_digest(directory: str) -> str:
    """The anchor's chain: its head and the exact bytes of its log (content-addressed documents such as
    a review may be added meanwhile; the chain may not move)."""
    head = Anchor(directory).head()
    with open(os.path.join(directory, LOG), "rb") as handle:
        log = hashlib.sha256(handle.read()).hexdigest()
    return f"{head.seq}:{head.sha256}:{log}"


def _default_execute_revoked(cur) -> bool:
    cur.execute("SELECT EXISTS (SELECT 1 FROM pg_default_acl d JOIN pg_roles a ON a.oid = d.defaclrole "
                "WHERE a.rolname = 'voalack_admin' AND d.defaclobjtype = 'f' AND d.defaclnamespace = 0 "
                "AND NOT EXISTS (SELECT 1 FROM aclexplode(d.defaclacl) x "
                "                WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE'))")
    return cur.fetchone()[0]


HASH_CHUNK = 1 << 20


def file_sha256(path: str) -> str:
    """SHA-256 of a file read in bounded chunks (a backup dump may be larger than memory)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def restore_shared(directory: str, admin_dsn: str, dump_path: str, inventory_sha256: str, journal_dir: str,
                   fault: Optional[Callable[[str], None]] = None, *, layout: str) -> str:
    """The supervised Voalack-only restore (D9), in the declared layout ('shared': a database shared with
    Alerta; 'voalack_only'). Only while the anchor is inventoried with exactly this inventory, bound to
    exactly this backup, one run at a time. Returns 'validated', or 'already_complete' when this
    inventory's restore was validated before and the current state still validates. Raises
    RestoreRefused before any change, RestoreFailed after a failed step (re-run to continue) and
    JournalCorrupt for an unusable journal (manual review)."""
    import subprocess
    if layout not in LAYOUTS:
        raise ValueError(f"unknown layout {layout!r}")
    restore_permitted(directory, inventory_sha256)
    backup = file_sha256(dump_path)
    journal = RestoreJournal(journal_dir, inventory_sha256)
    with journal.exclusive():
        entries = journal.entries()
        if entries and (entries[0].get("backup_sha256"), entries[0].get("layout"), entries[0].get("contract")) != \
                (backup, layout, contract_digest()):
            raise RestoreRefused("this inventory's restore is bound to another backup, layout or contract")
        steps = [e["step"] for e in entries]
        shared = layout == "shared"
        hook = fault or (lambda point: None)
        if "validated" not in steps:
            with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
                problems = _layout_state(cur, layout)
                if not entries:
                    journal.append("begin", inventory_sha256=inventory_sha256, backup_sha256=backup, layout=layout,
                                   contract=contract_digest(), publications=_publication_digest(cur),
                                   anchor=_anchor_digest(directory))
                    entries = journal.entries()
            if problems == ["capture trigger absent"]:
                # Absent and journaled as detached by this procedure: continue. Absent otherwise (including a
                # committed detach whose journal entry was lost): an unknown state for manual review.
                if "detached" not in steps:
                    raise RestoreRefused("the capture trigger is absent and this procedure did not record detaching it")
            elif problems:
                raise RestoreRefused("the database is not as declared and approved: " + "; ".join(problems))
            # Every unfinished state (fresh, or resumed after detached/restored/recreated), after the earlier
            # refusals and before any hook, database change or FURTHER journal append. A fresh attempt has already
            # journaled its begin entry above, so a staged refusal leaves exactly that entry (disclosed limit).
            _refuse_staged_restore(admin_dsn)
            if not problems and shared and "restored" not in steps:
                detach_capture_trigger(admin_dsn)
                journal.append("detached")
                steps.append("detached")
            hook("after_detach")
            if "restored" not in steps:
                done = subprocess.run(["pg_restore", "--clean", "--if-exists", "-d", admin_dsn, dump_path],
                                      capture_output=True, text=True)
                hook("after_restore")
                if done.returncode != 0:
                    journal.append("restore_failed", returncode=done.returncode, stderr=done.stderr[-2000:])
                    raise RestoreFailed(f"pg_restore exited {done.returncode}")
                journal.append("restored", returncode=0)
            hook("before_recreate")
            if shared:
                with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
                    absent = capture_contract(cur) == ["capture trigger absent"]
                if absent:
                    recreate_capture_trigger(admin_dsn)
                    journal.append("recreated")
        else:
            # A completed journal confers no coexistence 3a restore or recovery either: staged the same way.
            _refuse_staged_restore(admin_dsn)
        begin = journal.entries()[0]
        with psycopg2.connect(admin_dsn) as conn, conn.cursor() as cur:
            failures = _layout_state(cur, layout)
            if _publication_digest(cur) != begin["publications"]:
                failures.append("publication records changed")
            if not _default_execute_revoked(cur):
                failures.append("default EXECUTE for PUBLIC is not revoked")
        if _anchor_digest(directory) != begin["anchor"]:
            failures.append("anchor chain changed")
        if failures:
            raise RestoreFailed("restored state not validated: " + "; ".join(failures))
        if "validated" in steps:
            return "already_complete"
        journal.append("validated")
        return "validated"


# ==== Coexistence 3a S3b: the recovery coordinator (r8 section 11; S3b delta r2 + r3, concurred 78f1861c) ==========
# Step primitives and crash reconciliation for one recovery window, on ONE registered coordinator connection (READ
# COMMITTED, three strictly sequential transactions per step: intent, effect with its receipt, seal). Every decision is
# made and enforced by the installed guard functions (voalack_guard.*); this class only sequences them and performs the
# effects they bind (role limits, termination, trigger DDL). The package contains no sequence that runs a window
# without a restore: S3b production restores stay refused before any window (_refuse_staged_restore), the S3c restore
# phase does not exist, and the labelled no-restore sequence lives in the test tree.

S3B_STEPS = ("contain", "detach", "transition", "recreate", "validate", "close", "release")
TERMINATE_WAIT_MS = 10000
TERMINATE_ROUNDS = 3


class RecoveryClosed(RuntimeError):
    """The window stays closed: a refused predicate or a state the journal cannot explain (operator disposition)."""


def _terminate_backend(cur, pid: int) -> None:
    """One termination request (waits up to TERMINATE_WAIT_MS); its outcome is confirmed separately, never trusted."""
    cur.execute("SELECT pg_terminate_backend(%s, %s)", (pid, TERMINATE_WAIT_MS))


from psycopg2 import sql as pgsql   # noqa: E402  (S3b: role identifiers and limits are composed, never interpolated)


class Coordinator:
    """The registered coordinator of one recovery window. ``hook(point)`` is a fault-injection point for tests."""

    def __init__(self, dsn: str, window_id: int, hook: Optional[Callable[[str], None]] = None):
        self.dsn = dsn
        self.window_id = window_id
        self.source_sha256 = None
        self.hook = hook or (lambda point: None)
        self.conn = psycopg2.connect(dsn)
        self.conn.set_session(isolation_level="READ COMMITTED", autocommit=False)

    # -- lifecycle ---------------------------------------------------------------------------------------------------
    @classmethod
    def open(cls, dsn: str, source_sha256: str, attestation: dict, legacy_journal_dir: Optional[str] = None,
             hook: Optional[Callable[[str], None]] = None) -> "Coordinator":
        """Open a window and register this connection (two committed transactions). A legacy file restore journal
        for the installation is unexplained on a 3a installation: refused, never converted (r2 section B)."""
        if legacy_journal_dir and os.path.isdir(legacy_journal_dir) and os.listdir(legacy_journal_dir):
            raise RecoveryClosed("a legacy restore journal exists; it is never converted into a recovery window")
        conn = psycopg2.connect(dsn)
        conn.set_session(isolation_level="READ COMMITTED", autocommit=False)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT voalack_guard.open_window(%s, %s::jsonb)", (source_sha256, json.dumps(attestation)))
                window_id = cur.fetchone()[0]
            conn.commit()
        except psycopg2.Error as exc:
            conn.rollback()
            conn.close()
            raise RecoveryClosed(f"window refused: {exc.pgerror or exc}") from exc
        coordinator = cls.__new__(cls)
        coordinator.dsn, coordinator.window_id, coordinator.source_sha256 = dsn, window_id, source_sha256
        coordinator.hook = hook or (lambda point: None)
        coordinator.conn = conn
        coordinator._call("register_backend", "SELECT voalack_guard.register_backend(%s, %s)", (window_id, source_sha256))
        return coordinator

    @classmethod
    def resume(cls, dsn: str, window_id: int, source_sha256: str,
               hook: Optional[Callable[[str], None]] = None) -> "Coordinator":
        """Take over a window after the previous coordinator has gone: registration refuses while it is present, and
        refuses another approved source identity than the window's (the window also binds database and cluster)."""
        coordinator = cls(dsn, window_id, hook)
        coordinator.source_sha256 = source_sha256
        coordinator._call("register_backend", "SELECT voalack_guard.register_backend(%s, %s)", (window_id, source_sha256))
        return coordinator

    def close(self) -> None:
        self.conn.close()

    # -- transactions ------------------------------------------------------------------------------------------------
    def _call(self, what: str, query: str, args: tuple = ()):
        """One committed transaction; any database refusal keeps the window closed."""
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, args)
                row = cur.fetchone() if cur.description else None
            self.conn.commit()
            return row[0] if row else None
        except psycopg2.Error as exc:
            self.conn.rollback()
            raise RecoveryClosed(f"{what} refused: {exc.pgerror or exc}") from exc

    def _intent_row(self, seq: int) -> dict:
        with self.conn.cursor() as cur:
            cur.execute("SELECT step, prior, target FROM voalack_guard.recovery_journal "
                        "WHERE window_id = %s AND seq = %s AND kind = 'intent'", (self.window_id, seq))
            step, prior, target = cur.fetchone()
        self.conn.commit()
        return {"step": step, "prior": prior, "target": target}

    # -- the three transactions of a step ----------------------------------------------------------------------------
    def begin(self, step: str) -> int:
        seq = self._call(f"{step} intent", "SELECT voalack_guard.begin_step(%s, %s)", (self.window_id, step))
        self.hook(f"{step}:after_intent")
        return seq

    def effect(self, step: str, seq: int) -> None:
        """T_effect: the step's database effect, then its receipt (record_effect), committed together."""
        intent = self._intent_row(seq)
        four = [n for n in PROTECTION_TRIGGERS] + [CAPTURE_TRIGGER]
        try:
            with self.conn.cursor() as cur:
                cur.execute("SET LOCAL lock_timeout = '10s'")
                if step == "contain":
                    for role in intent["prior"]["k"]:
                        cur.execute(pgsql.SQL("ALTER ROLE {} CONNECTION LIMIT 0").format(pgsql.Identifier(role["name"])))
                elif step == "detach":
                    cur.execute("SELECT voalack_guard.open_permit(%s, %s)", (self.window_id, seq))
                    for name in four:
                        cur.execute(f"DROP TRIGGER IF EXISTS {name} ON public.alerts RESTRICT")
                elif step == "transition":
                    cur.execute("SELECT voalack_guard.transition_permit(%s, %s, 'detach', 'recreate')",
                                (self.window_id, seq))
                elif step == "recreate":
                    for name in intent["prior"]["present"]:
                        cur.execute(f"DROP TRIGGER {name} ON public.alerts RESTRICT")
                    cur.execute(approved_trigger_ddl())
                    for ddl in approved_protection_ddl():
                        cur.execute(ddl)
                elif step == "close":
                    cur.execute("SELECT voalack_guard.close_permit(%s, %s)", (self.window_id, seq))
                elif step == "release":
                    for role in intent["prior"]["k"]:
                        cur.execute(pgsql.SQL("ALTER ROLE {} CONNECTION LIMIT {}").format(
                            pgsql.Identifier(role["name"]), pgsql.Literal(int(role["limit"]))))
                else:
                    raise RecoveryClosed(f"step {step} has no effect transaction")
                self.hook(f"{step}:before_receipt")
                cur.execute("SELECT voalack_guard.record_effect(%s, %s)", (self.window_id, seq))
            self.conn.commit()
        except psycopg2.Error as exc:
            self.conn.rollback()
            raise RecoveryClosed(f"{step} effect refused: {exc.pgerror or exc}") from exc
        self.hook(f"{step}:after_effect")
        if step == "contain":
            self.terminate_contained()

    def seal(self, step: str, seq: int) -> int:
        """T_seal, in a fresh transaction. The seal row's insert trigger binds the receipt and runs the step's
        predicates; for validate it runs the validation, for close the protector probe."""
        n = self._call(f"{step} seal", "SELECT voalack_guard.seal_step(%s, %s)", (self.window_id, seq))
        self.hook(f"{step}:after_seal")
        return n

    def step(self, step: str) -> None:
        seq = self.begin(step)
        if step != "validate":
            self.effect(step, seq)
        self.seal(step, seq)

    def lab_gap(self) -> None:
        """The labelled no-restore gap (S3b lab profile): a journal record, never a restore record or marker."""
        self._call("lab gap", "SELECT voalack_guard.lab_gap(%s)", (self.window_id,))

    def close_window(self) -> None:
        self._call("close window", "SELECT voalack_guard.close_window(%s)", (self.window_id,))

    # -- containment: termination with bounded confirmation ----------------------------------------------------------
    def terminate_contained(self) -> None:
        """Terminate every session of every contained role (cluster-wide) and every other superuser session on this
        database, then confirm none remains (bounded rounds). A remaining session keeps the window closed."""
        query = ("SELECT a.pid FROM pg_stat_activity a JOIN pg_roles r ON r.oid = a.usesysid "
                 "WHERE a.pid <> pg_backend_pid() AND a.backend_type = 'client backend' "
                 "AND (a.usesysid = ANY (%s::oid[]) OR (r.rolsuper AND a.datname = current_database()))")
        with self.conn.cursor() as cur:
            cur.execute("SELECT voalack_guard.window_snapshot(%s)", (self.window_id,))
            k = [int(role["oid"]) for role in cur.fetchone()[0]["k"]]
        self.conn.commit()
        for _ in range(TERMINATE_ROUNDS):
            with self.conn.cursor() as cur:
                cur.execute(query, (k,))
                pids = [row[0] for row in cur.fetchall()]
                self.hook("contain:terminate")
                for pid in pids:
                    _terminate_backend(cur, pid)
            self.conn.commit()
            with self.conn.cursor() as cur:
                cur.execute(query, (k,))
                remaining = [row[0] for row in cur.fetchall()]
            self.conn.commit()
            if not remaining:
                return
        raise RecoveryClosed(f"sessions remain after termination: {sorted(remaining)}")

    # -- crash reconciliation (r3 section 1; r2 section F) -----------------------------------------------------------
    def classify(self) -> dict:
        """Read the window, journal, receipts and catalog in ONE read-only REPEATABLE READ snapshot and classify the
        latest step. Acting happens afterwards, through the guard functions, which recheck everything."""
        self.conn.rollback()
        self.conn.set_session(isolation_level="REPEATABLE READ", readonly=True)
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT (voalack_guard.open_intent(%s)).seq, (voalack_guard.open_intent(%s)).step, "
                            "voalack_guard.next_step(%s)", (self.window_id,) * 3)
                seq, step, nxt = cur.fetchone()
                if seq is None:
                    return {"state": "between", "next": nxt}
                cur.execute("SELECT prior, target FROM voalack_guard.recovery_journal WHERE window_id = %s AND seq = %s",
                            (self.window_id, seq))
                prior, target = cur.fetchone()
                if step == "validate":
                    return {"state": "redo", "step": step, "seq": seq}
                cur.execute("SELECT EXISTS (SELECT 1 FROM voalack_guard.recovery_effects "
                            "WHERE window_id = %s AND intent_seq = %s)", (self.window_id, seq))
                receipt = cur.fetchone()[0]
                cur.execute("SELECT voalack_guard.effect_problems(%s, %s, %s::jsonb)",
                            (self.window_id, step, json.dumps(target)))
                target_holds = cur.fetchone()[0] == []
                prior_holds = self._prior_holds(cur, step, prior)
        finally:
            self.conn.rollback()
            self.conn.set_session(isolation_level="READ COMMITTED", readonly=False)
        if receipt:
            return {"state": "seal" if target_holds else "unexplained", "step": step, "seq": seq,
                    "why": None if target_holds else "a receipt whose effect the catalog contradicts"}
        if prior_holds:
            return {"state": "redo", "step": step, "seq": seq}
        return {"state": "unexplained", "step": step, "seq": seq,
                "why": "an effect without its receipt" if target_holds else "neither the prior nor the target holds"}

    def _prior_holds(self, cur, step: str, prior: dict) -> bool:
        four = [CAPTURE_TRIGGER] + list(PROTECTION_TRIGGERS)
        cur.execute("SELECT tgname FROM pg_trigger WHERE tgrelid = 'public.alerts'::regclass AND tgname = ANY (%s)",
                    (four,))
        present = sorted(row[0] for row in cur.fetchall())
        cur.execute("SELECT window_id, phase FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL")
        permit = cur.fetchone()
        if step in ("contain", "release"):
            k = prior["k"]
            cur.execute("SELECT oid::bigint, rolconnlimit FROM pg_roles WHERE oid = ANY (%s::oid[])",
                        ([int(r["oid"]) for r in k],))
            limits = dict(cur.fetchall())
            want = {int(r["oid"]): (int(r["limit"]) if step == "contain" else 0) for r in k}
            return limits == want
        if step == "detach":
            return permit is None and present == sorted(prior["present"])
        if step == "transition":
            return permit == (self.window_id, "detach")
        if step == "recreate":
            return permit == (self.window_id, "recreate") and present == sorted(prior["present"])
        if step == "close":
            return permit is not None and permit[0] == self.window_id
        return False

    def reconcile(self) -> str:
        """Resume the latest step from the snapshot's classification; an unexplained state raises RecoveryClosed."""
        c = self.classify()
        if c["state"] == "between":
            return f"between steps; next {c['next']}"
        if c["state"] == "unexplained":
            raise RecoveryClosed(f"unexplained {c['step']} intent {c['seq']}: {c['why']}")
        if c["state"] == "redo" and c["step"] != "validate":
            self.effect(c["step"], c["seq"])                       # contain's effect terminates as well
        elif c["step"] == "contain":
            self.terminate_contained()                             # committed limits, termination not confirmed
        self.seal(c["step"], c["seq"])
        return f"{c['step']} {'re-run and sealed' if c['state'] == 'redo' else 'sealed'}"
