"""T04 S4: outcome events and the operator projection (spec r1-r3, D1-D7) on the lab database.

Native Alerta 9.1.0 and PostgreSQL in the guest; the fake ONE provider supplies upstream outcomes.
Every identity (event digest, note id, note-row digest) is recomputed here independently in Python
from the stored rows. Projection is display only: these witnesses also check that it never touches
delivery state, intents, captures or the alert row.
"""
import datetime
import hashlib
import json
import uuid

import psycopg2
import psycopg2.extras
import pytest

from conftest import APP_DSN, DSN, LAB_ANCHOR_DIR, SENDER_DSN, VERIFIER_DSN, guard_bypassed, lab_anchor, sql
from test_t04_s2_sender import _effect, _owner, fake, instance  # noqa: F401
from voalack import projector, verifier

PROJECTOR_DSN = "postgres://lab_projector:lab-only-projector@localhost/alerta"
NAMESPACE = uuid.UUID("31964abc-7784-44a0-a81f-4a1f829a329d")
NAME = "lab-projector"


# -- independent recomputation (D4, D7.1) -------------------------------------------------------------

def canonical(value) -> bytes:
    def check(v):
        if isinstance(v, float):
            raise AssertionError("no floats in canonical JSON")
        if isinstance(v, dict):
            for x in v.values():
                check(x)
        if isinstance(v, list):
            for x in v:
                check(x)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def utc(value):
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def event_sha256(e) -> str:
    pre = {"action_id": str(e["action_id"]), "epoch": e["epoch"], "revision": e["revision"], "outcome": e["outcome"],
           "reason": e["reason"], "facts": e["facts"], "occurred_at": utc(e["occurred_at"]),
           "alert_id": e["alert_id"], "customer": e["customer"], "note_text": e["note_text"],
           "note_time": utc(e["note_time"])}
    return hashlib.sha256(canonical(pre)).hexdigest()


def note_id(sha: str) -> str:
    b = bytearray(hashlib.sha256(NAMESPACE.bytes + sha.encode()).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x80
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def note_row_sha256(n) -> str:
    doc = {"id": n["id"], "text": n["text"], "user": n["user"], "attributes": n["attributes"], "type": n["type"],
           "create_time": utc(n["create_time"]), "update_time": utc(n["update_time"]), "alert": n["alert"],
           "customer": n["customer"]}
    return hashlib.sha256(canonical(doc)).hexdigest()


# -- helpers ------------------------------------------------------------------------------------------

def rows(statement, args=(), dsn=DSN):
    with psycopg2.connect(dsn) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(statement, args)
        return [dict(r) for r in cur.fetchall()] if cur.description else []


def events(action):
    return rows("SELECT * FROM voalack.outcome_events WHERE action_id = %s ORDER BY revision", (action,))


def notes(action):
    return rows("SELECT * FROM public.notes WHERE attributes->'voalack'->>'action_id' = %s ORDER BY create_time, id",
                (action,))


def note(nid):
    found = rows("SELECT * FROM public.notes WHERE id = %s", (nid,))
    return found[0] if found else None


def publications(action):
    return rows("SELECT * FROM voalack_publication.publications WHERE action_id = %s ORDER BY epoch, revision",
                (action,))


def markers(action):
    return rows("SELECT * FROM voalack.projections WHERE action_id = %s ORDER BY revision", (action,))


def action_of(effect_id):
    return sql("SELECT action_id::text FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0][0]


def drain():
    """Project every pending event of the lab database (other tests' events included)."""
    out = []
    while True:
        batch = projector.run(PROJECTOR_DSN, LAB_ANCHOR_DIR, NAME, max_steps=500)
        out.extend(batch)
        if batch[-1]["outcome"] != "done":
            return out


def status(action):
    with psycopg2.connect(PROJECTOR_DSN) as conn:
        return projector.status(conn, action)


def alert_digest(alert_id):
    """The alert row exactly, apart from nothing: projection must not change it."""
    return sql("SELECT md5(a::text) FROM alerts a WHERE a.id = %s", (alert_id,))[0][0]


def delivery_digest():
    return sql("SELECT md5(string_agg(x, '|' ORDER BY x)) FROM ("
               "SELECT 'e' || e::text AS x FROM voalack.effects e UNION ALL "
               "SELECT 'a' || a.attempt_id || a.state || a.permit_state FROM voalack.attempts a UNION ALL "
               "SELECT 'g' || g::text FROM voalack.target_guards g UNION ALL "
               "SELECT 'p' || p.action_id FROM voalack.prepared_intents p UNION ALL "
               "SELECT 'c' || c.action_id FROM voalack.captures c) t")[0][0]


def check_identities_on(dsn, action):
    """Every event's digest and note id, and every published note's row digest (while the note is
    present), recomputed here from the stored rows of the database at dsn."""
    for e in rows("SELECT * FROM voalack.outcome_events WHERE action_id = %s ORDER BY revision", (action,), dsn):
        assert e["event_sha256"] == event_sha256(e), e
        assert e["note_id"] == note_id(e["event_sha256"])
        if e["alert_id"] is not None:
            assert e["note_attributes"] == {"voalack": {"action_id": action, "epoch": e["epoch"],
                                                        "revision": e["revision"], "event_sha256": e["event_sha256"]}}
    for p in rows("SELECT * FROM voalack_publication.publications WHERE action_id = %s", (action,), dsn):
        found = rows("SELECT * FROM public.notes WHERE id = %s", (p["note_id"],), dsn)
        assert found and note_row_sha256(found[0]) == p["note_row_sha256"], p


def check_identities(action):
    check_identities_on(DSN, action)


@pytest.fixture
def drained(app):
    drain()


# -- witnesses ----------------------------------------------------------------------------------------

def test_one_note_per_event_in_order_with_exact_rows(client, app, instance, fake, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    alert_id = sql("SELECT alert_id FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0][0]
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    evs = events(action)
    assert [(e["revision"], e["outcome"]) for e in evs] == [(1, "queued"), (2, "confirmed")]
    head = lab_anchor().head()
    assert {e["epoch"] for e in evs} == {head.epoch}
    before_alert, before_delivery = alert_digest(alert_id), delivery_digest()
    intents = sql("SELECT count(*) FROM voalack.prepared_intents")[0][0]

    drain()
    got = notes(action)
    assert [n["id"] for n in got] == [e["note_id"] for e in evs]
    for e, n in zip(evs, got):
        assert (n["text"], n["user"], n["type"], n["alert"], n["customer"], n["attributes"]) == \
               (e["note_text"], "voalack", "alert", e["alert_id"], e["customer"], e["note_attributes"])
        assert n["create_time"] == n["update_time"] == e["note_time"]
        assert len(n["text"]) <= 400
    assert got[0]["text"].startswith("[Voalack] ACK queued for Veeam ONE · epoch %d · action %s · revision 1 · "
                                      "ACK requested " % (head.epoch, action))
    assert got[1]["text"].startswith("[Voalack] ACK confirmed by Veeam ONE · epoch %d" % head.epoch)
    assert [(p["epoch"], p["revision"], p["note_id"]) for p in publications(action)] == \
           [(e["epoch"], e["revision"], e["note_id"]) for e in evs]
    assert [m["status"] for m in markers(action)] == ["projected", "projected"]
    check_identities(action)
    st = status(action)
    assert st["current"] == {"note_id": evs[1]["note_id"], "epoch": head.epoch, "revision": 2}
    assert st["latest_publication"]["display"] == "valid" and st["last_projected_revision"] == 2
    # display only: the alert row, delivery ledger, intents and captures are unchanged
    assert alert_digest(alert_id) == before_alert and delivery_digest() == before_delivery
    assert sql("SELECT count(*) FROM voalack.prepared_intents")[0][0] == intents
    # idempotent: nothing more to publish, no duplicate
    assert drain()[-1]["outcome"] == "idle" and len(notes(action)) == 2


def test_forged_future_ordinary_note_never_orders_or_displays(client, app, instance, fake, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    alert_id = sql("SELECT alert_id FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0][0]
    drain()
    forged = str(uuid.uuid4())
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:     # Alerta's own login can write notes
        cur.execute("INSERT INTO notes (id, text, \"user\", attributes, type, create_time, update_time, alert, customer) "
                    "VALUES (%s, '[Voalack] ACK confirmed by Veeam ONE · epoch 99 · revision 99', 'voalack', %s, "
                    "'alert', now(), now(), %s, 'lab-customer')",
                    (forged, json.dumps({"voalack": {"action_id": action, "epoch": 99, "revision": 99,
                                                     "event_sha256": "f" * 64}}), alert_id))
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    drain()
    assert [m["status"] for m in markers(action)] == ["projected", "projected"]
    assert [p["revision"] for p in publications(action)] == [1, 2]
    st = status(action)
    assert st["current"]["revision"] == 2 and st["current"]["note_id"] != forged
    assert note(forged) is not None                                   # left alone, never adopted


def test_unproven_note_at_the_derived_id_is_a_visible_stop(client, app, instance, fake, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    alert_id = sql("SELECT alert_id FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0][0]
    nid = events(action)[0]["note_id"]
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO notes (id, text, \"user\", attributes, type, create_time, update_time, alert, customer) "
                    "VALUES (%s, 'squatter', 'someone', NULL, 'alert', now(), now(), %s, 'lab-customer')", (nid, alert_id))
    drain()
    assert [(m["revision"], m["status"]) for m in markers(action)] == [(1, "note_conflict")]
    assert publications(action) == [] and note(nid)["text"] == "squatter"
    st = status(action)
    assert st["stopped"]["status"] == "note_conflict" and st["current"] is None and st["last_projected_revision"] == 0
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"      # delivery is never held by display
    drain()
    assert [m["revision"] for m in markers(action)] == [1] and len(notes(action)) == 0


def test_altered_and_missing_published_notes_are_reported_never_repaired(client, app, instance, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    drain()
    nid = events(action)[0]["note_id"]
    assert status(action)["latest_publication"]["display"] == "valid"
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        cur.execute("UPDATE notes SET text = text || ' (edited)' WHERE id = %s", (nid,))
    st = status(action)
    assert st["latest_publication"]["display"] == "altered" and st["current"] is None
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM notes WHERE id = %s", (nid,))
    st = status(action)
    assert st["latest_publication"]["display"] == "missing" and st["current"] is None
    drain()
    assert note(nid) is None and [m["status"] for m in markers(action)] == ["projected"]
    assert len(publications(action)) == 1


# Coexistence 3a S2 (frozen r8 section 9, amended openly): deleting a ONE alert closes its lifetime, so the event's
# destination fails the lifetime fence first ('alert lifetime changed'); before 3a this read 'alert missing'.
@pytest.mark.parametrize("change, detail", [("customer", "alert customer changed"), ("delete", "alert lifetime changed")])
def test_destination_is_frozen_and_never_rerouted(client, app, instance, drained, change, detail):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    alert_id = sql("SELECT alert_id FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0][0]
    if change == "customer":
        sql("UPDATE alerts SET customer = 'lab-other' WHERE id = %s", (alert_id,), fetch=False)
    else:
        sql("DELETE FROM alerts WHERE id = %s", (alert_id,), fetch=False)
    drain()
    assert [(m["status"], m["detail"]) for m in markers(action)] == [("destination_conflict", detail)]
    assert publications(action) == [] and notes(action) == []
    assert status(action)["stopped"]["status"] == "destination_conflict"


def test_projector_has_only_its_display_capability(app):
    def denied(dsn, statement, args=()):
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute(statement, args)
    with psycopg2.connect(PROJECTOR_DSN) as conn:
        verifier.check_ready(conn, projector.PROJECTOR)
    for statement in ("SELECT * FROM public.notes", "SELECT * FROM public.alerts",
                      "SELECT * FROM voalack_publication.publications", "SELECT * FROM voalack.effects",
                      "SELECT * FROM voalack.attempts",
                      "INSERT INTO voalack.outcome_events (action_id) VALUES (gen_random_uuid())",
                      "SELECT voalack.release_stale_started('x', 1, gen_random_uuid())",
                      "SELECT voalack.backfill_projection_snapshot()",
                      "SELECT voalack._append_event(gen_random_uuid(), 'queued', '{}'::jsonb)",
                      "SELECT voalack.adopt_recovery(2, 2, repeat('a', 64), '{}'::jsonb, 'x', 'none', NULL, 'x', 'x')"):
        denied(PROJECTOR_DSN, statement)
    for dsn in (APP_DSN, SENDER_DSN, VERIFIER_DSN):
        denied(dsn, "SELECT * FROM voalack_publication.publications")
        denied(dsn, "SELECT * FROM voalack.project_next('x', 1, repeat('a', 64))")
    # the definer's rights on Alerta's tables are exactly the projection's
    assert sql("SELECT has_table_privilege('voalack_admin', 'public.notes', 'SELECT'), "
               "has_table_privilege('voalack_admin', 'public.notes', 'INSERT'), "
               "has_table_privilege('voalack_admin', 'public.notes', 'UPDATE'), "
               "has_table_privilege('voalack_admin', 'public.notes', 'DELETE'), "
               "has_column_privilege('voalack_admin', 'public.alerts', 'id', 'UPDATE'), "
               "has_column_privilege('voalack_admin', 'public.alerts', 'status', 'UPDATE')")[0] == \
        (True, True, False, False, True, False)


def test_stalled_projector_never_delays_delivery_and_order_holds(client, app, instance, fake, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    head = lab_anchor().head()
    stalled = psycopg2.connect(PROJECTOR_DSN)
    try:
        cur = stalled.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", ("stalled", head.epoch, head.sha256))
        first = dict(cur.fetchone())
        assert (first["outcome"], first["revision"], first["status"]) == ("done", 1, "projected")
        # [native] a second projector skips the locked action; the sender confirms meanwhile
        other = projector.run(PROJECTOR_DSN, LAB_ANCHOR_DIR, "other", max_steps=500)
        assert action not in {r.get("action_id") for r in other}
        owner = _owner(instance, fake)
        sent = owner.apply_once(effect_id)
        assert sent["outcome"] == "confirmed", sent
        assert [e["revision"] for e in events(action)] == [1, 2] and publications(action) == []
    finally:
        stalled.close()                                               # killed: rollback, nothing published
    drain()
    assert [(m["revision"], m["status"]) for m in markers(action)] == [(1, "projected"), (2, "projected")]
    assert [m["projector"] for m in markers(action)] == [NAME, NAME]


def test_unknown_commit_is_resolved_by_rereading_the_same_identity(client, app, instance, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    head = lab_anchor().head()
    with psycopg2.connect(PROJECTOR_DSN) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", (NAME, head.epoch, head.sha256))
        lost = dict(cur.fetchone())
        conn.rollback()                                               # the COMMIT never happened
    lost["action_id"] = str(lost["action_id"])
    assert projector.resolve(PROJECTOR_DSN, lost) == "not_committed" and publications(action) == []
    with psycopg2.connect(PROJECTOR_DSN) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", (NAME, head.epoch, head.sha256))
        done = dict(cur.fetchone())
    done["action_id"] = str(done["action_id"])
    assert (done["note_id"], done["revision"]) == (lost["note_id"], lost["revision"])   # the same identity
    assert projector.resolve(PROJECTOR_DSN, done) == "committed"
    assert projector.resolve(PROJECTOR_DSN, dict(done, note_id=str(uuid.uuid4()))) == "conflict"
    assert len(notes(action)) == 1


@pytest.mark.parametrize("prelude", [
    None,                                                                    # unpinned direct DML
    "SELECT 1 FROM voalack.recovery_epoch WHERE false FOR SHARE",            # zero-row locking SELECT
    "LOCK TABLE voalack.recovery_epoch IN ROW SHARE MODE",                   # relation lock masquerade
    "LOCK TABLE voalack.recovery_epoch IN EXCLUSIVE MODE",
    "SAVEPOINT s; SELECT voalack._pin_epoch(); ROLLBACK TO SAVEPOINT s",     # a pin rolled back
    "SELECT set_config('voalack.epoch_pin', '1', true)",                    # a marker of another transaction
])
def test_event_needs_the_epoch_row_pinned_by_this_transaction(client, app, instance, prelude):
    """D7.4 as corrected: a relation lock, a zero-row lock or a rolled-back pin is not a pin; the write
    and its event fail closed together."""
    effect_id = _effect(client, app, instance)
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        if prelude:
            cur.execute(prelude)
        with pytest.raises(psycopg2.errors.RaiseException, match="pinned the recovery epoch row first"):
            cur.execute("UPDATE voalack.effects SET state = 'BLOCKED' WHERE effect_id = %s", (effect_id,))
    assert sql("SELECT state FROM voalack.effects WHERE effect_id = %s", (effect_id,))[0][0] == "QUEUED"
    assert len(events(action_of(effect_id))) == 1


def test_the_pin_holds_the_epoch_row_until_commit(client, app, instance):
    """[native] After a pin, a close (FOR UPDATE on the row) waits until the pinning transaction ends."""
    _effect(client, app, instance)
    pinned = psycopg2.connect(DSN)
    try:
        pinned.cursor().execute("SELECT voalack._pin_epoch()")
        with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET lock_timeout = '300ms'")
            with pytest.raises(psycopg2.errors.LockNotAvailable):
                cur.execute("SELECT 1 FROM voalack.recovery_epoch FOR UPDATE")
    finally:
        pinned.close()


def test_same_transaction_changes_are_distinct_events_in_statement_order(client, app, instance, fake):
    """No coalescing: two state changes in one transaction are two consecutive revisions."""
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack._pin_epoch()")
        cur.execute("UPDATE voalack.effects SET state = 'UNCERTAIN' WHERE effect_id = %s", (effect_id,))
        cur.execute("UPDATE voalack.effects SET state = 'UNCERTAIN' WHERE effect_id = %s", (effect_id,))  # no change
        cur.execute("UPDATE voalack.effects SET state = 'BLOCKED' WHERE effect_id = %s", (effect_id,))
        cur.execute("SELECT txid_current()")
        txid = cur.fetchone()[0]
    evs = events(action)
    assert [(e["revision"], e["outcome"]) for e in evs] == [(1, "queued"), (2, "uncertain"), (3, "blocked")]
    assert evs[1]["txid"] == evs[2]["txid"] == txid and evs[1]["facts"]["prior_state"] == "QUEUED"
    assert "may have reached Veeam ONE" in evs[1]["note_text"]
    check_identities(action)


def test_rolled_back_change_leaves_no_event_and_no_revision(client, app, instance):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT voalack._pin_epoch()")
        cur.execute("UPDATE voalack.effects SET state = 'BLOCKED' WHERE effect_id = %s", (effect_id,))
        conn.rollback()
    assert [e["revision"] for e in events(action)] == [1]
    assert sql("SELECT last_revision FROM voalack.projection_actions WHERE action_id = %s", (action,))[0][0] == 1


# --- R3: settlement events in actual statement order --------------------------------------------------

def test_settlement_and_its_state_change_are_two_events_in_statement_order(client, app, instance, fake, drained):
    from test_t04_s3b_settlement import _wait_effects
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    owner = _owner(instance, fake)
    owner.transport.timeout = 0.5
    fake.script["delay"] = 1.5                                   # [fake] the ACK completes later
    result = owner.apply_once(effect_id)
    assert result["outcome"] == "uncertain", result
    assert _wait_effects(fake, 1)
    late = owner.reconcile(result["attempt_id"])
    assert late["settlement"] == "settled", late
    evs = events(action)
    assert [(e["revision"], e["outcome"]) for e in evs] == \
           [(1, "queued"), (2, "uncertain"), (3, "settled:confirmed_attributed"), (4, "confirmed")]
    assert evs[2]["txid"] == evs[3]["txid"]                      # one transaction, two labelled facts
    drain()
    assert [m["status"] for m in markers(action)] == ["projected"] * 4
    assert [n["id"] for n in notes(action)] == [e["note_id"] for e in evs]
    check_identities(action)


# --- charter clause 9, acceptance rows 34 and 37 -------------------------------------------------------

def test_a_failed_notes_write_retries_only_the_projection(client, app, instance, fake, drained):
    """Row 34: the remote ACK is confirmed and the notes write fails; the projection is retried later and
    nothing on the delivery side happens again (no attempt, ACK write, receipt or provider effect)."""
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    sent = (owner.transport.counts["ack_writes"], fake.counts["receipts"], fake.counts["effects"])
    attempts = sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0]
    sql("CREATE FUNCTION public.lab_fail_notes() RETURNS trigger LANGUAGE plpgsql AS "
        "$$ BEGIN RAISE EXCEPTION 'lab: notes write fails'; END; $$", fetch=False)
    sql("CREATE TRIGGER lab_fail_notes BEFORE INSERT ON public.notes FOR EACH ROW "
        "EXECUTE FUNCTION public.lab_fail_notes()", fetch=False)
    try:
        with projector.connect(PROJECTOR_DSN) as conn:
            for _ in range(3):
                with pytest.raises(psycopg2.errors.RaiseException, match="notes write fails"):
                    projector.step(conn, LAB_ANCHOR_DIR, NAME)
        assert markers(action) == [] and publications(action) == [] and notes(action) == []
    finally:
        sql("DROP TRIGGER IF EXISTS lab_fail_notes ON public.notes", fetch=False)
        sql("DROP FUNCTION IF EXISTS public.lab_fail_notes()", fetch=False)
    drain()
    assert [m["status"] for m in markers(action)] == ["projected", "projected"]
    assert (owner.transport.counts["ack_writes"], fake.counts["receipts"], fake.counts["effects"]) == sent
    assert sql("SELECT count(*) FROM voalack.attempts WHERE effect_id = %s", (effect_id,))[0][0] == attempts
    assert owner.apply_once(effect_id)["reason"] == "effect_not_queued"          # never resent


def test_a_projected_note_reentering_alerta_creates_no_intent(client, app, instance, fake, drained):
    """Row 37 and clause 9: the projected note is written without Alerta's routes or hooks; the same text
    sent back through Alerta's note route and as an action text creates no capture, intent or event."""
    from conftest import OPERATOR, basic
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    alert_id = sql("SELECT alert_id FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0][0]
    drain()
    text = notes(action)[0]["text"]
    counts = lambda: sql("SELECT (SELECT count(*) FROM voalack.prepared_intents WHERE alert_id = %s), "  # noqa: E731
                         "(SELECT count(*) FROM voalack.captures WHERE alert_id = %s), "
                         "(SELECT count(*) FROM voalack.outcome_events WHERE action_id = %s)",
                         (alert_id, alert_id, action))[0]
    before = counts()
    r = client.put(f"/alert/{alert_id}/note", json={"text": text}, headers=basic(OPERATOR))
    assert r.status_code in (200, 201), r.get_data(as_text=True)
    r = client.put(f"/alert/{alert_id}/action", json={"action": "close", "text": text}, headers=basic(OPERATOR))
    assert counts() == before
    drain()
    assert len(notes(action)) == 1 and [m["status"] for m in markers(action)] == ["projected"]


def test_two_projectors_on_one_action_publish_in_order(client, app, instance, fake, drained):
    """[native] Two projectors race on an action with no position row yet: the second waits on the first's
    uncommitted position creation, then publishes only the next revision; never an older note later."""
    import threading
    import time
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    owner = _owner(instance, fake)
    assert owner.apply_once(effect_id)["outcome"] == "confirmed"
    head = lab_anchor().head()
    first = psycopg2.connect(PROJECTOR_DSN)
    out = {}

    def second():
        with psycopg2.connect(PROJECTOR_DSN) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", ("second", head.epoch, head.sha256))
            out["second"] = dict(cur.fetchone())
    try:
        cur = first.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", ("first", head.epoch, head.sha256))
        assert dict(cur.fetchone())["revision"] == 1
        thread = threading.Thread(target=second)
        thread.start()
        for _ in range(100):
            waiting = sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                          "WHERE NOT l.granted AND a.usename = 'lab_projector'")[0][0]
            if waiting:
                break
            time.sleep(0.05)
        assert waiting, "the second projector did not wait on the first's position"
        first.commit()
        thread.join(10)
    finally:
        first.close()
    assert (out["second"]["revision"], out["second"]["status"]) == (2, "projected")
    assert [(m["revision"], m["projector"]) for m in markers(action)] == [(1, "first"), (2, "second")]
    assert [n["id"] for n in notes(action)] == [e["note_id"] for e in events(action)]


def test_locked_candidates_never_hide_a_later_action(client, app, instance, drained):
    """Bot finding (PR review): pending actions locked by other projectors must not hide a later unlocked
    one, however many there are; with everything pending locked elsewhere the answer is 'busy', not
    'idle'. Positions exist (committed) before the locks, so the projector meets SKIP LOCKED, not an
    insert wait."""
    effect_ids = [_effect(client, app, instance) for _ in range(65)]
    actions = [action_of(e) for e in effect_ids]
    drain()                                                       # revision 1 projected; positions committed
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:     # 65 pending revision-2 events at once
        cur.execute("SELECT voalack._pin_epoch()")
        cur.execute("UPDATE voalack.effects SET state = 'BLOCKED' WHERE effect_id = ANY(%s)", (effect_ids,))
    order = [r[0] for r in sql("SELECT action_id::text FROM voalack.outcome_events WHERE action_id = ANY(%s::uuid[]) "
                               "AND revision = 2 ORDER BY event_id", (actions,))]
    assert len(order) == 65
    head = lab_anchor().head()
    blocker = psycopg2.connect(DSN)
    try:
        blocker.cursor().execute("SELECT 1 FROM voalack.projection_positions WHERE action_id = ANY(%s::uuid[]) "
                                 "FOR UPDATE", (order[:64],))     # the 64 oldest, held by "other projectors"
        with psycopg2.connect(PROJECTOR_DSN) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", (NAME, head.epoch, head.sha256))
            got = dict(cur.fetchone())
        assert (got["outcome"], str(got["action_id"]), got["revision"]) == ("done", order[64], 2), got
        with psycopg2.connect(PROJECTOR_DSN) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM voalack.project_next(%s, %s, %s)", (NAME, head.epoch, head.sha256))
            assert dict(cur.fetchone())["outcome"] == "busy"      # pending work exists, all locked elsewhere
    finally:
        blocker.close()
    assert drain()[-1]["outcome"] == "idle"
    assert all(len(notes(a)) == 2 for a in actions)


# -- coexistence 3a S2: legacy revisions project only on recorded operator authority, and say so --------------------

def _make_legacy(action):
    """[lab] The action's binding revision loses its recorded lifetime (a pre-migration legacy revision)."""
    rev = sql("SELECT binding_id, binding_revision FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0]
    with guard_bypassed("A1 legacy construction: binding_revisions_immutable toggled and restored"):  # S3a A1
        sql("ALTER TABLE voalack.binding_revisions DISABLE TRIGGER USER", fetch=False)
        try:
            sql("UPDATE voalack.binding_revisions SET alert_lifetime_id = NULL "
                "WHERE (binding_id, binding_revision) = (%s, %s)", rev, fetch=False)
        finally:
            sql("ALTER TABLE voalack.binding_revisions ENABLE TRIGGER USER", fetch=False)
    return rev


def test_an_unattested_legacy_event_stops_as_lifetime_unknown(client, app, instance, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    _make_legacy(action)
    drain()
    assert [(m["status"], m["detail"]) for m in markers(action)] == [("destination_conflict", "lifetime_unknown")]
    assert publications(action) == [] and notes(action) == []


def test_an_attested_legacy_event_projects_and_names_the_operator_authority(client, app, instance, drained):
    effect_id = _effect(client, app, instance)
    action = action_of(effect_id)
    rev = _make_legacy(action)
    alert_id = sql("SELECT alert_id FROM voalack.prepared_intents WHERE action_id = %s", (action,))[0][0]
    lifetime = sql("SELECT voalack.alert_open_lifetime(%s)", (alert_id,))[0][0]
    sql("SET ROLE voalack_admin; SELECT voalack.attest_legacy_revision(%s, %s, %s, 'lab-operator', 'lab basis')",
        (rev[0], rev[1], lifetime), fetch=False)
    drain()
    got = markers(action)
    assert got and all(m["status"] == "projected" for m in got), got
    assert all(m["detail"].startswith("lifetime by operator attestation: lab-operator at ") for m in got), got
    assert len(publications(action)) == len(got)
