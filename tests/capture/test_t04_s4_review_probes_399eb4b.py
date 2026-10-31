"""Independent native S4 review probes at exact 399eb4b; product executes only in smolvm."""
import threading
import time
import psycopg2
import pytest
from conftest import APP_DSN, DSN, LAB_ANCHOR_DIR
from test_t04_s2_sender import _effect, instance
from test_t04_s3c_restore import _capture
from test_t04_s3c_recovery import sibling, _q
from test_t04_s4_recovery import _verify
from test_t04_s4_projection import drained, PROJECTOR_DSN, NAME, lab_anchor, action_of, notes
from voalack import projector

@pytest.mark.parametrize("change", ["missing", "altered"])
def test_unknown_commit_resolution_requires_the_bound_note(client, app, instance, drained, change):
    effect = _effect(client, app, instance)
    action = action_of(effect)
    with projector.connect(PROJECTOR_DSN) as conn:
        done = projector.step(conn, LAB_ANCHOR_DIR, NAME)
    assert done["action_id"] == action and done["status"] == "projected"
    assert projector.resolve(PROJECTOR_DSN, done) == "committed"
    with psycopg2.connect(APP_DSN) as conn, conn.cursor() as cur:
        if change == "missing":
            cur.execute("DELETE FROM public.notes WHERE id = %s", (done["note_id"],))
        else:
            cur.execute("UPDATE public.notes SET text = text || ' (changed)' WHERE id = %s", (done["note_id"],))
    with projector.connect(PROJECTOR_DSN) as conn:
        status = projector.status(conn, action)
    assert status["latest_publication"]["display"] == change
    assert status["current"] is None
    # D4 requires a fresh positive read of event, protected publication, marker and note.
    assert projector.resolve(PROJECTOR_DSN, done) == "conflict"


def test_verifier_waiting_for_epoch_has_not_locked_originals(client, app, instance, sibling):
    action = _capture(client, instance)
    sib = sibling()
    out = {}
    blocker = psycopg2.connect(sib.dsn)
    cur = blocker.cursor()
    # Positive control: the original is available before starting the verifier.
    cur.execute("SELECT action_id FROM voalack.prepared_intents WHERE action_id = %s FOR UPDATE NOWAIT", (action,))
    blocker.rollback()
    cur.execute("SELECT * FROM voalack.recovery_epoch FOR UPDATE")
    def run():
        try:
            out["result"] = _verify(app, sib, action)
        except Exception as exc:
            out["error"] = repr(exc)
    thread = threading.Thread(target=run)
    thread.start()
    waiting = 0
    locked_original = False
    try:
        for _ in range(100):
            waiting = _q(sib.dsn, "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE NOT l.granted AND a.usename = 'lab_verifier'")[0][0]
            if waiting:
                break
            time.sleep(0.02)
        assert waiting, out
        cur.execute("SAVEPOINT lock_probe")
        try:
            cur.execute("SELECT action_id FROM voalack.prepared_intents WHERE action_id = %s FOR UPDATE NOWAIT", (action,))
        except psycopg2.errors.LockNotAvailable:
            locked_original = True
        finally:
            cur.execute("ROLLBACK TO SAVEPOINT lock_probe")
    finally:
        blocker.rollback()
        blocker.close()
        thread.join(10)
    assert not thread.is_alive(), out
    assert out["result"]["outcome"] == "verified", out
    assert not locked_original, "record_verification locked the original before promote_effect could pin the epoch"

