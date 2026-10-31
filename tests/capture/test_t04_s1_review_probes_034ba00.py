"""Independent synthetic S1 correction probes; execute only in disposable smolvm."""
import pytest
import psycopg2
from conftest import sql, VERIFIER_DSN
from voalack import verifier
from test_t04_s1_corrections import (_captured, _verify, _effects, _paused, _verify_in_thread,
                                    _wait_until, _blocked_by, _release)


@pytest.mark.parametrize('case,drift,restore', [
    ('column_update', 'GRANT UPDATE (state) ON voalack.effects TO voalack_verifier',
     'REVOKE UPDATE (state) ON voalack.effects FROM voalack_verifier'),
    ('replica_only_immutability', 'ALTER TABLE voalack.verifications ENABLE REPLICA TRIGGER verifications_immutable',
     'ALTER TABLE voalack.verifications ENABLE TRIGGER verifications_immutable'),
    ('partial_effect_uniqueness',
     "ALTER TABLE voalack.effects DROP CONSTRAINT effects_effect_key_key; "
     "CREATE UNIQUE INDEX lab_partial_effect_key ON voalack.effects(effect_key) WHERE state = 'REMOTE_CONFIRMED'",
     'DROP INDEX voalack.lab_partial_effect_key; ALTER TABLE voalack.effects ADD CONSTRAINT effects_effect_key_key UNIQUE(effect_key)'),
])
def test_readiness_refuses_weakened_protections_before_claim(client, app, case, drift, restore):
    _, action_id = _captured(client)
    sql(drift, fetch=False)
    try:
        with psycopg2.connect(VERIFIER_DSN) as conn:
            refused = False
            try:
                verifier.check_ready(conn)
            except verifier.NotReady:
                refused = True
        print('READINESS_DRIFT', case, 'refused', refused)
        # Prove the changed UPDATE capability is effective for the actual runtime role.
        if case == 'column_update' and not refused:
            result = _verify(app, action_id)
            with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
                cur.execute("UPDATE voalack.effects SET state='REMOTE_CONFIRMED' WHERE action_id=%s", (action_id,))
                assert cur.rowcount == 1
            print('DIRECT_EFFECT_WRITE', _effects(action_id), result)
        assert refused, (case, 'unsupported catalog accepted')
    finally:
        sql(restore, fetch=False)


def test_capture_changed_during_promotion_is_not_committed(client, app):
    _, action_id = _captured(client)
    gate = 73900401
    with _paused('effects', gate) as holder:
        worker, box = _verify_in_thread(app, action_id)
        assert _wait_until(lambda: _blocked_by(holder.get_backend_pid())), box
        # Promotion has consumed its fingerprint; insertion is now paused on the lab advisory lock.
        sql("UPDATE voalack.captures SET history_text='synthetic changed during promotion' WHERE action_id=%s",
            (action_id,), fetch=False)
        _release(holder, gate)
        worker.join(20)
    assert not worker.is_alive() and 'error' not in box, box
    print('CAPTURE_CHANGED_AT_PROMOTION', box, _effects(action_id))
    assert box['result']['outcome'] != 'verified' and _effects(action_id) == [], box
