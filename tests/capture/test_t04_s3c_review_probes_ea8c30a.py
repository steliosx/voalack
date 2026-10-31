"""Independent exact-ea8c30a probes; PostgreSQL waits native, provider synthetic.

Assertions express R4/R6 secure boundary behavior, not existing implementation.
The immutable submitted source and submitted tests are unchanged.
"""
import os
import threading
import time

import psycopg2
import pytest

from test_t04_s2_sender import _effect, fake, instance
from test_t04_s3c_recovery import _owner, _q, sibling
from test_t04_s3c_restore import _close_and_inventory, _restore_and_recover, _reopen, _staged_restore_and_recover
from voalack.recovery import Anchor, Supervisor
from voalack.sender import OwnerStopped


def _lock(sib, instance):
    conn = psycopg2.connect(sib.dsn)
    conn.cursor().execute("SELECT 1 FROM voalack.session_owners WHERE instance_id=%s FOR UPDATE", (instance,))
    return conn


def _wait(sib, statement):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        count = _q(sib.dsn, "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                   "AND usename='lab_sender' AND wait_event_type='Lock' AND query LIKE %s", ('%' + statement + '%',))[0][0]
        if count == 1:
            return
        time.sleep(.01)
    raise AssertionError('native PostgreSQL waiter not observed: ' + statement)


def _close_anchor(sib):
    head = Anchor(sib.anchor).head()
    return Supervisor(sib.anchor).append((head.seq, head.sha256), 'closed')


@pytest.mark.parametrize('close', [False, True])
def test_login_rechecks_external_close_after_native_epoch_wait(app, instance, fake, sibling, close):
    sib = sibling()
    owner = _owner(sib, instance, fake)
    locker = psycopg2.connect(sib.dsn)
    locker.cursor().execute('SELECT 1 FROM voalack.recovery_epoch FOR UPDATE')
    result = {}
    def login():
        try:
            owner.login()
            result['outcome'] = 'logged_in'
        except OwnerStopped as exc:
            result['outcome'] = str(exc)
        except BaseException as exc:
            result['error'] = repr(exc)
    worker = threading.Thread(target=login)
    worker.start()
    try:
        _wait(sib, 'check_owner')
        if close:
            _close_anchor(sib)             # fsynced close, SQL close not yet completed
    finally:
        locker.commit()
        locker.close()
    worker.join(3)
    assert not worker.is_alive() and 'error' not in result, result
    print('LOGIN_NATIVE_WAIT', result, owner.transport.counts, fake.counts, flush=True)
    assert owner.transport.counts['logins'] == (0 if close else 1), (result, owner.transport.counts)
    assert owner.stopped == ('anchor_changed' if close else None)


@pytest.mark.parametrize('close_anchor', [False, True])
def test_ack_rechecks_external_close_after_postconnect_native_wait(client, app, instance, fake, sibling, close_anchor):
    effect = _effect(client, app, instance)
    sib = sibling()
    result = {}
    closer = []
    def after_connect(connection):
        locker = _lock(sib, instance)
        def close():
            try:
                _wait(sib, 'check_dispatch')
                if close_anchor:
                    _close_anchor(sib)
                result['native_wait_and_close'] = True
            except BaseException as exc:
                result['error'] = repr(exc)
            finally:
                locker.commit()
                locker.close()
        thread = threading.Thread(target=close)
        closer.append(thread)
        thread.start()
    owner = _owner(sib, instance, fake, hooks={'after_connect': after_connect}, handoff_bound=10)
    sent = owner.apply_once(effect)
    for thread in closer:
        thread.join(3)
        assert not thread.is_alive()
    assert result.get('native_wait_and_close') and 'error' not in result, result
    print('ACK_POSTCONNECT_NATIVE_WAIT', sent, owner.counts, owner.transport.counts,
          owner.transport.phase_counts, fake.counts, flush=True)
    assert owner.transport.counts['ack_writes'] == (0 if close_anchor else 1) and fake.counts['receipts'] == (0 if close_anchor else 1), sent
    assert (sent['outcome'], sent['reason']) == (('held', 'anchor_changed') if close_anchor else ('confirmed', 'fake_ack'))


@pytest.mark.parametrize('document', ['inventory', 'review'])
def test_open_anchor_retains_document_dependency(client, app, instance, fake, sibling, document):
    effect = _effect(client, app, instance)
    sib = sibling()
    prior = _owner(sib, instance, fake)
    sha = _close_and_inventory(sib, instance, fake, [prior])
    _restore_and_recover(sib, sha)           # no restore: ordinary untouched queued work is eligible
    _reopen(sib, instance, fake)
    fresh = _owner(sib, instance, fake, owner_id='review-fresh')
    name = next(name for name in os.listdir(sib.anchor) if name.startswith(document + '-'))
    os.unlink(os.path.join(sib.anchor, name))
    try:
        sent = fresh.apply_once(effect)
    except OwnerStopped as exc:
        sent = {'outcome': 'stopped', 'reason': str(exc)}
    print('OPEN_MISSING_INVENTORY', sent, fresh.transport.counts, fake.counts, flush=True)
    assert fresh.transport.counts['ack_writes'] == 0 and fake.counts['receipts'] == 0, sent
    assert fresh.stopped == 'anchor_changed'


def test_s3a_staged_two_restores_preserve_frozen_holder_proof(client, app, instance, fake, sibling, tmp_path):
    from test_t04_s3c_restore import _holds
    effect = _effect(client, app, instance)
    sib = sibling()
    dump = tmp_path / 'before-dispatch.dump'
    sib.dump(dump)
    original = _owner(sib, instance, fake)
    fake.script['ack'] = 'close_after_body'
    assert original.apply_once(effect)['outcome'] == 'uncertain'
    fake.script['ack'] = 'success'
    first_sha = _close_and_inventory(sib, instance, fake, [original])
    # Coexistence 3a S3a staged conversion (reviewer decision c34fa527): the steps above are unchanged; the
    # backup-bound recover is refused as staged. The original post-recovery oracles (at f2395b2a) are an
    # explicit S3c debt, re-proved with the admitted restore there; not current-3a recovery qualification.
    _staged_restore_and_recover(sib, first_sha, dump, fake=fake)


