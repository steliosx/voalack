"""Independent original S3a source-concern probe, exact cf8b55a.
Native PostgreSQL commits/state and kernel connect refusal; ACK-only port routing and
lost commit acknowledgement are scripted. Containment is trusted lab evidence after
zero ACK bytes; new OwnerSession models fresh incarnation, not a separate OS process.
"""
import hashlib
import json
import time
from pathlib import Path

import pytest
from conftest import sql
from test_t04_s2_sender import (_effect, _owner, _contain, fake, instance)
from test_t04_s3a_transport import _refuse_ack_connects, _phase
from voalack.sender import UnknownCommit


def _record(name, values):
    Path('/out/' + name + '.json').write_text(json.dumps(values, indent=2, default=str) + '\n')


@pytest.mark.parametrize('mode', ['commit_then_unknown', 'known_then_reconstruct', 'rollback_then_unknown'])
def test_reconstructed_owner_does_not_inherit_retry(client, app, instance, fake, mode):
    effect = _effect(client, app, instance)
    def lost_ack(conn):
        if mode == 'commit_then_unknown':
            conn.commit()  # native SQL COMMIT happened; only its acknowledgement is hidden
        else:
            conn.rollback()
        raise UnknownCommit('scripted lost settlement acknowledgement')
    hooks = {} if mode == 'known_then_reconstruct' else {'commit:not_sent': lost_ack}
    original = _owner(instance, fake, hooks=hooks)
    refusal = _refuse_ack_connects(original, 1)
    original.hooks['before_send'] = refusal['before_send']
    first = original.apply_once(effect)
    refusal['restore']()
    initial = sql('SELECT state, attempt_count, in_flight_attempt, next_attempt_after FROM voalack.effects WHERE effect_id=%s', (effect,))[0]
    assert _phase(original, fake)['writes'] == 0
    if mode == 'known_then_reconstruct':
        assert first['outcome'] == 'not_sent'
        original.stop('lab reconstruction after known settlement')
    else:
        assert first['reason'] == 'unknown_not_sent_commit'
        assert original.stopped == 'unknown_not_sent_commit'
    _contain(instance, original.generation)
    successor = _owner(instance, fake, owner_id='independent-reconstructed')
    assert successor.incarnation != original.incarnation and successor.generation > original.generation
    if initial[3] is not None:
        # Wait for the protected persisted backoff, using the native server clock.
        while not sql('SELECT clock_timestamp() >= %s', (initial[3],))[0][0]:
            time.sleep(0.05)
    before = dict(fake.counts)
    result = successor.apply_once(effect)
    counts = _phase(successor, fake)
    attempts = sql('SELECT attempt_id, owner_generation, incarnation, state, permit_state FROM voalack.attempts WHERE effect_id=%s ORDER BY started_at', (effect,))
    _record('restart-' + mode, {'head':'cf8b55a801db568feb6f3e91394b3c97a60bf984', 'mode':mode, 'original_result':first,
         'initial_effect':initial, 'successor_result':result, 'successor_phase':counts,
         'successor_transport':successor.transport.counts, 'provider_before':before, 'provider_after':fake.counts,
         'attempts':attempts})
    assert result['outcome'] in ('refused', 'held'), result
    assert len(attempts) == 1, attempts
    assert counts['dispatch'] == counts['connects'] == counts['writes'] == 0, counts
    assert successor.transport.counts == {'ack_writes':0,'logins':0,'reads':0,'revokes':0}
    assert fake.counts == before


def test_original_live_known_commit_can_retry(client, app, instance, fake):
    effect = _effect(client, app, instance)
    owner = _owner(instance, fake)
    refusal = _refuse_ack_connects(owner, 1)
    owner.hooks['before_send'] = refusal['before_send']
    result = owner.apply_with_retry(effect)
    counts = _phase(owner, fake)
    _record('original-live-positive', {'result':result,'phase':counts,'transport':owner.transport.counts})
    assert result['outcome'] == 'confirmed', result
    assert counts == {'dispatch':2,'connects':2,'connect_failures':1,'writes':1,'receipts':1,'effects':1}


def test_probe_import_digest():
    raw=Path(__file__).read_bytes()
    Path('/out/independent-probe-import-digest.json').write_text(json.dumps({'file':__file__,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
