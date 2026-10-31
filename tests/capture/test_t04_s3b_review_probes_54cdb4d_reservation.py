"""Independent review witness: a real SQL fence refusal after the first live check."""
from test_t04_s2_sender import fake, instance
from test_t04_s3b_settlement import _uncertain
from conftest import sql


def test_native_reservation_owner_fence_latches_local_stop(client, app, instance, fake):
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake)
    original = owner._owner_call
    before = dict(fake.counts)
    def call(statement, args):
        if 'begin_reconciliation(' in statement:
            # Real administrator transition in the interval after _fence committed,
            # before begin_reconciliation acquires and checks the owner row.
            sql("UPDATE voalack.session_owners SET state = 'suspended' WHERE instance_id = %s",
                (instance,), fetch=False)
        return original(statement, args)
    owner._owner_call = call
    result = owner.reconcile(attempt_id)
    assert result.get('reservation') == 'owner_fenced', result
    assert fake.counts == before
    assert sql("SELECT state, in_flight_attempt::text FROM voalack.effects WHERE effect_id = %s",
               (effect_id,))[0] == ('UNCERTAIN', attempt_id)
    assert sql("SELECT state FROM voalack.target_guards WHERE attempt_id = %s", (attempt_id,)) == [('uncertain',)]
    assert owner.stopped is not None, (result, owner.stopped)
