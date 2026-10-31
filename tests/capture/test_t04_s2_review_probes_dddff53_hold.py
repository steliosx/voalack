"""Native DB loss in the best-effort hold path; scripted scheduling wrapper only."""
import hashlib,json,threading,time
from pathlib import Path
import psycopg2
from conftest import DSN,sql
from test_t04_s2_sender import instance,fake,_effect,_owner
from voalack.sender import OwnerStopped

Path('/out/executed-probe-sha256.txt').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()+'\n')

def test_native_hold_backend_loss_stops_whole_owner(client,app,instance,fake):
    effect=_effect(client,app,instance)
    owner=_owner(instance,fake,hooks={'before_send':lambda _: sql("DELETE FROM voalack.accepted_kids WHERE kid = 'lab-k1'",fetch=False)})
    original=owner._hold
    observations=[]
    def hold(attempt,reason):
        blocker=psycopg2.connect(DSN)
        cur=blocker.cursor()
        cur.execute('SELECT 1 FROM voalack.attempts WHERE attempt_id = %s FOR UPDATE',(attempt,))
        errors=[]
        def terminate():
            try:
                limit=time.monotonic()+1.5
                while time.monotonic()<limit:
                    rows=sql("SELECT pid,query,wait_event_type,wait_event FROM pg_stat_activity WHERE usename='lab_sender' AND position('hold_attempt' in query)>0 AND %s=ANY(pg_blocking_pids(pid))",(blocker.get_backend_pid(),))
                    if rows:
                        observations.append(rows[0])
                        sql('SELECT pg_terminate_backend(%s)',(rows[0][0],))
                        return
                    time.sleep(.01)
                errors.append('hold SQL backend wait not observed')
            except BaseException as exc:
                errors.append(repr(exc))
        worker=threading.Thread(target=terminate);worker.start()
        try:
            original(attempt,reason)
        finally:
            worker.join(5);blocker.rollback();blocker.close()
        assert not worker.is_alive() and not errors,errors
        assert observations and observations[0][2]=='Lock',observations
    owner._hold=hold
    try:
        result=owner.apply_once(effect)
    finally:
        sql("INSERT INTO voalack.accepted_kids VALUES ('lab-k1') ON CONFLICT DO NOTHING",fetch=False)
    stopped_after_failure=owner.stopped
    try:
        owner.revoke()
    except OwnerStopped:
        pass
    state=sql('SELECT a.state,a.permit_state,o.state FROM voalack.attempts a JOIN voalack.session_owners o USING(instance_id) WHERE a.attempt_id=%s',(result['attempt_id'],))
    evidence=dict(result=result,local_stop_at_hold_return=stopped_after_failure,native_wait=observations,attempt_owner_state=state,dispatch=owner.counts,transport=owner.transport.counts,provider=fake.counts)
    Path('/out/hold-witness.json').write_text(json.dumps(evidence,default=str,indent=2)+'\n')
    assert stopped_after_failure is not None,evidence
    assert owner.transport.counts['revokes']==fake.counts['revokes']==0,evidence
