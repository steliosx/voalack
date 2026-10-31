"""Native idempotent start wait crossing the original exclusive deadline."""
import dataclasses,hashlib,json,threading,time,uuid
from datetime import timedelta
from pathlib import Path
import psycopg2,psycopg2.extras
from conftest import DSN,SENDER_DSN,sql
from test_t04_s2_sender import instance,fake,_effect,_owner,_call
Path('/out/executed-probe-sha256.txt').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()+'\n')

def test_idempotent_start_rechecks_deadline_after_native_wait(client,app,instance,fake):
    signing=app.extensions['voalack_signing']
    app.extensions['voalack_signing']=dataclasses.replace(signing,capture_window=timedelta(seconds=1),execution_window=timedelta(milliseconds=1500))
    try:effect=_effect(client,app,instance)
    finally:app.extensions['voalack_signing']=signing
    owner=_owner(instance,fake)
    args=(str(uuid.uuid4()),effect,instance,owner.generation,owner.incarnation)
    statement='SELECT * FROM voalack.start_attempt(%s,%s,%s,%s,%s)'
    first=_call(statement,args);assert first['outcome']=='started',first
    positive=_call(statement,args);assert positive==first,(positive,first)
    deadline=sql('SELECT p.execution_expires_at FROM voalack.effects e JOIN voalack.prepared_intents p USING(action_id) WHERE e.effect_id=%s',(effect,))[0][0]
    blocker=psycopg2.connect(DSN);cur=blocker.cursor();cur.execute('SELECT 1 FROM voalack.effects WHERE effect_id=%s FOR UPDATE',(effect,))
    conn=psycopg2.connect(SENDER_DSN,connect_timeout=2,options='-c lock_timeout=2000 -c statement_timeout=10000');pid=conn.get_backend_pid();result={};errors=[]
    def start():
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute(statement,args);result.update(c.fetchone());conn.commit()
        except BaseException as exc:errors.append(repr(exc))
    worker=threading.Thread(target=start);worker.start();blocked=[]
    try:
        limit=time.monotonic()+1
        while time.monotonic()<limit:
            blocked=sql('SELECT query,wait_event_type,wait_event FROM pg_stat_activity WHERE pid=%s AND %s=ANY(pg_blocking_pids(pid))',(pid,blocker.get_backend_pid()))
            if blocked:break
            time.sleep(.01)
        assert blocked and blocked[0][1]=='Lock',blocked
        while not sql('SELECT clock_timestamp()>%s',(deadline,))[0][0]:time.sleep(.01)
        blocker.rollback();worker.join(5);assert not worker.is_alive() and not errors,errors
        evidence=dict(initial=first,positive_same_id=positive,result=result,deadline=deadline,observed_wait=blocked,finished_at=sql('SELECT clock_timestamp()')[0][0],transport=owner.transport.counts,provider=fake.counts)
        Path('/out/start-witness.json').write_text(json.dumps(evidence,default=str,indent=2)+'\n')
        assert result['outcome']=='expired',evidence
        assert owner.transport.counts=={'ack_writes':0,'logins':0,'reads':0,'revokes':0},evidence
    finally:
        blocker.rollback();blocker.close();worker.join(5);conn.close()
