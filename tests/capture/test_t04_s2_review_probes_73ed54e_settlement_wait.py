"""Observe actual PostgreSQL blocking at the final configuration settlement fence."""
import hashlib,json,threading,time
from pathlib import Path
import psycopg2
from conftest import DSN,sql
from test_t04_s2_sender import instance,fake,_effect,_owner,_attempt,_effect_state,_guards,_counts,_no_new_network
from voalack.sender import OwnerStopped
import pytest
Path('/out/settlement-wait-probe-sha256.txt').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()+'\n')

def test_actual_settlement_configuration_wait_and_aba_stop(client,app,instance,fake):
    effect=_effect(client,app,instance)
    admin=psycopg2.connect(DSN)
    state={'wait':None,'errors':[]}
    holder={}
    def before_record(_):
        admin.cursor().execute('UPDATE voalack.instance_config SET config_revision=2 WHERE instance_id=%s',(instance,))
        backend=holder['owner']._db().get_backend_pid()
        blocker=admin.get_backend_pid()
        def observe_and_commit():
            try:
                with psycopg2.connect(DSN) as observer:
                    observer.autocommit=True
                    deadline=time.monotonic()+8
                    while time.monotonic()<deadline:
                        with observer.cursor() as c:
                            c.execute('SELECT wait_event_type,wait_event,query,pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid=%s',(backend,))
                            row=c.fetchone()
                        if row and row[0]=='Lock' and blocker in row[3] and 'voalack.record_result' in row[2]:
                            state['wait']={'backend':backend,'blocker':blocker,'wait_event_type':row[0],'wait_event':row[1],'query':row[2],'blocking_pids':row[3]}
                            break
                        time.sleep(0.02)
                    if state['wait'] is None:state['errors'].append('Settlement configuration lock wait not observed')
            except Exception as exc:state['errors'].append(type(exc).__name__+': '+str(exc))
            finally:admin.commit()
        t=threading.Thread(target=observe_and_commit)
        holder['thread']=t;t.start()
    owner=holder['owner']=_owner(instance,fake,hooks={'before_record':before_record})
    try:
        result=owner.apply_once(effect)
        holder['thread'].join(10)
        assert not holder['thread'].is_alive()
    finally:admin.close()
    witness={'wait':state,'result':result,'local_stop':owner.stopped,'attempt':_attempt(result['attempt_id']),
             'effect':_effect_state(effect),'guards':_guards(instance),
             'evidence':sql('SELECT kind,detail FROM voalack.attempt_evidence WHERE attempt_id=%s ORDER BY evidence_id',(result['attempt_id'],)),
             'counts':{'dispatch':dict(owner.counts),'transport':dict(owner.transport.counts),'provider':dict(fake.counts)}}
    Path('/out/settlement-native-wait.json').write_text(json.dumps(witness,default=str,indent=2)+'\n')
    assert state['wait'] and not state['errors'],witness
    assert (result['outcome'],result['reason'])==('held','config_changed') and owner.stopped=='config_changed',witness
    assert witness['attempt']==('uncertain','consumed') and witness['effect']==('UNCERTAIN',True) and witness['guards']==[('4711','uncertain')],witness
    assert [row[0] for row in witness['evidence']]==['late_result'],witness
    assert _counts(owner,fake)==(1,1,1,1),witness
    sql('UPDATE voalack.instance_config SET config_revision=1 WHERE instance_id=%s',(instance,),fetch=False)
    before=(dict(owner.transport.counts),dict(fake.counts))
    with pytest.raises(OwnerStopped):owner.apply_once(effect)
    _no_new_network(owner,fake,before)
    witness['aba_network_unchanged']=before==(dict(owner.transport.counts),dict(fake.counts))
    Path('/out/settlement-native-wait.json').write_text(json.dumps(witness,default=str,indent=2)+'\n')
