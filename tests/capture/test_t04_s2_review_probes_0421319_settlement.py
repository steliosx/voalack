"""Independent native configuration transition before result settlement; fake HTTP contract."""
import hashlib,json
from pathlib import Path
import pytest
from conftest import sql
from test_t04_s2_sender import instance,fake,_effect,_owner,_attempt,_effect_state,_guards

Path('/out/settlement-probe-sha256.txt').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()+'\n')

@pytest.mark.parametrize('change',['unchanged','revision','credential'])
def test_original_session_result_cannot_settle_after_config_change(client,app,instance,fake,change):
    effect=_effect(client,app,instance)
    def change_config(_):
        if change=='revision':
            sql('UPDATE voalack.instance_config SET config_revision=2 WHERE instance_id=%s',(instance,),fetch=False)
        elif change=='credential':
            sql('UPDATE voalack.instance_config SET credential_ref=%s WHERE instance_id=%s',('rotated-'+instance,instance),fetch=False)
    owner=_owner(instance,fake,hooks={'before_record':change_config})
    result=owner.apply_once(effect)
    evidence={'change':change,'result':result,'local_stop':owner.stopped,
              'attempt':_attempt(result['attempt_id']),'effect':_effect_state(effect),'guards':_guards(instance),
              'owner_state':sql('SELECT state,bound_credential_ref,bound_config_revision FROM voalack.session_owners WHERE instance_id=%s',(instance,)),
              'current_config':sql('SELECT credential_ref,config_revision FROM voalack.instance_config WHERE instance_id=%s',(instance,)),
              'evidence':sql('SELECT kind,detail FROM voalack.attempt_evidence WHERE attempt_id=%s ORDER BY evidence_id',(result['attempt_id'],)),
              'dispatch':dict(owner.counts),'transport':dict(owner.transport.counts),'provider':dict(fake.counts)}
    Path('/out/settlement-'+change+'.json').write_text(json.dumps(evidence,default=str,indent=2)+'\n')
    assert owner.counts['dispatch_entries']==owner.transport.counts['ack_writes']==fake.counts['receipts']==fake.counts['effects']==1,evidence
    assert owner.transport.counts['reads']==fake.counts['reads']==2,evidence
    if change=='unchanged':
        assert result['outcome']=='confirmed' and evidence['attempt']==('confirmed','consumed') and evidence['effect']==('REMOTE_CONFIRMED',False),evidence
    else:
        # Original already-issued result may be evidence; changed configuration grants no stale settlement.
        assert result['outcome']!='confirmed',evidence
        assert evidence['attempt']!=('confirmed','consumed') and evidence['effect']!=('REMOTE_CONFIRMED',False),evidence
        assert evidence['guards'],evidence
        assert owner.stopped=='config_changed',evidence
