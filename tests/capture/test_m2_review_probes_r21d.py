"""Independent verification-time direct dependency substitutions; synthetic guest only."""
import pytest
import bcrypt
from conftest import OPERATOR, ack, basic, captures, intents, new_alert, status
from voalack import intent


@pytest.mark.parametrize('branch,bypass', [('basic',False), ('basic',True), ('jwt',False), ('jwt',True)])
def test_invalid_credentials_do_not_become_verified_via_changed_dependency(client, app, monkeypatch, branch, bypass):
    alert_id = new_alert(client)
    if branch == 'basic':
        headers = basic((OPERATOR[0], 'definitely-not-the-password'))
        if bypass:
            original_checkpw = bcrypt.checkpw
            def self_restoring_checkpw(password, stored_hash):
                bcrypt.checkpw = original_checkpw
                return True
            monkeypatch.setattr(bcrypt, 'checkpw', self_restoring_checkpw)
    else:
        from alerta.models import token as token_module
        token = client.post('/auth/login', json={'username':OPERATOR[0], 'password':OPERATOR[1]}).get_json()['token']
        parts = token.split('.')
        # Flip the first signature character, retaining the entire valid claims payload.
        parts[2] = ('A' if parts[2][0] != 'A' else 'B') + parts[2][1:]
        headers = {'Authorization':'Bearer ' + '.'.join(parts)}
        if bypass:
            original_decode = token_module.jwt.decode
            def unchecked_decode(*args, **kwargs):
                token_module.jwt.decode = original_decode
                options = dict(kwargs.get('options') or {})
                options['verify_signature'] = False
                kwargs['options'] = options
                return original_decode(*args, **kwargs)
            monkeypatch.setattr(token_module.jwt, 'decode', unchecked_decode)
    # The added four helper/wrapper identity checks still pass in the unsupported configuration.
    assert intent.recorders_in_place()
    r = client.put(f'/alert/{alert_id}/action', json={'action':'ack', 'text':'synthetic dependency witness'}, headers=headers)
    outcome = (r.status_code, status(alert_id)[0], captures(alert_id), intents(alert_id))
    print('VERIFICATION_TIME_AUTH', branch, bypass, outcome, intent.dependencies_in_place())
    assert r.status_code >= 400, outcome
    assert outcome[1:] == ('open',0,0), outcome
