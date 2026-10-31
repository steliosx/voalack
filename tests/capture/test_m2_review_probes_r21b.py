"""Independent first-install verification-helper provenance check; synthetic guest only."""
import json
import subprocess
import sys

import pytest
from conftest import CONFIG, OPERATOR, captures, intents, new_alert, status

CHILD = r'''
import json,sys
import alerta.app
from conftest import CONFIG, OPERATOR, ack, captures, intents, status
original_factory = alerta.app.create_app
replace = sys.argv[1] == 'replace'
if replace:
    def factory(*args, **kwargs):
        app = original_factory(*args, **kwargs)
        from alerta.models.user import User
        # An unsupported authentication extension installed before Voalack's first install.
        # It looks up the account but performs no password verification.
        User.check_credentials = staticmethod(lambda username, password: User.find_by_username(username))
        return app
    alerta.app.create_app = factory
from voalack.boundary import create_app
try:
    app = create_app(config_override=CONFIG)
except RuntimeError as exc:
    print('AUTH_OUTCOME ' + json.dumps({'startup_refused': True, 'reason_type': type(exc).__name__}))
    sys.exit(0)
with app.test_client() as client:
    who = OPERATOR if sys.argv[2] == 'valid' else (OPERATOR[0], 'definitely-not-the-password')
    r = ack(client, sys.argv[3], who=who)
    print('AUTH_OUTCOME ' + json.dumps({'startup_refused': False, 'http': r.status_code,
        'status': status(sys.argv[3])[0], 'captures': captures(sys.argv[3]), 'intents': intents(sys.argv[3])}))
'''


@pytest.mark.parametrize('mode,password', [('original','valid'), ('original','invalid'), ('replace','invalid')])
def test_first_install_qualifies_the_original_verifier(client, mode, password):
    alert_id = new_alert(client)
    process = subprocess.run([sys.executable, '-c', CHILD, mode, password, alert_id],
        text=True, capture_output=True, timeout=45)
    assert process.returncode == 0, (process.stdout, process.stderr)
    lines = [line.removeprefix('AUTH_OUTCOME ') for line in process.stdout.splitlines() if line.startswith('AUTH_OUTCOME ')]
    assert len(lines) == 1, (process.stdout, process.stderr)
    outcome = json.loads(lines[0])
    print('FIRST_INSTALL_AUTH', mode, password, outcome)
    if password == 'valid':
        assert outcome == {'startup_refused': False, 'http': 200, 'status': 'ack', 'captures': 1, 'intents': 1}
    elif not outcome['startup_refused']:
        assert outcome['http'] >= 400, outcome
        assert outcome['status'] == 'open' and outcome['captures'] == outcome['intents'] == 0, outcome
