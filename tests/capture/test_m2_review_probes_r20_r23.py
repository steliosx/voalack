"""Independent exact-head M2 witnesses. Synthetic guest only; expected refusals assert zero durable ACK/capture."""
import dataclasses
import time
from datetime import timedelta

import pytest
from flask import g, request
from conftest import OPERATOR, ack, basic, captures, intents, new_alert, sql, status, user_id
from test_c3_transaction import _Hook
from test_m2_signing import _before_request, _signing


def refused(r, alert_id):
    assert r.status_code >= 400, r.get_data(as_text=True)
    assert status(alert_id)[0] == 'open'
    assert captures(alert_id) == 0 and intents(alert_id) == 0


def test_independent_positive(client):
    alert_id = new_alert(client)
    assert ack(client, alert_id).status_code == 200
    assert captures(alert_id) == intents(alert_id) == 1


@pytest.mark.parametrize('change', [
    "attributes = attributes || '{\"captureId\": \"other\"}'",
    "attributes = attributes || '{\"veeamAlarmCombinationId\": \"other\"}'",
    "value = 'Info'", "severity = 'minor'", "origin = 'other'", "resource = 'veeamone:other'",
])
def test_final_source_predicate_is_rechecked(client, faults, change):
    alert_id = new_alert(client)
    def rewrite(alert, action, text):
        g.db.cursor().execute('UPDATE public.alerts SET ' + change + ' WHERE id = %s', (alert_id,))
    faults('independent_source_rewrite', _Hook('independent_source_rewrite', post_action=rewrite))
    refused(ack(client, alert_id), alert_id)


def test_forged_auth_evidence_does_not_qualify_auth_proxy(client, app):
    alert_id = new_alert(client)
    operator_id = user_id(OPERATOR[0])
    def forge():
        if request.endpoint == 'api.action_alert':
            g.voalack_auth_records = [('basic', operator_id, OPERATOR[0])]
    app.config['AUTH_PROXY'] = True
    try:
        with _before_request(app, forge):
            r = client.put(f'/alert/{alert_id}/action', json={'action': 'ack', 'text': 'x'},
                headers={'X-Proxy-User': OPERATOR[0], 'X-Proxy-Roles': 'user'})
    finally:
        app.config['AUTH_PROXY'] = False
    refused(r, alert_id)


def test_original_auth_branch_cannot_be_relabelled_in_g(client, faults):
    alert_id = new_alert(client)
    def rewrite(alert, action, text):
        g.voalack['frozen']['auth_type'] = 'bearer:basic'
    faults('independent_auth_rewrite', _Hook('independent_auth_rewrite', post_action=rewrite))
    refused(ack(client, alert_id), alert_id)


def test_original_capture_deadline_cannot_be_renewed_in_g(client, app, faults):
    alert_id = new_alert(client)
    def renew(alert, action, text):
        from alerta_ack_core import utc_timestamp
        frozen = g.voalack['frozen']
        time.sleep(1.5)
        frozen['capture_deadline'] = frozen['issued'] + timedelta(seconds=60)
        frozen['capture_expires_at'] = utc_timestamp(frozen['capture_deadline'])
    faults('independent_deadline_renewal', _Hook('independent_deadline_renewal', post_action=renew))
    with _signing(app, capture_window=timedelta(seconds=1)):
        r = ack(client, alert_id)
    refused(r, alert_id)


def test_future_admin_function_has_no_public_execute(app):
    sql('SET ROLE voalack_admin; CREATE FUNCTION voalack.independent_future_fn() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$', fetch=False)
    try:
        # Check PUBLIC itself (ACL entry), avoiding the runtime role's unrelated explicit grants.
        row = sql("SELECT EXISTS (SELECT 1 FROM pg_proc p, LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a WHERE p.oid = 'voalack.independent_future_fn()'::regprocedure AND a.grantee = 0 AND a.privilege_type = 'EXECUTE')")[0]
        assert row == (False,), row
    finally:
        sql('DROP FUNCTION voalack.independent_future_fn()', fetch=False)
