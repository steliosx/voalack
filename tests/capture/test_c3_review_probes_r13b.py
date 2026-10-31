"""R13 continuation: current payload action, alert and actor must match the gated action."""
import uuid
import json

import psycopg2
import pytest
from flask import g

from conftest import CONFIG, OPERATOR, ack, basic, captures, intents, new_alert, sql, status
from test_c3_transaction import _Hook


@pytest.mark.parametrize("mutation", ["action_id", "alert_id", "actor"])
def test_gated_source_is_immutable(app, monkeypatch, mutation):
    import alerta.app
    from voalack.boundary import create_app
    original = alerta.app.create_app
    saved = None

    def mutate(alert, action, text):
        cur = g.voalack["conn"].cursor()
        value = "different-actor" if mutation == "actor" else str(uuid.uuid4())
        cur.execute("UPDATE voalack.prepared_intents SET payload = payload || %s::jsonb WHERE action_id = %s",
                    (json.dumps({mutation: value}), g.voalack["action_id"]))
        return None

    def factory(*args, **kwargs):
        nonlocal saved
        target = original(*args, **kwargs)
        saved = dict(alerta.app.plugins.plugins)
        alerta.app.plugins.plugins["source-writer"] = _Hook("source-writer", post_action=mutate)
        return target

    try:
        with monkeypatch.context() as patch:
            patch.setattr(alerta.app, "create_app", factory)
            target = create_app(config_override=dict(CONFIG, VOALACK_REVIEWED_ACTION_PLUGINS=["source-writer"]))
        with target.test_client() as client:
            alert_id = new_alert(client)
            response = ack(client, alert_id)
        actual = (response.status_code, status(alert_id)[0], captures(alert_id), intents(alert_id),
                  sql("SELECT customer FROM public.alerts WHERE id = %s", (alert_id,))[0][0],
                  sql("SELECT payload FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,)))
        print("SOURCE_OUTCOME", mutation, actual)
        assert response.status_code >= 400, actual
        assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0, actual
    finally:
        if saved is not None:
            alerta.app.plugins.plugins.clear()
            alerta.app.plugins.plugins.update(saved)
