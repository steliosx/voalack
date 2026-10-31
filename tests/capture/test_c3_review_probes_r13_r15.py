"""Focused exact-5d80169 witnesses for automated findings; synthetic guest only."""
import uuid

import psycopg2
import pytest
from flask import g

from conftest import CONFIG, OPERATOR, ack, basic, captures, intents, new_alert, sql, status
from test_c3_transaction import _Hook


@pytest.mark.parametrize("mutation", ["customer", "binding_payload"])
def test_gated_source_is_immutable(app, monkeypatch, mutation):
    import alerta.app
    from voalack.boundary import create_app
    original = alerta.app.create_app
    saved = None

    def mutate(alert, action, text):
        cur = g.voalack["conn"].cursor()
        if mutation == "customer":
            cur.execute("UPDATE public.alerts SET customer = %s WHERE id = %s", ("different-customer", alert.id))
        else:
            cur.execute("UPDATE voalack.prepared_intents SET payload = payload || %s::jsonb WHERE action_id = %s",
                        ('{"binding_id":"different-binding","binding_revision":999}', g.voalack["action_id"]))
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
                  sql("SELECT payload->>'binding_id', payload->>'binding_revision' FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,)))
        print("SOURCE_OUTCOME", mutation, actual)
        assert response.status_code >= 400, actual
        assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0, actual
    finally:
        if saved is not None:
            alerta.app.plugins.plugins.clear()
            alerta.app.plugins.plugins.update(saved)


def test_commit_completion_lost_is_not_reported_as_confirmed_rollback(client, monkeypatch):
    from voalack.txn import DeferredCommitConnection
    original = DeferredCommitConnection.commit_now
    def completion_lost(self):
        original(self)  # actual PostgreSQL COMMIT is durable before completion is lost
        raise psycopg2.OperationalError("synthetic lost COMMIT completion")
    alert_id = new_alert(client)
    monkeypatch.setattr(DeferredCommitConnection, "commit_now", completion_lost)
    response = ack(client, alert_id)
    actual = (response.status_code, response.get_json(), status(alert_id)[0], captures(alert_id), intents(alert_id))
    print("COMMIT_OUTCOME", actual)
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 1 and intents(alert_id) == 1, actual
    assert "not saved" not in response.get_json().get("message", "").lower(), actual


def test_write_only_key_has_uniform_missing_and_present_refusal(client):
    alert_id = new_alert(client)
    response = client.post("/key", json={"scopes": ["write:alerts"], "text": "synthetic write-only"}, headers=basic(OPERATOR))
    assert response.status_code == 201, response.get_data(as_text=True)
    key = response.get_json()["key"]
    def send(id):
        return client.put(f"/alert/{id}/action", json={"action": "ack", "text": "synthetic"}, headers={"Authorization": f"Key {key}"})
    unbound = new_alert(client, bound=False)
    present, present_unbound, absent = send(alert_id), send(unbound), send(str(uuid.uuid4()))
    actual = (present.status_code, present_unbound.status_code, absent.status_code, present.get_json(),
              present_unbound.get_json())
    print("KEY_OUTCOME", actual)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
    # Coexistence 3a (r8 B2 amendment): uniform within the ONE class; an absent id is upstream (404).
    assert present.status_code == present_unbound.status_code == 403, actual
    body = lambda r: {k: v for k, v in r.get_json().items() if k != "requestId"}   # noqa: E731
    assert body(present) == body(present_unbound), actual
    assert absent.status_code == 404, actual
