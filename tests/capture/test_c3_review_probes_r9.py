"""A refused candidate must not become HTTP success before capture state exists."""
import psycopg2
import pytest
from alerta.exceptions import ApiError
from conftest import DSN, OPERATOR, ack, basic, captures, intents, new_alert, status


@pytest.mark.parametrize("failure", ["api-key", "registry-unavailable"])
def test_gate_refusal_rewritten_by_handler_is_not_success(client, app, failure):
    aid = new_alert(client)
    key = None
    if failure == "api-key":
        response = client.post("/key", json={"scopes": ["write:alerts", "read:alerts"], "text": "lab"}, headers=basic(OPERATOR))
        assert response.status_code == 201
        key = response.get_json()["key"]
    handlers = app.error_handler_spec[None].setdefault(None, {})
    previous = dict(handlers)
    handlers[ApiError] = lambda exc: ({"status": "ok", "handled": True}, 200)
    holder = None
    try:
        if failure == "registry-unavailable":
            holder = psycopg2.connect(DSN)
            holder.cursor().execute("LOCK TABLE voalack.bindings IN ACCESS EXCLUSIVE MODE")
            response = ack(client, aid)
        else:
            response = client.put(f"/alert/{aid}/action", json={"action": "ack", "text": "key ack"}, headers={"Authorization": f"Key {key}"})
    finally:
        if holder is not None:
            holder.rollback()
            holder.close()
        handlers.clear()
        handlers.update(previous)
    assert status(aid)[0] == "open" and captures(aid) == 0 and intents(aid) == 0
    assert response.status_code >= 400, (failure, response.status_code, response.get_json())
