"""An ACK authenticated by an API key is not a human ACK: nothing is staged or captured."""
from conftest import OPERATOR, basic, captures, intents, new_alert, status


def test_api_key_ack_is_not_captured(client):
    alert_id = new_alert(client)
    r = client.post("/key", json={"scopes": ["write:alerts", "read:alerts"], "text": "lab"},
                    headers=basic(OPERATOR))
    assert r.status_code == 201, r.get_data(as_text=True)
    key = r.get_json()["key"]
    response = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "by key"},
                          headers={"Authorization": f"Key {key}"})
    assert response.status_code >= 400, response.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
