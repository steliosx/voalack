"""The lab itself works: authenticated ingest, human ACK, history row in PostgreSQL."""
import uuid

import psycopg2

from conftest import DSN, OPERATOR, basic


def test_human_ack_writes_history(client):
    resource = f"lab-{uuid.uuid4()}"
    r = client.post("/alert", json={"resource": resource, "event": "VeeamOneAlarm", "environment": "Development",
                                     "severity": "major", "service": ["lab"], "text": "synthetic"},
                    headers=basic(OPERATOR))
    assert r.status_code == 201, r.get_data(as_text=True)
    alert_id = r.get_json()["id"]
    r = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "synthetic ack"}, headers=basic(OPERATOR))
    assert r.status_code == 200, r.get_data(as_text=True)
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT status, (history[1]).type, (history[1]).\"user\" FROM alerts WHERE id=%s", (alert_id,))
        assert cur.fetchone() == ("ack", "ack", OPERATOR[0])


def test_unauthenticated_ack_is_refused(client):
    r = client.put(f"/alert/{uuid.uuid4()}/action", json={"action": "ack"})
    assert r.status_code == 401
