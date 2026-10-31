import pytest
from flask import request_finished
from voalack.boundary import _on_request_finished
from conftest import ack, new_alert, status, captures, intents


@pytest.mark.parametrize("foreign_last", [False, True])
def test_foreign_success_response_cannot_hide_rejected_ack(client, app, monkeypatch, foreign_last):
    aid = new_alert(client)
    seen = []
    def success(sender, response=None, **extra):
        seen.append(status(aid)[0])
        response.status_code = 200
        response.set_data('{"status":"ok","handled":true}')
        response.mimetype = "application/json"
    original = request_finished.receivers_for
    def ordered(sender):
        receivers = list(original(sender))
        # Both orders are permitted by Blinker. Keep the receiver set unchanged.
        return iter(sorted(receivers, key=lambda r: (r is success) if foreign_last else (r is _on_request_finished)))
    request_finished.connect(success, app, weak=False)
    monkeypatch.setattr(request_finished, "receivers_for", ordered)
    try:
        response = ack(client, aid)
    finally:
        request_finished.disconnect(success, app)
    assert seen == ["open"], seen
    assert status(aid)[0] == "open" and captures(aid) == 0 and intents(aid) == 0
    assert response.status_code >= 400, (foreign_last, response.status_code, response.get_json())
