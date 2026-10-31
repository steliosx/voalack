import pytest
from conftest import ack, new_alert, status, captures, intents


@pytest.mark.parametrize("code", [201, 204])
def test_early_success_status_cannot_report_rolled_back_ack(client, app, code):
    aid = new_alert(client)
    def change(response):
        response.status_code = code
        return response
    callbacks = app.after_request_funcs[None]
    callbacks.append(change)  # Flask reverses this list: runs before Voalack's boundary.
    try:
        response = ack(client, aid)
    finally:
        callbacks.remove(change)
    assert status(aid)[0] == "open" and captures(aid) == 0 and intents(aid) == 0
    assert response.status_code >= 400, (code, response.status_code, response.get_data(as_text=True))
