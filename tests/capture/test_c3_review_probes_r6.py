import pytest
from werkzeug.exceptions import InternalServerError
from conftest import ack, new_alert, status, captures, intents
from test_c3_session_save import _FailingSave


@pytest.mark.parametrize('handler_status', [None, 200])
def test_failed_session_save_cannot_report_http_success(client, app, handler_status):
    aid = new_alert(client)
    wrapper = app.session_interface
    original = wrapper.inner
    previous_handlers = dict(app.error_handler_spec[None].get(500, {}))
    previous_propagate = app.config.get('PROPAGATE_EXCEPTIONS')
    app.config['PROPAGATE_EXCEPTIONS'] = False
    if handler_status:
        app.error_handler_spec[None].setdefault(500, {})[InternalServerError] = lambda exc: ({'status': 'ok', 'handled': True}, handler_status)
    wrapper.inner = _FailingSave(original)
    try:
        response = ack(client, aid)
    finally:
        wrapper.inner = original
        app.error_handler_spec[None].setdefault(500, {}).clear()
        app.error_handler_spec[None][500].update(previous_handlers)
        app.config['PROPAGATE_EXCEPTIONS'] = previous_propagate
    assert status(aid)[0] == 'open' and captures(aid) == 0 and intents(aid) == 0
    assert response.status_code >= 400, (response.status_code, response.get_json(), status(aid), captures(aid))
