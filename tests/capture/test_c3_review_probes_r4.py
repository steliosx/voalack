from flask import g
from werkzeug.exceptions import InternalServerError
from conftest import ack, new_alert, status, captures, intents


def test_response_callback_failure_rewritten_to_200_does_not_commit(client, app):
    aid = new_alert(client)
    def fail_once(response):
        if not g.get('review_response_failed'):
            g.review_response_failed = True
            raise RuntimeError('injected response processing failure')
        return response
    previous_handlers = dict(app.error_handler_spec[None].get(500, {}))
    previous_propagate = app.config.get('PROPAGATE_EXCEPTIONS')
    app.config['PROPAGATE_EXCEPTIONS'] = False
    app.error_handler_spec[None].setdefault(500, {})[InternalServerError] = lambda exc: ({'status': 'ok', 'handled': True}, 200)
    app.after_request_funcs[None].append(fail_once)
    try:
        response = ack(client, aid)
    finally:
        app.after_request_funcs[None].remove(fail_once)
        app.error_handler_spec[None][500].clear()
        app.error_handler_spec[None][500].update(previous_handlers)
        app.config['PROPAGATE_EXCEPTIONS'] = previous_propagate
    assert status(aid)[0] == 'open', (response.status_code, status(aid), captures(aid), intents(aid))
    assert captures(aid) == 0 and intents(aid) == 0
