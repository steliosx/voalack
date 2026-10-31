from conftest import ack, new_alert, sql, status, captures, OPERATOR
from test_c3_transaction import _Hook

def test_repeat_ack_response_is_preserved(client):
    aid = new_alert(client)
    assert ack(client, aid).status_code == 200
    response = ack(client, aid)
    assert response.status_code == 409, response.get_data(as_text=True)
    assert captures(aid) == 1

def test_final_ack_note_matches_prepared_intent(client, faults):
    aid = new_alert(client)
    def rewrite(alert, status, text):
        return alert, status, 'reviewed final note'
    faults('note_rewriter', _Hook('note_rewriter', status_change=rewrite))
    response = ack(client, aid, text='original note')
    assert response.status_code == 200, response.get_data(as_text=True)
    row = sql("SELECT p.payload->>'note', (a.history[1]).text FROM voalack.prepared_intents p JOIN alerts a ON a.id=p.alert_id WHERE p.alert_id=%s", (aid,))[0]
    assert row[0] == row[1], repr(row)

def test_late_response_disposition_rolls_back(client, app):
    def change(response):
        response.status_code = 202
        return response
    aid = new_alert(client)
    app.after_request_funcs[None].append(change)
    try:
        response = ack(client, aid)
    finally:
        app.after_request_funcs[None].remove(change)
    # Amended (automated review of dfef40d): a 202 set by a response callback is not Alerta's
    # genuine ForwardingLoop result, so the rolled-back ACK now answers 500. Was: == 202.
    assert response.status_code == 500
    assert status(aid)[0] == 'open'
    assert captures(aid) == 0

def test_error_handler_200_does_not_commit_failed_chain(client, app, faults):
    from alerta.exceptions import ApiError
    from test_c3_transaction import _raise
    aid = new_alert(client)
    previous = dict(app.error_handler_spec[None][None])
    app.error_handler_spec[None][None][ApiError] = lambda exc: ({'status': 'ok', 'handled': True}, 200)
    faults('fail_handled_as_200', _Hook('fail_handled_as_200', post_action=_raise(RuntimeError('failed chain'))))
    try:
        response = ack(client, aid)
    finally:
        app.error_handler_spec[None][None].clear()
        app.error_handler_spec[None][None].update(previous)
    assert status(aid)[0] == 'open', (response.status_code, status(aid), captures(aid))
    assert captures(aid) == 0

def test_post_action_cannot_replace_captured_history(client, faults):
    aid = new_alert(client)
    # Use the actual request connection: a separate connection would wait on the row lock.
    def rewrite_in_transaction(alert, action, text):
        from flask import g
        g.db.cursor().execute("UPDATE alerts SET history[1] = json_populate_record(history[1], json_build_object('text', 'replaced after capture')) WHERE id=%s", (aid,))
    faults('history_rewriter', _Hook('history_rewriter', post_action=rewrite_in_transaction))
    response = ack(client, aid)
    assert response.status_code == 500, (response.status_code, status(aid), captures(aid))
    assert status(aid)[0] == 'open' and captures(aid) == 0

def test_eligibility_lookup_lock_wait_is_bounded(client, app):
    import threading
    import psycopg2
    from conftest import DSN
    aid = new_alert(client)
    locker = psycopg2.connect(DSN)
    locker.cursor().execute('LOCK TABLE voalack.bindings IN ACCESS EXCLUSIVE MODE')
    results = {}
    def call():
        try:
            with app.test_client() as other:
                results['response'] = ack(other, aid, who=None).status_code
        except Exception as exc:
            results['error'] = type(exc).__name__
    thread = threading.Thread(target=call)
    thread.start()
    thread.join(timeout=2.8)
    still_waiting = thread.is_alive()
    locker.rollback()
    locker.close()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert not still_waiting, ('eligibility SELECT still blocked past 2-second lock bound', results)
