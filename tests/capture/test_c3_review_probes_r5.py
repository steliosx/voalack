from conftest import ack, new_alert, captures, intents, status


def test_null_session_commits_without_a_session_save(client, app):
    previous_secret = app.config['SECRET_KEY']
    app.config['SECRET_KEY'] = None
    try:
        aid = new_alert(client)
        response = ack(client, aid)
    finally:
        app.config['SECRET_KEY'] = previous_secret
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(aid)[0] == 'ack' and captures(aid) == 1 and intents(aid) == 1


def test_session_save_changed_response_status_does_not_commit(client, app):
    aid = new_alert(client)
    wrapper = app.session_interface
    original = wrapper.inner
    class ChangeDisposition:
        def __getattr__(self, name):
            return getattr(original, name)
        def save_session(self, app_, session, response):
            original.save_session(app_, session, response)
            response.status_code = 500
    wrapper.inner = ChangeDisposition()
    try:
        response = ack(client, aid)
    finally:
        wrapper.inner = original
    assert status(aid)[0] == 'open', (response.status_code, status(aid), captures(aid), intents(aid))
    assert captures(aid) == 0 and intents(aid) == 0


def test_session_save_cannot_invalidate_final_ack_history(client, app):
    aid = new_alert(client)
    wrapper = app.session_interface
    original = wrapper.inner
    class RewriteHistory:
        def __getattr__(self, name):
            return getattr(original, name)
        def save_session(self, app_, session, response):
            from flask import g
            g.db.cursor().execute("UPDATE alerts SET history[1] = json_populate_record(history[1], json_build_object('text', 'changed during session save')) WHERE id=%s", (aid,))
            original.save_session(app_, session, response)
    wrapper.inner = RewriteHistory()
    try:
        response = ack(client, aid)
    finally:
        wrapper.inner = original
    assert status(aid)[0] == 'open', (response.status_code, status(aid), captures(aid), intents(aid))
    assert captures(aid) == 0 and intents(aid) == 0
