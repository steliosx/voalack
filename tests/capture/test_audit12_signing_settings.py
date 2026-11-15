"""Audit 2026-11-08 finding 12: unusable signing settings are found at startup and named in the log.

load_signing() returned None silently for most bad settings, and accepted a key that was too
short or a key ID the envelope refuses, so every bound ACK then failed as a generic error. Now
every configured key must have a valid key ID and a usable length, and the first unusable setting
is logged by name; no value or key byte is logged.
"""
import logging
import os

import pytest

from conftest import CONFIG, KEY_FILE, ack, new_alert
from voalack import intent

SECRET = b"lab-only-synthetic-signing-key-for-audit12-"


def _key(tmp_path, size):
    path = tmp_path / f"key-{size}.bin"
    path.write_bytes((SECRET * 4)[:size])
    return str(path)


def _load(caplog, **changes):
    config = dict(CONFIG, **changes)
    for name, value in list(changes.items()):
        if value is None:
            config.pop(name)
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="voalack"):
        loaded = intent.load_signing(config)
    errors = [r.getMessage() for r in caplog.records if r.name == "voalack.intent"]
    assert all(SECRET[:16].decode() not in m for m in errors)            # never a key byte
    return loaded, errors


def test_valid_settings_load_without_errors(app, caplog):
    loaded, errors = _load(caplog)
    assert loaded is not None and loaded.kid == "lab-k1" and errors == []


@pytest.mark.parametrize("changes,setting", [
    ({"VOALACK_DEPLOYMENT_ID": None}, "VOALACK_DEPLOYMENT_ID"),
    ({"VOALACK_SIGNING_KEY_FILES": {}}, "VOALACK_SIGNING_KEY_FILES"),
    ({"VOALACK_SIGNING_KEY_FILES": {"lab k1": KEY_FILE}, "VOALACK_ACTIVE_KID": "lab k1"}, "VOALACK_SIGNING_KEY_FILES"),
    ({"VOALACK_SIGNING_KEY_FILES": {"k" * 33: KEY_FILE}, "VOALACK_ACTIVE_KID": "k" * 33}, "VOALACK_SIGNING_KEY_FILES"),
    ({"VOALACK_ACTIVE_KID": "lab-k2"}, "VOALACK_ACTIVE_KID"),
    ({"VOALACK_MESSAGE_POLICY_REVISION": 0}, "VOALACK_MESSAGE_POLICY_REVISION"),
    ({"VOALACK_CAPTURE_WINDOW_SECONDS": 61}, "VOALACK_CAPTURE_WINDOW_SECONDS"),
    ({"VOALACK_EXECUTION_WINDOW_SECONDS": 20, "VOALACK_CAPTURE_WINDOW_SECONDS": 30}, "VOALACK_EXECUTION_WINDOW_SECONDS"),
    ({"VOALACK_ALLOWED_AUTH_PROVIDERS": "basic"}, "VOALACK_ALLOWED_AUTH_PROVIDERS"),   # a bare string, not a list
    ({"VOALACK_SIGNING_KEY_FILES": {"lab-k1": "/nonexistent/voalack-key"}}, "VOALACK_SIGNING_KEY_FILES"),
])
def test_each_unusable_setting_is_refused_and_named(app, caplog, changes, setting):
    loaded, errors = _load(caplog, **changes)
    assert loaded is None
    assert len(errors) == 1 and setting in errors[0], errors


@pytest.mark.parametrize("size,usable", [(31, False), (32, True), (128, True), (129, False)])
def test_key_length_is_checked_for_every_configured_key(app, caplog, tmp_path, size, usable):
    files = {"lab-k1": KEY_FILE, "lab-old": _key(tmp_path, size)}       # an inactive key is checked too
    loaded, errors = _load(caplog, VOALACK_SIGNING_KEY_FILES=files)
    assert (loaded is not None) is usable
    if not usable:
        assert len(errors) == 1 and "'lab-old'" in errors[0] and "32 to 128 bytes" in errors[0], errors


def test_a_short_active_key_refuses_bound_acks_instead_of_failing_them(client, app, caplog, tmp_path):
    loaded, errors = _load(caplog, VOALACK_SIGNING_KEY_FILES={"lab-k1": _key(tmp_path, 16)})
    assert loaded is None and errors
    original = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = loaded
    try:
        r = ack(client, new_alert(client))
    finally:
        app.extensions["voalack_signing"] = original
    assert r.status_code == 503 and "signing is not configured" in r.get_data(as_text=True)
    assert os.path.getsize(KEY_FILE) >= 32
