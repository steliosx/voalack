"""R21 (review of 9674120): bcrypt.checkpw and jwt.decode must be the pinned entry points at first install."""
import json
import subprocess
import sys

import pytest

from conftest import new_alert

CHILD = r'''
import json, sys
import alerta.app
from conftest import CONFIG, OPERATOR, ack
original_factory = alerta.app.create_app
mode = sys.argv[1]


def factory(*args, **kwargs):
    app = original_factory(*args, **kwargs)
    if mode == "bcrypt":
        import bcrypt
        bcrypt.checkpw = lambda password, hashed: True
    elif mode == "jwt":
        import jwt
        original = jwt.decode
        jwt.decode = lambda *a, **k: original(*a, **k)
    return app


alerta.app.create_app = factory
from voalack.boundary import create_app
try:
    app = create_app(config_override=CONFIG)
except RuntimeError as exc:
    print("OUTCOME " + json.dumps({"refused": True, "message": str(exc)[:80]}))
    sys.exit(0)
with app.test_client() as client:
    print("OUTCOME " + json.dumps({"refused": False, "http": ack(client, sys.argv[2]).status_code}))
'''


@pytest.mark.parametrize("mode,refused", [("none", False), ("bcrypt", True), ("jwt", True)])
def test_first_install_qualifies_the_direct_verifiers(client, mode, refused):
    alert_id = new_alert(client)
    process = subprocess.run([sys.executable, "-c", CHILD, mode, alert_id], text=True, capture_output=True, timeout=60)
    assert process.returncode == 0, (process.stdout, process.stderr)
    lines = [l.removeprefix("OUTCOME ") for l in process.stdout.splitlines() if l.startswith("OUTCOME ")]
    assert len(lines) == 1, (process.stdout, process.stderr)
    outcome = json.loads(lines[0])
    assert outcome["refused"] is refused, outcome
    if not refused:
        assert outcome["http"] == 200, outcome


@pytest.mark.parametrize("branch", ["basic", "jwt"])
def test_self_restoring_swap_during_verification_is_refused(client, app, branch):
    # A replacement that undoes itself on first use leaves the gate-time check satisfied; the
    # recorder must see it while verification runs.
    from flask import request
    from conftest import OPERATOR, ack, basic, captures, intents, status
    alert_id = new_alert(client)
    if branch == "basic":
        import bcrypt as module
        name, headers = "checkpw", basic((OPERATOR[0], "definitely-not-the-password"))
        fake_result = lambda *a, **k: True
    else:
        import jwt as module
        token = client.post("/auth/login", json={"username": OPERATOR[0], "password": OPERATOR[1]}).get_json()["token"]
        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        name, headers = "decode", {"Authorization": "Bearer " + ".".join(parts)}
        real = module.decode
        fake_result = lambda *a, **k: real(*a, **{**k, "options": {**(k.get("options") or {}), "verify_signature": False}})
    original = getattr(module, name)

    def self_restoring(*args, **kwargs):
        setattr(module, name, original)
        return fake_result(*args, **kwargs)

    def install_swap():
        if request.endpoint == "api.action_alert":
            setattr(module, name, self_restoring)
    app.before_request_funcs.setdefault(None, []).append(install_swap)
    try:
        r = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"}, headers=headers)
    finally:
        app.before_request_funcs[None].remove(install_swap)
        setattr(module, name, original)
    assert r.status_code >= 400, r.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
