"""A4: the write audit webhook fires before the commit, so install refuses it."""
import pytest
from flask import Flask

from voalack.boundary import _check_audit_webhook, install


def test_install_refuses_the_write_audit_webhook():
    app = Flask(__name__)
    app.config.update(AUDIT_URL="https://audit.example.test/hook", AUDIT_TRAIL=["admin", "write"])
    with pytest.raises(RuntimeError, match="A4"):
        install(app)


def test_write_audit_logging_is_refused():
    # Alerta's audit formatter logs the request data, the ACK note and customers/scopes (A4).
    with pytest.raises(RuntimeError, match="audit logging"):
        _check_audit_webhook({"AUDIT_URL": "", "AUDIT_TRAIL": ["write"], "AUDIT_LOG": True})


@pytest.mark.parametrize("config", [
    {"AUDIT_URL": None, "AUDIT_TRAIL": ["admin", "write"]},
    {"AUDIT_URL": "https://audit.example.test/hook", "AUDIT_TRAIL": ["admin", "auth"]},
    {"AUDIT_URL": None, "AUDIT_TRAIL": ["admin", "auth"], "AUDIT_LOG": True},
])
def test_other_audit_settings_are_accepted(config):
    _check_audit_webhook(config)
