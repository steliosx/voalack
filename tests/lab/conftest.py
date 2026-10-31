"""Real Alerta 9.1.0 on real PostgreSQL, in-process through Flask's test client."""
import base64
import os

import pytest

DSN = os.environ.get("VOALACK_LAB_DSN", "postgres://alerta:lab-only-synthetic@localhost/alerta")
OPERATOR = ("operator@example.test", "synthetic-password-1")
READER = ("reader@example.test", "synthetic-password-2")


@pytest.fixture(scope="session")
def app():
    from alerta.app import create_app
    app = create_app(config_override={
        "TESTING": True, "DATABASE_URL": DSN, "AUTH_REQUIRED": True, "SECRET_KEY": "lab-only-synthetic-secret",
        "ADMIN_USERS": [], "PLUGINS": ["reject"], "ALLOWED_ENVIRONMENTS": ["Development"],
    })
    with app.app_context():
        from alerta.auth.utils import generate_password_hash
        from alerta.models.user import User
        for (login, password), roles in ((OPERATOR, ["user"]), (READER, ["guest"])):
            if not User.find_by_username(login):
                User(name=login.split("@")[0], login=login, password=generate_password_hash(password), email=login, roles=roles,
                     text="synthetic", email_verified=True).create()
    return app


def basic(credentials):
    return {"Authorization": "Basic " + base64.b64encode(":".join(credentials).encode()).decode()}


@pytest.fixture
def client(app):
    return app.test_client()
