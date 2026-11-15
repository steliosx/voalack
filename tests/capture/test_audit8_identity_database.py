"""Audit 2026-11-08 finding 8: the startup role check examines the database Alerta uses.

Alerta connects with ``psycopg2.connect(dsn=DATABASE_URL, dbname=DATABASE_NAME)``, so a set
DATABASE_NAME overrides the URL's database. The check used the URL alone and could examine another
database. A lab database owned by the runtime role makes the difference visible: the database-owner
rule refuses it, and passes for Alerta's own database.
"""
import uuid
from urllib.parse import urlsplit, urlunsplit

import psycopg2
import pytest

from conftest import APP_DSN, DSN


def _on(dsn, database):
    parts = urlsplit(dsn)
    return urlunsplit(parts._replace(path="/" + database))


@pytest.fixture
def owned_database(app):
    """A disposable empty database owned by the runtime role (lab only)."""
    name = f"voalack_lab_owned_{uuid.uuid4().hex[:8]}"
    runtime = urlsplit(APP_DSN).username
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    try:
        admin.cursor().execute(f'CREATE DATABASE {name} OWNER "{runtime}"')
        yield name
    finally:
        admin.cursor().execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.close()


def test_owned_database_alone_is_refused(owned_database):
    from voalack.boundary import _check_database_identity
    with pytest.raises(RuntimeError, match="must not be a superuser"):
        _check_database_identity({"DATABASE_URL": _on(APP_DSN, owned_database)})


def test_database_name_overrides_the_url_like_alerta(owned_database):
    from voalack.boundary import _check_database_identity
    alerta_db = urlsplit(APP_DSN).path.lstrip("/")
    # Alerta would use the owned database: the check must look there and refuse.
    with pytest.raises(RuntimeError, match="must not be a superuser"):
        _check_database_identity({"DATABASE_URL": APP_DSN, "DATABASE_NAME": owned_database})
    # Alerta would use its own database although the URL names the owned one: the check passes.
    _check_database_identity({"DATABASE_URL": _on(APP_DSN, owned_database), "DATABASE_NAME": alerta_db})


def test_unset_database_name_keeps_the_url_database():
    from voalack.boundary import _check_database_identity
    _check_database_identity({"DATABASE_URL": APP_DSN, "DATABASE_NAME": None})
    with pytest.raises(RuntimeError, match="must not be a superuser"):
        _check_database_identity({"DATABASE_URL": DSN, "DATABASE_NAME": None})
