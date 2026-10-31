"""Apply the Voalack schema (idempotent)."""
import hashlib
import re
from importlib.resources import files

# Coexistence 3a S3a: the packaged expectation files and the order of the one apply transaction. Each expectation
# names exactly the packaged sources it was derived from (r3 review: an exact set, not any recorded subset).
EXPECTATIONS = {"guard_expected.sql": ("guard_pre.sql", "schema.sql", "guard_post.sql"),
                "guard_phases.sql": ("guard_pre.sql", "lifetime_prepare.sql")}
ORDER = ("guard_pre.sql", "guard_expected.sql", "guard_phases.sql", "guard_admit.sql", "schema.sql", "guard_post.sql")
_DECLARATION = re.compile(r"^-- derived-from ([a-z_]+\.sql) sha256 ([0-9a-f]{64})$")


class PackageIntegrityError(RuntimeError):
    """The packaged source expectations do not match the packaged source: refused before any SQL is issued."""


def verify_packaged_expectations() -> None:
    """Before any schema, admission or preparation SQL: every packaged expectation must declare exactly its own source
    set, each source once, with that packaged file's exact sha256. A missing, extra, duplicated, foreign, path-like or
    malformed declaration, or a different digest, is refused: never applied."""
    sql = files("voalack").joinpath("sql")
    for name, sources in EXPECTATIONS.items():
        text = sql.joinpath(name).read_text(encoding="utf-8")
        declared = []
        for line in text.splitlines():
            if line.startswith("-- derived-from"):
                found = _DECLARATION.match(line)
                if not found:
                    raise PackageIntegrityError(f"{name} has a malformed derivation declaration: {line[:120]!r}")
                declared.append(found.groups())
        names = [source for source, _ in declared]
        if sorted(names) != sorted(sources) or len(names) != len(set(names)):
            raise PackageIntegrityError(f"{name} must declare exactly {sorted(sources)} once each, not {sorted(names)}")
        for source, digest in declared:
            actual = hashlib.sha256(sql.joinpath(source).read_bytes()).hexdigest()
            if actual != digest:
                raise PackageIntegrityError(f"{name} was derived from another {source} ({digest} != {actual})")


def schema_sql() -> str:
    return files("voalack").joinpath("sql/schema.sql").read_text(encoding="utf-8")


def prepare_lifetime_migration(conn) -> None:
    """Create only the lifetime migration's dispositions table, committed on its own, so an operator can record a
    disposition for each collision a refused schema apply listed (the refused apply rolls back everything it made).
    Coexistence 3a S3a: the packaged integrity check (which binds lifetime_prepare.sql's bytes through guard_phases.sql)
    runs first, before any SQL; the step itself refuses anywhere but a pre-lifetime installation, so it is no longer
    idempotent: a repeated preparation is refused before any change (schema apply and reapply stay idempotent). Its
    commit is its own: a later refused schema apply does not undo it, and the prepared state is then admitted only as
    exactly the approved phase 4d70e69c-prepared."""
    verify_packaged_expectations()
    with conn.cursor() as cur:
        cur.execute(files("voalack").joinpath("sql/lifetime_prepare.sql").read_text(encoding="utf-8"))
    conn.commit()


def full_sql() -> str:
    """Coexistence 3a S3a: the DDL protector wraps the schema, applied as one transaction (r8 section 10 bootstrap
    order), with the packaged source expectation loaded before the freeze (F7). schema_sql() stays the voalack schema
    source alone (recovery reads its approved trigger DDL)."""
    sql = files("voalack").joinpath("sql")
    return "\n".join(sql.joinpath(n).read_text(encoding="utf-8") for n in ORDER)


# Taken first in the apply transaction, before any statement changes public.alerts' catalog row (a GRANT on an
# upgrade or reapply). Otherwise autovacuum's ANALYZE of alerts can wait on this transaction while the later
# lifetime migration's LOCK TABLE waits on that ANALYZE: a deadlock (seen in a full-suite run). Taken first, a waiting
# autovacuum is cancelled instead.
LOCK_ALERTS_FIRST = """DO $$
BEGIN
    IF to_regclass('public.alerts') IS NOT NULL THEN
        LOCK TABLE public.alerts IN SHARE ROW EXCLUSIVE MODE;
    END IF;
END;
$$;"""


def apply(conn) -> None:
    verify_packaged_expectations()          # before any SQL is issued on the connection
    with conn.cursor() as cur:
        cur.execute(LOCK_ALERTS_FIRST)
        cur.execute(full_sql())
    conn.commit()
