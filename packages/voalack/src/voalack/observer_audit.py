"""T05b S3: the administrative installation audit of the ledger-only observer (S3).

Separate from the runtime readiness profiles: it reads the catalog as the administrator and compares the named
structural metadata of the observer objects with the frozen inventory shipped with the package
(``sql/observer_inventory.json``). Scope: the named tables, columns, constraints and functions; the six named
triggers (an extra unnamed trigger is not detected); sequences by type, start and increment only. It is not a
complete installation or full-catalog check. It grants nothing and is not a capability list; runtime roles keep their own
readiness checks. A replaced function body with unchanged metadata is not detected (disclosed limit): functions
are audited by signature, owner, SECURITY DEFINER, configuration and ACL.
"""
import json
from importlib import resources

OBSERVER_TABLES = ("observation_chains", "observation_reads", "observation_completions", "source_observations",
                   "observation_evidence")
OBSERVER_SEQUENCES = ("observation_seq", "observation_evidence_evidence_id_seq")
OBSERVER_FUNCTIONS = ("_observer_flag_bump", "_observation_invalid", "_observation_lines", "_utc_micro",
                      "_sha256_text", "_observation_class", "_observation_refusal", "begin_observation",
                      "record_observation", "observation_status")
OBSERVER_TRIGGERS = ("instance_config_observer_bump",) + tuple(f"{t}_immutable" for t in OBSERVER_TABLES)
# The one observer column on a pre-existing table.
OBSERVER_COLUMNS = (("instance_config", "observer_enabled"),)

CLASSES = ("tables", "columns", "sequences", "constraints", "functions", "triggers", "acls")

_QUERIES = {
    "tables": """
        SELECT c.relname FROM pg_class c
         WHERE c.relnamespace = 'voalack'::regnamespace AND c.relkind = 'r' AND c.relname = ANY(%(tables)s)
         ORDER BY 1""",
    "columns": """
        SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
               pg_get_expr(d.adbin, d.adrelid)
          FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
          LEFT JOIN pg_attrdef d ON (d.adrelid, d.adnum) = (a.attrelid, a.attnum)
         WHERE c.relnamespace = 'voalack'::regnamespace AND a.attnum > 0 AND NOT a.attisdropped
           AND (c.relname = ANY(%(tables)s)
                OR (c.relname, a.attname) IN (SELECT * FROM unnest(%(col_tables)s::text[], %(col_names)s::text[])))
         ORDER BY 1, 2""",
    "sequences": """
        SELECT c.relname, s.seqtypid::regtype::text, s.seqstart, s.seqincrement
          FROM pg_class c JOIN pg_sequence s ON s.seqrelid = c.oid
         WHERE c.relnamespace = 'voalack'::regnamespace AND c.relname = ANY(%(sequences)s)
         ORDER BY 1""",
    "constraints": """
        SELECT c.relname, k.conname, k.contype::text, pg_get_constraintdef(k.oid)
          FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
         WHERE c.relnamespace = 'voalack'::regnamespace AND c.relname = ANY(%(tables)s)
         ORDER BY 1, 2""",
    "functions": """
        SELECT p.proname, pg_get_function_identity_arguments(p.oid), pg_get_userbyid(p.proowner), p.prosecdef,
               coalesce(array_to_string(p.proconfig, ','), '')
          FROM pg_proc p
         WHERE p.pronamespace = 'voalack'::regnamespace AND p.proname = ANY(%(functions)s)
         ORDER BY 1, 2""",
    "triggers": """
        SELECT t.tgname, t.tgrelid::regclass::text, t.tgtype, t.tgenabled::text, t.tgfoid::regprocedure::text,
               t.tgqual IS NULL, cardinality(t.tgattr::int2[])
          FROM pg_trigger t
         WHERE NOT t.tgisinternal AND t.tgname = ANY(%(triggers)s)
         ORDER BY 1, 2""",
    "acls": """
        SELECT 'relation', c.relname::text, coalesce(array_to_string(c.relacl, ','), '')   -- text, not name: no truncation
          FROM pg_class c
         WHERE c.relnamespace = 'voalack'::regnamespace
           AND (c.relname = ANY(%(tables)s) OR c.relname = ANY(%(sequences)s))
        UNION ALL
        SELECT 'function', p.proname::text || '(' || pg_get_function_identity_arguments(p.oid) || ')',
               coalesce(array_to_string(p.proacl, ','), '')
          FROM pg_proc p
         WHERE p.pronamespace = 'voalack'::regnamespace AND p.proname = ANY(%(functions)s)
         ORDER BY 1, 2""",
}


def _params():
    return {"tables": list(OBSERVER_TABLES), "sequences": list(OBSERVER_SEQUENCES),
            "functions": list(OBSERVER_FUNCTIONS), "triggers": list(OBSERVER_TRIGGERS),
            "col_tables": [t for t, _ in OBSERVER_COLUMNS], "col_names": [c for _, c in OBSERVER_COLUMNS]}


def inventory(cur) -> dict:
    """The installed observer inventory, one sorted list of rows per class (JSON-compatible values)."""
    out = {}
    for cls in CLASSES:
        cur.execute(_QUERIES[cls], _params())
        out[cls] = [list(row) for row in cur.fetchall()]
    return out


def expected() -> dict:
    """The frozen inventory shipped with the package."""
    return json.loads(resources.files("voalack").joinpath("sql/observer_inventory.json").read_text())


def audit(cur, frozen: dict = None) -> list:
    """Problems of the installed observer against the frozen inventory, one entry per differing class
    (empty: as installed and frozen). Every class is compared; none may be missing from the frozen file."""
    frozen = expected() if frozen is None else frozen
    actual = inventory(cur)
    problems = []
    for cls in CLASSES:
        if cls not in frozen:
            problems.append(f"{cls}: not in the frozen inventory")
        elif sorted(actual[cls], key=repr) != sorted(frozen[cls], key=repr):   # order-independent
            missing = [r for r in frozen[cls] if r not in actual[cls]]
            extra = [r for r in actual[cls] if r not in frozen[cls]]
            problems.append(f"{cls}: missing {missing} extra {extra}")
    return problems
