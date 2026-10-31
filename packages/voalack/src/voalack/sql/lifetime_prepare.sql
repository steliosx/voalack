-- Voalack lifetime migration preparation (contract r8 section 7). Apply as a superuser, committed on its own, before
-- schema.sql on an installation whose history may hold ids now used by non-ONE alerts: schema.sql runs in one
-- transaction, so when its lifetime-1 migration refuses, the dispositions table created there is rolled back with
-- it. This file creates only the dispositions table and what it needs, with the same definitions schema.sql uses
-- (schema.sql keeps them with IF NOT EXISTS / OR REPLACE, so applying both is idempotent). It creates no trigger on
-- public.alerts and changes nothing else.
-- Coexistence 3a S3a (F7, prepared phase): the step runs only on a pre-lifetime installation, i.e. the voalack schema
-- exists and voalack_lifetime does not. Anywhere else (fresh, an S2 or later stage, a repeated or partial preparation,
-- an installed guard) it refuses before any change, so it never normalises existing lifetime state that schema
-- admission would then compare. Its exact objects are the approved phase 4d70e69c-prepared.
DO $$
BEGIN
    IF to_regnamespace('voalack') IS NULL OR to_regnamespace('voalack_lifetime') IS NOT NULL THEN
        RAISE EXCEPTION 'voalack: the lifetime preparation step runs only on a pre-lifetime installation; refused '
                        'before any change';
    END IF;
END;
$$;
CREATE SCHEMA IF NOT EXISTS voalack_lifetime;
CREATE OR REPLACE FUNCTION voalack_lifetime.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'voalack: % rows are immutable', TG_TABLE_NAME;
END;
$$;
CREATE TABLE IF NOT EXISTS voalack_lifetime.migration_dispositions (
    alert_id     text PRIMARY KEY,
    disposition  text NOT NULL CHECK (disposition = 'reserve_collision'),
    actor        text NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 256),
    basis        text NOT NULL CHECK (octet_length(basis) BETWEEN 1 AND 4096),
    recorded_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'voalack_lifetime.migration_dispositions'::regclass
                     AND tgname = 'migration_dispositions_immutable') THEN
        CREATE TRIGGER migration_dispositions_immutable BEFORE UPDATE OR DELETE
            ON voalack_lifetime.migration_dispositions FOR EACH ROW EXECUTE FUNCTION voalack_lifetime.refuse_change();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'voalack_lifetime.migration_dispositions'::regclass
                     AND tgname = 'migration_dispositions_no_truncate') THEN
        CREATE TRIGGER migration_dispositions_no_truncate BEFORE TRUNCATE
            ON voalack_lifetime.migration_dispositions FOR EACH STATEMENT EXECUTE FUNCTION voalack_lifetime.refuse_change();
    END IF;
END;
$$;
ALTER SCHEMA voalack_lifetime OWNER TO voalack_admin;
ALTER FUNCTION voalack_lifetime.refuse_change() OWNER TO voalack_admin;
ALTER TABLE voalack_lifetime.migration_dispositions OWNER TO voalack_admin;
REVOKE ALL ON SCHEMA voalack_lifetime FROM PUBLIC;
REVOKE ALL ON voalack_lifetime.migration_dispositions FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION voalack_lifetime.refuse_change() FROM PUBLIC;
