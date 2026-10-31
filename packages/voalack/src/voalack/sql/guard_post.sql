-- ==== Coexistence 3a S3a: DDL protector, part 2 (applied last, same transaction) ====
-- The guard reads the protected objects by name (catalog lookups need USAGE on their schemas; nothing more).
GRANT USAGE ON SCHEMA voalack, voalack_lifetime TO voalack_guard_owner;

-- Bootstrap only (frozen inventory still empty): record the inventory, never from live state (F7). The function,
-- relation, trigger, column, constraint, index and namespace expectations come from the packaged source expectation
-- (guard_expected.sql: generated from a pristine apply of this same source, outside the product, and reviewed); the four
-- public triggers and the two event triggers come from their literal frozen definitions. The final check below then
-- refuses any installed object that differs from that expectation, and the whole apply rolls back: no freeze is
-- committed, nothing is repaired, revoked or refrozen. On reapply, the frozen inventory must equal the expectation.
DO $$
DECLARE
    differs text[];
BEGIN
    IF NOT EXISTS (SELECT 1 FROM voalack_guard.frozen_inventory) THEN
        INSERT INTO voalack_guard.frozen_inventory (kind, name, attrs)
        SELECT e.kind, e.name, e.attrs FROM pg_temp.voalack_expected_inventory e;
        INSERT INTO voalack_guard.frozen_inventory (kind, name, attrs)
        SELECT 'public_trigger', d.name, 'O|' || d.def FROM voalack_guard.public_trigger_defs() d;
        INSERT INTO voalack_guard.frozen_inventory (kind, name, attrs) VALUES
            ('event_trigger', 'voalack_protect_alerts_end', 'ddl_command_end|O|voalack_guard.protect()|'),
            ('event_trigger', 'voalack_protect_alerts_drop', 'sql_drop|O|voalack_guard.protect()|');
        PERFORM set_config('voalack.first_freeze', 'on', true);
    ELSE
        differs := ARRAY(
            (SELECT f.kind || ' ' || f.name FROM voalack_guard.frozen_inventory f
              WHERE f.kind IN (SELECT DISTINCT e.kind FROM pg_temp.voalack_expected_inventory e)
             EXCEPT SELECT e.kind || ' ' || e.name FROM pg_temp.voalack_expected_inventory e)
            UNION
            (SELECT e.kind || ' ' || e.name FROM pg_temp.voalack_expected_inventory e
              WHERE NOT EXISTS (SELECT 1 FROM voalack_guard.frozen_inventory f
                                 WHERE f.kind = e.kind AND f.name = e.name AND f.attrs = e.attrs)));
        IF cardinality(differs) > 0 THEN
            RAISE EXCEPTION 'voalack: the frozen inventory differs from the packaged source expectation; reapply refused: %',
                differs;
        END IF;
    END IF;
END;
$$;

-- The two event triggers, last. Created only when absent (first bootstrap); a reapply verified them first.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'voalack_protect_alerts_end') THEN
        CREATE EVENT TRIGGER voalack_protect_alerts_end ON ddl_command_end EXECUTE FUNCTION voalack_guard.protect();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'voalack_protect_alerts_drop') THEN
        CREATE EVENT TRIGGER voalack_protect_alerts_drop ON sql_drop EXECUTE FUNCTION voalack_guard.protect();
    END IF;
END;
$$;

-- The whole inventory must now be intact, or the apply (bootstrap or reapply) rolls back.
DO $$
BEGIN
    IF cardinality(voalack_guard.inventory_problems()) > 0 THEN
        IF current_setting('voalack.first_freeze', true) = 'on' THEN
            RAISE EXCEPTION 'voalack: installed protected objects do not match the approved source expectation; '
                            'bootstrap refused, no freeze committed: %', voalack_guard.inventory_problems();
        END IF;
        RAISE EXCEPTION 'voalack: protected inventory not intact after apply: %', voalack_guard.inventory_problems();
    END IF;
END;
$$;
