-- ==== Coexistence 3a S3a: first-install admission (F7), after guard_pre.sql and before schema.sql ====
-- Only on first install (empty frozen inventory; a reapply is governed by guard_pre's reapply verification). The
-- pre-existing protected objects are the current inventory minus the guard objects guard_pre.sql itself just created
-- (guard_pre refused any pre-existing guard state first, so those can hide nothing). They must be either
--   none at all (a fresh installation), or
--   exactly one approved predecessor phase's COMPLETE required set (pg_temp.voalack_phase_expectation, loaded by the
--   packaged guard_phases.sql): presence, absence and attributes; anything missing, extra or different refuses.
-- Otherwise the first install is refused here, before schema.sql could replace a body, rewrite an owner, revoke a grant
-- or create a missing hook: no repair, no partial upgrade. Objects new in S3a are simply absent from every phase.
DO $$
DECLARE
    phase_name text;
    differs text[];
    report text := '';
BEGIN
    IF EXISTS (SELECT 1 FROM voalack_guard.frozen_inventory) THEN
        RETURN;
    END IF;
    -- Fresh only by independent absence: no Voalack project schema at all (guard_pre.sql creates none of these), not
    -- merely an empty protected selection. A damaged installation that lost its protected objects but keeps its schema,
    -- tables or data is partial project state: it matches no phase below and is refused.
    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname IN ('voalack', 'voalack_lifetime', 'voalack_publication'))
       AND NOT EXISTS (SELECT 1 FROM voalack_guard.current_inventory() c
                        WHERE c.name NOT LIKE 'voalack\_guard.%' AND NOT (c.kind = 'namespace' AND c.name = 'voalack_guard')) THEN
        PERFORM set_config('voalack.predecessor_phase', 'fresh', true);
        RETURN;
    END IF;
    FOR phase_name IN SELECT DISTINCT p.phase FROM pg_temp.voalack_phase_expectation p ORDER BY 1 LOOP
        differs := ARRAY(
            WITH pre AS (SELECT c.kind, c.name, c.attrs FROM voalack_guard.current_inventory() c
                          WHERE c.name NOT LIKE 'voalack\_guard.%'
                            AND NOT (c.kind = 'namespace' AND c.name = 'voalack_guard')),
                 exp AS (SELECT p.kind, p.name, p.attrs FROM pg_temp.voalack_phase_expectation p
                          WHERE p.phase = phase_name)
            SELECT 'missing ' || e.kind || ' ' || e.name FROM exp e
             WHERE NOT EXISTS (SELECT 1 FROM pre r WHERE r.kind = e.kind AND r.name = e.name)
            UNION ALL
            SELECT 'extra ' || r.kind || ' ' || r.name FROM pre r
             WHERE NOT EXISTS (SELECT 1 FROM exp e WHERE e.kind = r.kind AND e.name = r.name)
            UNION ALL
            SELECT 'differs ' || e.kind || ' ' || e.name FROM exp e JOIN pre r ON r.kind = e.kind AND r.name = e.name
             WHERE r.attrs IS DISTINCT FROM e.attrs
            ORDER BY 1);
        IF cardinality(differs) = 0 THEN
            PERFORM set_config('voalack.predecessor_phase', phase_name, true);
            RETURN;
        END IF;
        report := report || phase_name || ': ' || differs::text || '; ';
    END LOOP;
    RAISE EXCEPTION 'voalack: pre-existing protected objects match no approved predecessor phase; first install refused '
                    'before any change: %', report;
END;
$$;
