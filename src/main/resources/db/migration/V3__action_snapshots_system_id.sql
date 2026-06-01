
ALTER TABLE action_snapshots ADD COLUMN system_id   TEXT;
ALTER TABLE action_snapshots ADD COLUMN system_type TEXT;

UPDATE action_snapshots
   SET system_id = subaccount_id::text, system_type = 'SUBACCOUNT'
 WHERE subaccount_id IS NOT NULL;

UPDATE action_snapshots
   SET system_id = payload ->> 'iasTenantId', system_type = 'IAS'
 WHERE subaccount_id IS NULL;

DROP INDEX IF EXISTS ix_snapshots_target;
DROP INDEX IF EXISTS ix_snapshots_unconsumed;
ALTER TABLE action_snapshots DROP COLUMN subaccount_id;

ALTER TABLE action_snapshots ALTER COLUMN system_id   SET NOT NULL;
ALTER TABLE action_snapshots ALTER COLUMN system_type SET NOT NULL;
ALTER TABLE action_snapshots
    ADD CONSTRAINT ck_action_snapshots_system_type
    CHECK (system_type IN ('SUBACCOUNT', 'IAS'));

CREATE INDEX ix_snapshots_target
    ON action_snapshots(target_user_id, system_type, system_id);

CREATE INDEX ix_snapshots_unconsumed
    ON action_snapshots(system_type, system_id, target_user_id, snapshot_kind, created_at DESC)
    WHERE consumed_at IS NULL;
