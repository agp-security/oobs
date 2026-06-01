CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE ias_tenants (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name              TEXT NOT NULL,
    ias_host                  TEXT NOT NULL UNIQUE,
    encrypted_creds           BYTEA NOT NULL,
    encrypted_creds_nonce     BYTEA NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by                TEXT NOT NULL,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by                TEXT NOT NULL
);

CREATE INDEX ix_ias_tenants_host ON ias_tenants(ias_host);

CREATE TABLE subaccounts (
    id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subaccount_guid               UUID NOT NULL UNIQUE,
    cis_display_name              TEXT NOT NULL,
    cis_display_name_refreshed_at TIMESTAMPTZ,
    label                         TEXT,
    region                        TEXT NOT NULL,
    global_account_id             UUID,
    global_account_name           TEXT,
    stage                         TEXT,
    enrolled_by                   TEXT NOT NULL,
    enrolled_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_health_at                TIMESTAMPTZ,
    last_health_error             TEXT,
    status                        TEXT NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active','disabled','error')),
    cf_org_id                     UUID
);

CREATE INDEX ix_subaccounts_region         ON subaccounts(region);
CREATE INDEX ix_subaccounts_status         ON subaccounts(status);
CREATE INDEX ix_subaccounts_global_account ON subaccounts(global_account_id);
CREATE INDEX ix_subaccounts_stage          ON subaccounts(lower(stage));
CREATE INDEX ix_subaccounts_cf_org_id      ON subaccounts(cf_org_id);

CREATE TABLE subaccount_credentials (
    subaccount_id UUID    NOT NULL REFERENCES subaccounts(id) ON DELETE CASCADE,
    kind          TEXT    NOT NULL
                  CHECK (kind IN ('cis','xsuaa_apiaccess','cf_technical_user')),
    key_version   INTEGER NOT NULL DEFAULT 1,
    cipher        BYTEA   NOT NULL,
    nonce         BYTEA   NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at    TIMESTAMPTZ,
    PRIMARY KEY (subaccount_id, kind)
);

CREATE TABLE subaccount_contacts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subaccount_id UUID NOT NULL REFERENCES subaccounts(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL
                  CHECK (role IN ('security','ops','business','technical','other')),
    notes         TEXT,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_subaccount_contacts_subaccount ON subaccount_contacts(subaccount_id);
CREATE UNIQUE INDEX ux_subaccount_contacts_role
    ON subaccount_contacts(subaccount_id, lower(email), role);

CREATE TABLE containment_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correlation_id    UUID NOT NULL,
    system_id         TEXT,
    system_type        TEXT NOT NULL CHECK(system_type IN ('SUBACCOUNT', 'IAS', 'ONPREM', 'INTERNAL')),
    target_user_email TEXT NOT NULL,
    target_user_id    TEXT,
    action            TEXT NOT NULL CHECK (action IN (
        'ias_deactivate','xsuaa_delete_shadow','xsuaa_strip_roles',
        'ias_strip_groups',
        'ias_activate','xsuaa_restore_roles','ias_restore_groups',
        'cf_revoke_org_roles','cf_restore_org_roles','cf_revoke_tokens',
        'enroll','unenroll',
        'sod_scan','sod_finding',
        'protect_add','protect_disable','protect_block',
        'health_check',
        'comment'
    )),
    actor             TEXT NOT NULL,
    actor_source      TEXT NOT NULL
                      CHECK (actor_source IN ('ui','soar-api','system')),
    outcome           TEXT NOT NULL
                      CHECK (outcome IN ('ok','partial','failed','dry-run','skipped')),
    error_message     TEXT,
    details           JSONB,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ
);

CREATE INDEX ix_events_system_id     ON containment_events(system_id);
CREATE INDEX ix_events_system_type     ON containment_events(system_type);
CREATE INDEX ix_events_correlation    ON containment_events(correlation_id);
CREATE INDEX ix_events_target_user    ON containment_events(lower(target_user_email));
CREATE INDEX ix_events_started_at     ON containment_events(started_at DESC);

CREATE INDEX ix_events_action         ON containment_events(action);
CREATE INDEX ix_events_outcome        ON containment_events(outcome);
CREATE INDEX ix_events_correlation_time ON containment_events(correlation_id, started_at DESC);

CREATE TABLE action_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correlation_id  UUID NOT NULL,
    subaccount_id   UUID REFERENCES subaccounts(id) ON DELETE CASCADE,
    target_user_id  TEXT NOT NULL,
    snapshot_kind   TEXT NOT NULL
                    CHECK (snapshot_kind IN (
                        'role_collections', 'ias_user_state', 'cf_org_roles',
                        'ias_user_groups'
                    )),
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at     TIMESTAMPTZ
);

CREATE INDEX ix_snapshots_correlation ON action_snapshots(correlation_id);
CREATE INDEX ix_snapshots_target      ON action_snapshots(target_user_id, subaccount_id);
CREATE INDEX ix_snapshots_unconsumed
    ON action_snapshots(subaccount_id, target_user_id, snapshot_kind, created_at DESC)
    WHERE consumed_at IS NULL;

CREATE TABLE protected_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subaccount_id   UUID REFERENCES subaccounts(id) ON DELETE CASCADE,
    ias_tenant_id   UUID REFERENCES ias_tenants(id) ON DELETE CASCADE,
    user_email      TEXT NOT NULL,
    user_ias_id     TEXT,
    reason          TEXT NOT NULL,
    origin          TEXT NOT NULL
                    CHECK (origin IN ('manual','self','system','rule')),
    added_by        TEXT NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    disabled_at     TIMESTAMPTZ,
    disabled_by     TEXT,
    CONSTRAINT ck_protected_users_scope_exclusive
        CHECK (subaccount_id IS NULL OR ias_tenant_id IS NULL)
);

CREATE INDEX ix_protected_users_email      ON protected_users(lower(user_email));
CREATE INDEX ix_protected_users_subaccount ON protected_users(subaccount_id);
CREATE INDEX ix_protected_users_ias_tenant ON protected_users(ias_tenant_id);
CREATE INDEX ix_protected_users_active     ON protected_users(enabled) WHERE enabled = TRUE;

CREATE UNIQUE INDEX ux_protected_users_active_email
    ON protected_users (
        COALESCE(subaccount_id::text, ''),
        COALESCE(ias_tenant_id::text, ''),
        lower(user_email)
    )
    WHERE enabled = TRUE;

CREATE TABLE conflict_sets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL UNIQUE,
    description      TEXT,
    kind             TEXT NOT NULL DEFAULT 'sod'
                     CHECK (kind IN ('sod', 'critical', 'threshold', 'external_email')),
    threshold_count  INTEGER,
    severity         TEXT NOT NULL DEFAULT 'high'
                     CHECK (severity IN ('low','medium','high','critical')),
    role_collections JSONB NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    scope_level      TEXT NOT NULL DEFAULT 'subaccount'
                     CHECK (scope_level IN ('subaccount','space','org','global')),
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_conflict_sets_threshold
        CHECK (kind <> 'threshold' OR threshold_count IS NOT NULL)
);

CREATE INDEX ix_conflict_sets_kind ON conflict_sets(kind) WHERE enabled = TRUE;

CREATE TABLE central_viewer_keys (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    global_account_id     UUID,
    global_account_name   TEXT,
    label                 TEXT,
    cipher                BYTEA NOT NULL,
    nonce                 BYTEA NOT NULL,
    key_version           INTEGER NOT NULL DEFAULT 1,
    sync_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 60
                          CHECK (sync_interval_minutes >= 1
                                 AND sync_interval_minutes <= 10080),  -- max 1 week
    last_sync_at          TIMESTAMPTZ,
    last_sync_error       TEXT,
    last_sync_count       INTEGER,
    added_by              TEXT NOT NULL,
    added_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_central_viewer_keys_ga
    ON central_viewer_keys(global_account_id)
    WHERE global_account_id IS NOT NULL;

CREATE INDEX ix_central_viewer_keys_sync_due
    ON central_viewer_keys(sync_enabled, last_sync_at);

CREATE TABLE discovered_subaccounts (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    central_key_id         UUID NOT NULL REFERENCES central_viewer_keys(id) ON DELETE CASCADE,
    subaccount_guid        UUID NOT NULL,
    display_name           TEXT,
    subdomain              TEXT,
    region                 TEXT,
    parent_type            TEXT,
    parent_guid            UUID,
    global_account_guid    UUID,
    state                  TEXT,
    state_message          TEXT,
    beta_enabled           BOOLEAN,
    used_for_production    TEXT,
    description            TEXT,
    discovered_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (central_key_id, subaccount_guid)
);

CREATE INDEX ix_discovered_central_key ON discovered_subaccounts(central_key_id);
CREATE INDEX ix_discovered_guid        ON discovered_subaccounts(subaccount_guid);

CREATE TABLE app_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT NOT NULL
);

CREATE TABLE audit_sinks (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                      TEXT NOT NULL UNIQUE
                              CHECK (kind IN ('splunk_hec','btp_audit_log')),
    enabled                   BOOLEAN NOT NULL DEFAULT FALSE,
    config_plaintext          JSONB NOT NULL DEFAULT '{}'::jsonb,
    encrypted_secret          BYTEA,
    encrypted_secret_nonce    BYTEA,
    last_test_at              TIMESTAMPTZ,
    last_test_status          TEXT,          -- 'ok' | 'failed' | NULL
    last_test_message         TEXT,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by                TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE origin_profiles (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL UNIQUE,
    description   TEXT,
    origin_keys   TEXT[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by    TEXT NOT NULL
);

CREATE INDEX ix_origin_profiles_name ON origin_profiles(lower(name));
