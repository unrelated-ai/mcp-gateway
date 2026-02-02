-- migrate:up
-- Mode 3 schema extension: per-tenant audit settings + audit event log.

-- ---------------------------------------------------------------------------
-- Tenants: add audit settings (per-tenant, optional, default OFF)
-- ---------------------------------------------------------------------------

alter table tenants
    add column if not exists audit_enabled boolean not null default false;

alter table tenants
    add column if not exists audit_retention_days integer not null default 30;

alter table tenants
    add column if not exists audit_default_level text not null default 'metadata';

alter table tenants
    add constraint tenants_audit_retention_days_nonnegative
    check (audit_retention_days >= 0);

alter table tenants
    add constraint tenants_audit_default_level_valid
    check (audit_default_level in ('off', 'summary', 'metadata', 'payload'));

-- ---------------------------------------------------------------------------
-- Profiles: add audit override settings (JSONB, inherits tenant defaults)
-- ---------------------------------------------------------------------------

alter table profiles
    add column if not exists audit_settings jsonb not null default '{}'::jsonb;

-- ---------------------------------------------------------------------------
-- Audit event log (append-only)
-- ---------------------------------------------------------------------------

create table if not exists audit_events (
    id bigserial primary key,
    ts timestamptz not null default now(),

    -- Tenant is required (per-tenant feature + isolation boundary).
    tenant_id text not null references tenants(id) on delete cascade,

    -- Optional profile linkage (for profile-scoped views).
    profile_id uuid null references profiles(id) on delete set null,

    -- Actor identity (best-effort; may be null depending on plane/auth mode).
    api_key_id uuid null references api_keys(id) on delete set null,
    oidc_issuer text null,
    oidc_subject text null,

    action text not null,

    -- Optional HTTP context (admin/tenant planes).
    http_method text null,
    http_route text null,
    status_code integer null,

    -- Optional tool context (data plane tools/call).
    -- tool_ref uses stable identity: "<source_id>:<original_tool_name>".
    tool_ref text null,
    tool_name_at_time text null,

    ok boolean not null,
    duration_ms bigint null,
    error_kind text null,
    error_message text null,

    -- Strict allowlist JSON for additional sanitized metadata (never secrets).
    meta jsonb not null default '{}'::jsonb
);

create index if not exists audit_events_tenant_ts_idx
    on audit_events (tenant_id, ts desc);

create index if not exists audit_events_tenant_profile_ts_idx
    on audit_events (tenant_id, profile_id, ts desc);

create index if not exists audit_events_tenant_api_key_ts_idx
    on audit_events (tenant_id, api_key_id, ts desc);

create index if not exists audit_events_tenant_action_ts_idx
    on audit_events (tenant_id, action, ts desc);

create index if not exists audit_events_tenant_tool_ref_ts_idx
    on audit_events (tenant_id, tool_ref, ts desc);

-- migrate:down

drop index if exists audit_events_tenant_tool_ref_ts_idx;
drop index if exists audit_events_tenant_action_ts_idx;
drop index if exists audit_events_tenant_api_key_ts_idx;
drop index if exists audit_events_tenant_profile_ts_idx;
drop index if exists audit_events_tenant_ts_idx;

drop table if exists audit_events;

alter table profiles
    drop column if exists audit_settings;

alter table tenants
    drop constraint if exists tenants_audit_default_level_valid;
alter table tenants
    drop constraint if exists tenants_audit_retention_days_nonnegative;

alter table tenants
    drop column if exists audit_default_level;
alter table tenants
    drop column if exists audit_retention_days;
alter table tenants
    drop column if exists audit_enabled;
