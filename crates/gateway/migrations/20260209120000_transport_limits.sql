-- migrate:up
-- Mode 3 schema extension: per-tenant transport limits defaults.

alter table tenants
    add column if not exists transport_limits jsonb not null default '{}'::jsonb;

-- migrate:down

alter table tenants
    drop column if exists transport_limits;
