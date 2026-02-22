-- migrate:up
-- Endpoint lifecycle + session drain activity + managed MCP catalog contract.

alter table upstreams
    add column if not exists network_class text not null default 'external';

alter table upstream_endpoints
    add column if not exists lifecycle text not null default 'active';

create table if not exists upstream_session_activity (
    tenant_id text not null references tenants(id) on delete cascade,
    profile_id uuid not null references profiles(id) on delete cascade,
    upstream_id text not null references upstreams(id) on delete cascade,
    endpoint_id text not null,
    session_hash text not null,
    last_seen_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    primary key (profile_id, upstream_id, endpoint_id, session_hash)
);

create index if not exists upstream_session_activity_upstream_last_seen_idx
    on upstream_session_activity (upstream_id, last_seen_at desc);

create index if not exists upstream_session_activity_tenant_profile_idx
    on upstream_session_activity (tenant_id, profile_id, last_seen_at desc);

create table if not exists managed_mcp_deployables (
    id text primary key,
    display_name text not null,
    description text null,
    image text not null,
    default_upstream_url text not null,
    enabled boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists managed_mcp_deployment_requests (
    id text primary key,
    tenant_id text not null references tenants(id) on delete cascade,
    deployable_id text not null references managed_mcp_deployables(id) on delete restrict,
    status text not null check (status in ('pending', 'reconciling', 'ready', 'failed')),
    upstream_id text null,
    message text null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists managed_mcp_deployment_requests_tenant_created_idx
    on managed_mcp_deployment_requests (tenant_id, created_at desc);

create index if not exists managed_mcp_deployment_requests_status_idx
    on managed_mcp_deployment_requests (status, updated_at desc);

-- migrate:down
drop table if exists managed_mcp_deployment_requests;
drop table if exists managed_mcp_deployables;
drop table if exists upstream_session_activity;

alter table upstream_endpoints
    drop column if exists lifecycle;

alter table upstreams
    drop column if exists network_class;
