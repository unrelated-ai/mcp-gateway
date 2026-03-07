-- migrate:up
create table if not exists managed_mcp_reconciler_heartbeats (
    reconciler_id text primary key,
    backend_mode text not null check (backend_mode in ('k8s', 'docker')),
    last_heartbeat_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists managed_mcp_reconciler_heartbeats_mode_last_idx
    on managed_mcp_reconciler_heartbeats (backend_mode, last_heartbeat_at desc);

-- migrate:down
drop table if exists managed_mcp_reconciler_heartbeats;
