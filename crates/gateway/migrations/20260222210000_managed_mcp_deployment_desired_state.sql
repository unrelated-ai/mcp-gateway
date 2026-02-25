-- migrate:up
alter table managed_mcp_deployment_requests
    add column if not exists desired_enabled boolean not null default true;

alter table managed_mcp_deployment_requests
    add column if not exists desired_replicas integer not null default 1;

-- migrate:down
alter table managed_mcp_deployment_requests
    drop column if exists desired_replicas;

alter table managed_mcp_deployment_requests
    drop column if exists desired_enabled;
