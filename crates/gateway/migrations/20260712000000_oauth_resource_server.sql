-- migrate:up
-- MCP OAuth resource-server auth model (1.0 maintenance-window migration).
-- Old gateway replicas cannot interpret these new mode values.

alter table profiles
  add column oauth_required_scopes text[] not null default '{}'::text[];

update profiles
set oauth_required_scopes = case
      when data_plane_auth_mode = 'jwt_every_request' then array['mcp:access']::text[]
      else '{}'::text[]
    end,
    data_plane_auth_mode = case data_plane_auth_mode
      when 'api_key_initialize_only' then 'api_key'
      when 'api_key_every_request' then 'api_key'
      when 'jwt_every_request' then 'oauth'
      else data_plane_auth_mode
    end;

alter table profiles
  alter column data_plane_auth_mode set default 'api_key',
  alter column accept_x_api_key set default false;

alter table profiles
  add constraint profiles_data_plane_auth_mode_check
  check (data_plane_auth_mode in ('disabled', 'api_key', 'oauth'));

-- migrate:down
alter table profiles
  drop constraint if exists profiles_data_plane_auth_mode_check;

update profiles
set data_plane_auth_mode = case data_plane_auth_mode
  when 'api_key' then 'api_key_every_request'
  when 'oauth' then 'jwt_every_request'
  else data_plane_auth_mode
end;

alter table profiles
  alter column data_plane_auth_mode set default 'api_key_initialize_only',
  alter column accept_x_api_key set default true,
  drop column oauth_required_scopes;
