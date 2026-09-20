//! Gateway HTTP routes shared by routers, audit events and administrative clients.
use crate::Route;

pub mod admin {
    use super::Route;
    pub const TENANTS: Route<0> = Route::new("/admin/v1/tenants");
    pub const TENANT: Route<1> = Route::new("/admin/v1/tenants/{tenant_id}");
    pub const TOOL_SOURCES: Route<1> = Route::new("/admin/v1/tenants/{tenant_id}/tool-sources");
    pub const TOOL_SOURCE: Route<2> =
        Route::new("/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}");
    pub const SECRETS: Route<1> = Route::new("/admin/v1/tenants/{tenant_id}/secrets");
    pub const SECRET: Route<2> = Route::new("/admin/v1/tenants/{tenant_id}/secrets/{name}");
    pub const OIDC_PRINCIPALS: Route<1> =
        Route::new("/admin/v1/tenants/{tenant_id}/oidc-principals");
    pub const OIDC_PRINCIPAL: Route<2> =
        Route::new("/admin/v1/tenants/{tenant_id}/oidc-principals/{subject}");
    pub const AUDIT_SETTINGS: Route<1> = Route::new("/admin/v1/tenants/{tenant_id}/audit/settings");
    pub const AUDIT_EVENTS: Route<1> = Route::new("/admin/v1/tenants/{tenant_id}/audit/events");
    pub const AUDIT_BY_TOOL: Route<1> =
        Route::new("/admin/v1/tenants/{tenant_id}/audit/analytics/tool-calls/by-tool");
    pub const AUDIT_BY_API_KEY: Route<1> =
        Route::new("/admin/v1/tenants/{tenant_id}/audit/analytics/tool-calls/by-api-key");
    pub const AUDIT_CLEANUP: Route<1> = Route::new("/admin/v1/tenants/{tenant_id}/audit/cleanup");
    pub const UPSTREAMS: Route<0> = Route::new("/admin/v1/upstreams");
    pub const UPSTREAM: Route<1> = Route::new("/admin/v1/upstreams/{upstream_id}");
    pub const UPSTREAM_ACTIVITY: Route<1> =
        Route::new("/admin/v1/upstreams/{upstream_id}/session-activity");
    pub const ENDPOINT: Route<2> =
        Route::new("/admin/v1/upstreams/{upstream_id}/endpoints/{endpoint_id}");
    pub const PROFILES: Route<0> = Route::new("/admin/v1/profiles");
    pub const PROFILE: Route<1> = Route::new("/admin/v1/profiles/{profile_id}");
    pub const PROFILE_AUDIT: Route<1> =
        Route::new("/admin/v1/profiles/{profile_id}/audit/settings");
    pub const TENANT_TOKENS: Route<0> = Route::new("/admin/v1/tenant-tokens");
    pub const DEPLOYABLES: Route<0> = Route::new("/admin/v1/managed-mcp/deployables");
    pub const HEARTBEAT: Route<0> = Route::new("/admin/v1/managed-mcp/reconciler-heartbeat");
    pub const DEPLOYMENTS: Route<0> = Route::new("/admin/v1/managed-mcp/deployments");
    pub const DEPLOYMENT: Route<1> = Route::new("/admin/v1/managed-mcp/deployments/{request_id}");
}

pub mod tenant {
    use super::Route;
    pub const PROFILE_AUDIT: Route<1> =
        Route::new("/tenant/v1/profiles/{profile_id}/audit/settings");
    pub const UPSTREAMS: Route<0> = Route::new("/tenant/v1/upstreams");
    pub const UPSTREAM: Route<1> = Route::new("/tenant/v1/upstreams/{upstream_id}");
    pub const ENDPOINT: Route<2> =
        Route::new("/tenant/v1/upstreams/{upstream_id}/endpoints/{endpoint_id}");
    pub const UPSTREAM_SURFACE: Route<1> = Route::new("/tenant/v1/upstreams/{upstream_id}/surface");
    pub const UPSTREAM_ACTIVITY: Route<1> =
        Route::new("/tenant/v1/upstreams/{upstream_id}/session-activity");
    pub const TOOL_SOURCES: Route<0> = Route::new("/tenant/v1/tool-sources");
    pub const TOOL_SOURCE: Route<1> = Route::new("/tenant/v1/tool-sources/{source_id}");
    pub const TOOL_SOURCE_TOOLS: Route<1> = Route::new("/tenant/v1/tool-sources/{source_id}/tools");
    pub const OPENAPI_INSPECT: Route<0> = Route::new("/tenant/v1/tool-sources/openapi/inspect");
    pub const VALIDATE_SOURCE_ID: Route<0> = Route::new("/tenant/v1/tool-sources/validate-id");
    pub const SECRETS: Route<0> = Route::new("/tenant/v1/secrets");
    pub const SECRET: Route<1> = Route::new("/tenant/v1/secrets/{name}");
    pub const API_KEYS: Route<0> = Route::new("/tenant/v1/api-keys");
    pub const API_KEY: Route<1> = Route::new("/tenant/v1/api-keys/{api_key_id}");
    pub const AUDIT_SETTINGS: Route<0> = Route::new("/tenant/v1/audit/settings");
    pub const TRANSPORT_LIMITS: Route<0> = Route::new("/tenant/v1/transport/limits");
    pub const AUDIT_EVENTS: Route<0> = Route::new("/tenant/v1/audit/events");
    pub const AUDIT_BY_TOOL: Route<0> = Route::new("/tenant/v1/audit/analytics/tool-calls/by-tool");
    pub const AUDIT_BY_API_KEY: Route<0> =
        Route::new("/tenant/v1/audit/analytics/tool-calls/by-api-key");
    pub const PROFILES: Route<0> = Route::new("/tenant/v1/profiles");
    pub const PROFILE: Route<1> = Route::new("/tenant/v1/profiles/{profile_id}");
    pub const PROFILE_SURFACE: Route<1> = Route::new("/tenant/v1/profiles/{profile_id}/surface");
    pub const DEPLOYABLES: Route<0> = Route::new("/tenant/v1/managed-mcp/deployables");
    pub const DEPLOYMENTS: Route<0> = Route::new("/tenant/v1/managed-mcp/deployments");
    pub const DEPLOYMENT: Route<1> = Route::new("/tenant/v1/managed-mcp/deployments/{request_id}");
}

pub mod bootstrap {
    use super::Route;
    pub const TENANT: Route<0> = Route::new("/bootstrap/v1/tenant");
    pub const STATUS: Route<0> = Route::new("/bootstrap/v1/tenant/status");
}
