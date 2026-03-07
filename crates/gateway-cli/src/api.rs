use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use unrelated_tool_transforms::TransformPipeline;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpProfileSettings {
    /// Control which MCP server capabilities the Gateway advertises (and enforces).
    #[serde(default)]
    pub capabilities: McpCapabilitiesPolicy,
    /// Server→client notification filtering (for the merged SSE stream).
    #[serde(default)]
    pub notifications: McpNotificationFilter,
    /// Namespacing / collision-handling policy for IDs in the merged SSE stream.
    #[serde(default)]
    pub namespacing: McpNamespacing,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpCapabilitiesPolicy {
    /// If non-empty, acts as an allowlist overriding defaults.
    #[serde(default)]
    pub allow: Vec<McpCapability>,
    /// Denylist applied after defaults / allowlist.
    #[serde(default)]
    pub deny: Vec<McpCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpCapability {
    Logging,
    Completions,
    ResourcesSubscribe,
    ToolsListChanged,
    ResourcesListChanged,
    PromptsListChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpNotificationFilter {
    /// If non-empty, only notifications with these methods are forwarded.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Notifications with these methods are dropped.
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RequestIdNamespacing {
    /// Current format: `unrelated.proxy.<b64(upstream_id)>.<b64(json(request_id))>`.
    #[serde(rename = "opaque")]
    #[default]
    Opaque,
    /// More readable upstream id, with the request id still encoded:
    /// `unrelated.proxy.r.<upstream_id>.<b64(json(request_id))>`.
    #[serde(rename = "readable")]
    Readable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SseEventIdNamespacing {
    /// Current format: `{upstream_id}/{upstream_event_id}`.
    #[serde(rename = "upstream-slash")]
    #[default]
    UpstreamSlash,
    /// Do not modify upstream event ids (may collide across upstreams).
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpNamespacing {
    #[serde(default)]
    pub request_id: RequestIdNamespacing,
    #[serde(default)]
    pub sse_event_id: SseEventIdNamespacing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Maximum number of attempts, including the initial attempt (1 => no retries).
    pub maximum_attempts: u32,
    /// Initial backoff interval in milliseconds (before the first retry).
    pub initial_interval_ms: u64,
    /// Backoff multiplier (typically >= 1.0).
    pub backoff_coefficient: f64,
    /// Optional maximum interval between retries in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_interval_ms: Option<u64>,
    /// Optional list of error category strings that should not be retried.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_retryable_error_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPolicy {
    /// Stable tool reference in the form `"<source_id>:<original_tool_name>"`.
    pub tool: String,
    /// Optional per-tool timeout override (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// Optional per-tool retry policy (Gateway-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryPolicy>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DataPlaneAuthMode {
    Disabled,
    ApiKeyInitializeOnly,
    ApiKeyEveryRequest,
    JwtEveryRequest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamEndpointLifecycle {
    #[default]
    Active,
    Draining,
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamNetworkClass {
    #[default]
    External,
    ClusterInternalManaged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataPlaneAuthSettings {
    pub mode: DataPlaneAuthMode,
    pub accept_x_api_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataPlaneLimitsSettings {
    pub rate_limit_enabled: bool,
    pub rate_limit_tool_calls_per_minute: Option<i64>,
    pub quota_enabled: bool,
    pub quota_tool_calls: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcPrincipalBinding {
    pub issuer: String,
    pub subject: String,
    pub profile_id: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ProfileUpsert {
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub allow_partial_upstreams: bool,
    pub upstreams: Vec<String>,
    pub sources: Vec<String>,
    pub transforms: TransformPipeline,
    pub tools: Vec<String>,
    pub data_plane_auth: Option<DataPlaneAuthSettings>,
    pub data_plane_limits: Option<DataPlaneLimitsSettings>,
    pub tool_call_timeout_secs: Option<u64>,
    pub tool_policies: Option<Vec<ToolPolicy>>,
    pub mcp: Option<McpProfileSettings>,
}

#[derive(Clone)]
pub struct ApiClient {
    admin_base: Url,
    token: String,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new(admin_base: Url, token: String) -> Self {
        Self {
            admin_base,
            token,
            http: reqwest::Client::new(),
        }
    }

    #[must_use]
    pub fn clone_with_token(&self, token: String) -> Self {
        Self {
            admin_base: self.admin_base.clone(),
            token,
            http: self.http.clone(),
        }
    }

    fn url(&self, path: &str) -> anyhow::Result<Url> {
        self.admin_base
            .join(path)
            .with_context(|| format!("join admin_base with path '{path}'"))
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", self.token),
        )
    }

    pub async fn put_tenant(&self, id: &str, enabled: bool) -> anyhow::Result<()> {
        let url = self.url("/admin/v1/tenants")?;
        self.auth(self.http.post(url))
            .json(&PutTenantRequest { id, enabled })
            .send()
            .await
            .context("POST /admin/v1/tenants")?
            .error_for_status()
            .context("POST /admin/v1/tenants status")?;
        Ok(())
    }

    pub async fn list_tenants(&self) -> anyhow::Result<Vec<Tenant>> {
        let url = self.url("/admin/v1/tenants")?;
        let resp: TenantsResponse = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/tenants")?
            .error_for_status()
            .context("GET /admin/v1/tenants status")?
            .json()
            .await
            .context("parse tenants response")?;
        Ok(resp.tenants)
    }

    pub async fn get_tenant(&self, id: &str) -> anyhow::Result<Tenant> {
        let url = self.url(&format!("/admin/v1/tenants/{id}"))?;
        let tenant: Tenant = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/tenants/{id}")?
            .error_for_status()
            .context("GET /admin/v1/tenants/{id} status")?
            .json()
            .await
            .context("parse tenant response")?;
        Ok(tenant)
    }

    pub async fn delete_tenant(&self, id: &str) -> anyhow::Result<()> {
        let url = self.url(&format!("/admin/v1/tenants/{id}"))?;
        self.auth(self.http.delete(url))
            .send()
            .await
            .context("DELETE /admin/v1/tenants/{id}")?
            .error_for_status()
            .context("DELETE /admin/v1/tenants/{id} status")?;
        Ok(())
    }

    pub async fn put_upstream(
        &self,
        id: &str,
        enabled: bool,
        network_class: UpstreamNetworkClass,
        endpoints: Vec<PutEndpoint>,
    ) -> anyhow::Result<()> {
        let url = self.url("/admin/v1/upstreams")?;
        self.auth(self.http.post(url))
            .json(&PutUpstreamRequest {
                id,
                enabled,
                network_class,
                endpoints,
            })
            .send()
            .await
            .context("POST /admin/v1/upstreams")?
            .error_for_status()
            .context("POST /admin/v1/upstreams status")?;
        Ok(())
    }

    pub async fn list_upstreams(&self) -> anyhow::Result<Vec<Upstream>> {
        let url = self.url("/admin/v1/upstreams")?;
        let resp: UpstreamsResponse = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/upstreams")?
            .error_for_status()
            .context("GET /admin/v1/upstreams status")?
            .json()
            .await
            .context("parse upstreams response")?;
        Ok(resp.upstreams)
    }

    pub async fn get_upstream(&self, id: &str) -> anyhow::Result<Upstream> {
        let url = self.url(&format!("/admin/v1/upstreams/{id}"))?;
        let upstream: Upstream = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/upstreams/{id}")?
            .error_for_status()
            .context("GET /admin/v1/upstreams/{id} status")?
            .json()
            .await
            .context("parse upstream response")?;
        Ok(upstream)
    }

    pub async fn delete_upstream(&self, id: &str) -> anyhow::Result<()> {
        let url = self.url(&format!("/admin/v1/upstreams/{id}"))?;
        self.auth(self.http.delete(url))
            .send()
            .await
            .context("DELETE /admin/v1/upstreams/{id}")?
            .error_for_status()
            .context("DELETE /admin/v1/upstreams/{id} status")?;
        Ok(())
    }

    pub async fn create_profile(
        &self,
        profile: ProfileUpsert,
    ) -> anyhow::Result<CreateProfileResponse> {
        let url = self.url("/admin/v1/profiles")?;
        let req = PutProfileRequest {
            id: None,
            tenant_id: &profile.tenant_id,
            name: &profile.name,
            description: profile.description.as_deref(),
            enabled: profile.enabled,
            allow_partial_upstreams: profile.allow_partial_upstreams,
            upstreams: profile.upstreams,
            sources: profile.sources,
            transforms: &profile.transforms,
            tools: Some(profile.tools),
            data_plane_auth: profile.data_plane_auth,
            data_plane_limits: profile.data_plane_limits,
            tool_call_timeout_secs: profile.tool_call_timeout_secs,
            tool_policies: profile.tool_policies,
            mcp: profile.mcp,
        };
        let resp: CreateProfileResponse = self
            .auth(self.http.post(url))
            .json(&req)
            .send()
            .await
            .context("POST /admin/v1/profiles")?
            .error_for_status()
            .context("POST /admin/v1/profiles status")?
            .json()
            .await
            .context("parse create profile response")?;
        Ok(resp)
    }

    pub async fn put_profile(
        &self,
        id: &str,
        profile: ProfileUpsert,
    ) -> anyhow::Result<CreateProfileResponse> {
        let url = self.url("/admin/v1/profiles")?;
        let req = PutProfileRequest {
            id: Some(id),
            tenant_id: &profile.tenant_id,
            name: &profile.name,
            description: profile.description.as_deref(),
            enabled: profile.enabled,
            allow_partial_upstreams: profile.allow_partial_upstreams,
            upstreams: profile.upstreams,
            sources: profile.sources,
            transforms: &profile.transforms,
            tools: Some(profile.tools),
            data_plane_auth: profile.data_plane_auth,
            data_plane_limits: profile.data_plane_limits,
            tool_call_timeout_secs: profile.tool_call_timeout_secs,
            tool_policies: profile.tool_policies,
            mcp: profile.mcp,
        };
        let resp: CreateProfileResponse = self
            .auth(self.http.post(url))
            .json(&req)
            .send()
            .await
            .context("POST /admin/v1/profiles (put)")?
            .error_for_status()
            .context("POST /admin/v1/profiles (put) status")?
            .json()
            .await
            .context("parse put profile response")?;
        Ok(resp)
    }

    pub async fn list_profiles(&self) -> anyhow::Result<Vec<Profile>> {
        let url = self.url("/admin/v1/profiles")?;
        let resp: ProfilesResponse = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/profiles")?
            .error_for_status()
            .context("GET /admin/v1/profiles status")?
            .json()
            .await
            .context("parse profiles response")?;
        Ok(resp.profiles)
    }

    pub async fn get_profile(&self, id: &str) -> anyhow::Result<Profile> {
        let url = self.url(&format!("/admin/v1/profiles/{id}"))?;
        let profile: Profile = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/profiles/{id}")?
            .error_for_status()
            .context("GET /admin/v1/profiles/{id} status")?
            .json()
            .await
            .context("parse profile response")?;
        Ok(profile)
    }

    pub async fn delete_profile(&self, id: &str) -> anyhow::Result<()> {
        let url = self.url(&format!("/admin/v1/profiles/{id}"))?;
        self.auth(self.http.delete(url))
            .send()
            .await
            .context("DELETE /admin/v1/profiles/{id}")?
            .error_for_status()
            .context("DELETE /admin/v1/profiles/{id} status")?;
        Ok(())
    }

    pub async fn issue_tenant_token(
        &self,
        tenant_id: &str,
        ttl_seconds: Option<u64>,
    ) -> anyhow::Result<IssueTenantTokenResponse> {
        let url = self.url("/admin/v1/tenant-tokens")?;
        let resp: IssueTenantTokenResponse = self
            .auth(self.http.post(url))
            .json(&IssueTenantTokenRequest {
                tenant_id: tenant_id.to_string(),
                ttl_seconds,
            })
            .send()
            .await
            .context("POST /admin/v1/tenant-tokens")?
            .error_for_status()
            .context("POST /admin/v1/tenant-tokens status")?
            .json()
            .await
            .context("parse issue tenant token response")?;
        Ok(resp)
    }

    pub async fn list_tool_sources(&self, tenant_id: &str) -> anyhow::Result<Vec<ToolSource>> {
        let url = self.url(&format!("/admin/v1/tenants/{tenant_id}/tool-sources"))?;
        let resp: ToolSourcesResponse = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/tenants/{tenant_id}/tool-sources")?
            .error_for_status()
            .context("GET /admin/v1/tenants/{tenant_id}/tool-sources status")?
            .json()
            .await
            .context("parse tool sources response")?;
        Ok(resp.sources)
    }

    pub async fn get_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<ToolSource> {
        let url = self.url(&format!(
            "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}"
        ))?;
        let source: ToolSource = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/tenants/{tenant_id}/tool-sources/{source_id}")?
            .error_for_status()
            .context("GET /admin/v1/tenants/{tenant_id}/tool-sources/{source_id} status")?
            .json()
            .await
            .context("parse tool source response")?;
        Ok(source)
    }

    pub async fn put_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
        body: serde_json::Value,
    ) -> anyhow::Result<()> {
        let url = self.url(&format!(
            "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}"
        ))?;
        self.auth(self.http.put(url))
            .json(&body)
            .send()
            .await
            .context("PUT /admin/v1/tenants/{tenant_id}/tool-sources/{source_id}")?
            .error_for_status()
            .context("PUT /admin/v1/tenants/{tenant_id}/tool-sources/{source_id} status")?;
        Ok(())
    }

    pub async fn delete_tool_source(&self, tenant_id: &str, source_id: &str) -> anyhow::Result<()> {
        let url = self.url(&format!(
            "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}"
        ))?;
        self.auth(self.http.delete(url))
            .send()
            .await
            .context("DELETE /admin/v1/tenants/{tenant_id}/tool-sources/{source_id}")?
            .error_for_status()
            .context("DELETE /admin/v1/tenants/{tenant_id}/tool-sources/{source_id} status")?;
        Ok(())
    }

    pub async fn list_secrets(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantSecretMetadata>> {
        let url = self.url(&format!("/admin/v1/tenants/{tenant_id}/secrets"))?;
        let resp: SecretsResponse = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/tenants/{tenant_id}/secrets")?
            .error_for_status()
            .context("GET /admin/v1/tenants/{tenant_id}/secrets status")?
            .json()
            .await
            .context("parse secrets response")?;
        Ok(resp.secrets)
    }

    pub async fn put_secret(&self, tenant_id: &str, name: &str, value: &str) -> anyhow::Result<()> {
        let url = self.url(&format!("/admin/v1/tenants/{tenant_id}/secrets/{name}"))?;
        self.auth(self.http.put(url))
            .json(&PutSecretBody { value })
            .send()
            .await
            .context("PUT /admin/v1/tenants/{tenant_id}/secrets/{name}")?
            .error_for_status()
            .context("PUT /admin/v1/tenants/{tenant_id}/secrets/{name} status")?;
        Ok(())
    }

    pub async fn delete_secret(&self, tenant_id: &str, name: &str) -> anyhow::Result<()> {
        let url = self.url(&format!("/admin/v1/tenants/{tenant_id}/secrets/{name}"))?;
        self.auth(self.http.delete(url))
            .send()
            .await
            .context("DELETE /admin/v1/tenants/{tenant_id}/secrets/{name}")?
            .error_for_status()
            .context("DELETE /admin/v1/tenants/{tenant_id}/secrets/{name} status")?;
        Ok(())
    }

    pub async fn list_oidc_principals(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<OidcPrincipalBinding>> {
        let url = self.url(&format!("/admin/v1/tenants/{tenant_id}/oidc-principals"))?;
        let resp: OidcPrincipalsResponse = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /admin/v1/tenants/{tenant_id}/oidc-principals")?
            .error_for_status()
            .context("GET /admin/v1/tenants/{tenant_id}/oidc-principals status")?
            .json()
            .await
            .context("parse oidc principals response")?;
        Ok(resp.principals)
    }

    pub async fn put_oidc_principal(
        &self,
        tenant_id: &str,
        subject: &str,
        profile_id: Option<&str>,
        enabled: bool,
    ) -> anyhow::Result<()> {
        let url = self.url(&format!("/admin/v1/tenants/{tenant_id}/oidc-principals"))?;
        self.auth(self.http.put(url))
            .json(&PutOidcPrincipalRequest {
                subject,
                profile_id,
                enabled,
            })
            .send()
            .await
            .context("PUT /admin/v1/tenants/{tenant_id}/oidc-principals")?
            .error_for_status()
            .context("PUT /admin/v1/tenants/{tenant_id}/oidc-principals status")?;
        Ok(())
    }

    pub async fn delete_oidc_principal(
        &self,
        tenant_id: &str,
        subject: &str,
        profile_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut url = self.url(&format!(
            "/admin/v1/tenants/{tenant_id}/oidc-principals/{subject}"
        ))?;
        if let Some(pid) = profile_id {
            url.query_pairs_mut().append_pair("profileId", pid);
        }
        self.auth(self.http.delete(url))
            .send()
            .await
            .context("DELETE /admin/v1/tenants/{tenant_id}/oidc-principals/{subject}")?
            .error_for_status()
            .context("DELETE /admin/v1/tenants/{tenant_id}/oidc-principals/{subject} status")?;
        Ok(())
    }

    // Tenant API (requires a tenant token as this client's bearer).
    pub async fn list_api_keys(&self) -> anyhow::Result<Vec<ApiKeyMetadata>> {
        let url = self.url("/tenant/v1/api-keys")?;
        let resp: ApiKeysResponse = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("GET /tenant/v1/api-keys")?
            .error_for_status()
            .context("GET /tenant/v1/api-keys status")?
            .json()
            .await
            .context("parse api keys response")?;
        Ok(resp.api_keys)
    }

    pub async fn create_api_key(
        &self,
        name: Option<&str>,
        profile_id: Option<&str>,
    ) -> anyhow::Result<CreateApiKeyResponse> {
        let url = self.url("/tenant/v1/api-keys")?;
        let resp: CreateApiKeyResponse = self
            .auth(self.http.post(url))
            .json(&CreateApiKeyRequest {
                name: name.map(ToString::to_string),
                profile_id: profile_id.map(ToString::to_string),
            })
            .send()
            .await
            .context("POST /tenant/v1/api-keys")?
            .error_for_status()
            .context("POST /tenant/v1/api-keys status")?
            .json()
            .await
            .context("parse create api key response")?;
        Ok(resp)
    }

    pub async fn revoke_api_key(&self, api_key_id: &str) -> anyhow::Result<()> {
        let url = self.url(&format!("/tenant/v1/api-keys/{api_key_id}"))?;
        self.auth(self.http.delete(url))
            .send()
            .await
            .context("DELETE /tenant/v1/api-keys/{api_key_id}")?
            .error_for_status()
            .context("DELETE /tenant/v1/api-keys/{api_key_id} status")?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PutTenantRequest<'a> {
    id: &'a str,
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PutUpstreamRequest<'a> {
    id: &'a str,
    enabled: bool,
    network_class: UpstreamNetworkClass,
    endpoints: Vec<PutEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutEndpoint {
    pub id: String,
    pub url: String,
    pub enabled: bool,
    pub lifecycle: UpstreamEndpointLifecycle,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PutProfileRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    tenant_id: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    enabled: bool,
    allow_partial_upstreams: bool,
    upstreams: Vec<String>,
    #[serde(default)]
    sources: Vec<String>,
    transforms: &'a TransformPipeline,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_plane_auth: Option<DataPlaneAuthSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_plane_limits: Option<DataPlaneLimitsSettings>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_policies: Option<Vec<ToolPolicy>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<McpProfileSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    pub id: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TenantsResponse {
    tenants: Vec<Tenant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamEndpoint {
    pub id: String,
    pub url: String,
    pub enabled: bool,
    pub lifecycle: UpstreamEndpointLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Upstream {
    pub id: String,
    pub enabled: bool,
    pub network_class: UpstreamNetworkClass,
    pub endpoints: Vec<UpstreamEndpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamsResponse {
    upstreams: Vec<Upstream>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub tenant_id: String,
    pub enabled: bool,
    pub allow_partial_upstreams: bool,
    pub upstreams: Vec<String>,
    pub sources: Vec<String>,
    pub transforms: TransformPipeline,
    pub tools: Vec<String>,
    pub data_plane_auth: DataPlaneAuthSettings,
    pub data_plane_limits: DataPlaneLimitsSettings,
    #[serde(default)]
    pub tool_call_timeout_secs: Option<u64>,
    #[serde(default)]
    pub tool_policies: Vec<ToolPolicy>,
    pub mcp: McpProfileSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfilesResponse {
    profiles: Vec<Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProfileResponse {
    pub ok: bool,
    pub id: String,
    pub data_plane_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueTenantTokenRequest {
    tenant_id: String,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueTenantTokenResponse {
    pub ok: bool,
    pub tenant_id: String,
    pub token: String,
    pub exp_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSource {
    pub id: String,
    #[serde(rename = "type")]
    pub tool_type: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToolSourcesResponse {
    sources: Vec<ToolSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantSecretMetadata {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretsResponse {
    secrets: Vec<TenantSecretMetadata>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PutSecretBody<'a> {
    value: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyMetadata {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub profile_id: Option<String>,
    pub revoked_at_unix: Option<i64>,
    pub last_used_at_unix: Option<i64>,
    pub total_tool_calls_attempted: i64,
    pub total_requests_attempted: i64,
    pub created_at_unix: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeysResponse {
    api_keys: Vec<ApiKeyMetadata>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyResponse {
    pub ok: bool,
    pub id: String,
    pub secret: String,
    pub prefix: String,
    pub profile_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OidcPrincipalsResponse {
    principals: Vec<OidcPrincipalBinding>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PutOidcPrincipalRequest<'a> {
    subject: &'a str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_id: Option<&'a str>,
    enabled: bool,
}
