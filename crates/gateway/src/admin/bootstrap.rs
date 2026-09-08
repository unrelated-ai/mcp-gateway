use super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BootstrapTenantRequest {
    /// First tenant id to create as the initial tenant.
    tenant_id: String,
    /// Optional tenant token TTL (seconds). Defaults to 365 days.
    #[serde(default)]
    ttl_seconds: Option<u64>,
    /// If true (default), create a starter profile for the new tenant.
    #[serde(default = "default_true")]
    create_profile: bool,
    /// Starter profile name when `createProfile` is true.
    #[serde(default)]
    profile_name: Option<String>,
    /// Starter profile description when `createProfile` is true.
    #[serde(default)]
    profile_description: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapTenantResponse {
    ok: bool,
    tenant_id: String,
    token: String,
    exp_unix_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_plane_path: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapTenantStatusResponse {
    bootstrap_enabled: bool,
    can_bootstrap: bool,
    tenant_count: usize,
}

pub(super) async fn bootstrap_tenant_status(
    Extension(state): Extension<Arc<AdminState>>,
) -> impl IntoResponse {
    // Mirror the bootstrap endpoint behavior: hidden unless explicitly enabled.
    if !state.bootstrap_enabled {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    let tenants = match store.list_tenants().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Json(BootstrapTenantStatusResponse {
        bootstrap_enabled: true,
        can_bootstrap: tenants.is_empty(),
        tenant_count: tenants.len(),
    })
    .into_response()
}

struct BootstrapProfileResult {
    profile_id: String,
    data_plane_path: String,
}

async fn create_bootstrap_profile(
    store: &Arc<dyn AdminStore>,
    tenant_id: &str,
    req: &BootstrapTenantRequest,
) -> Result<Option<BootstrapProfileResult>, Response> {
    if !req.create_profile {
        return Ok(None);
    }
    let profile_id = Uuid::new_v4().to_string();
    let name = req
        .profile_name
        .as_deref()
        .unwrap_or("Starter profile")
        .trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "profileName must be non-empty").into_response());
    }
    let description = req.profile_description.as_deref();
    let (transforms, mcp) = (TransformPipeline::default(), McpProfileSettings::default());
    if let Err(e) = store
        .put_profile(PutProfileInput {
            profile_id: &profile_id,
            tenant_id,
            name,
            description,
            flags: PutProfileFlags {
                enabled: true,
                allow_partial_upstreams: true,
            },
            upstream_ids: &[],
            source_ids: &[],
            transforms: &transforms,
            enabled_tools: &[],
            data_plane_auth: PutProfileDataPlaneAuth {
                // Security posture: strict mode by default for newly created starter profiles.
                mode: DataPlaneAuthMode::ApiKey,
                accept_x_api_key: false,
                oauth_required_scopes: Vec::new(),
            },
            limits: PutProfileLimits {
                rate_limit_enabled: false,
                rate_limit_tool_calls_per_minute: None,
                quota_enabled: false,
                quota_tool_calls: None,
            },
            tool_call_timeout_secs: None,
            tool_policies: &[],
            mcp: &mcp,
        })
        .await
    {
        if e.to_string().contains("profiles_tenant_name_ci_uq") {
            return Err((
                StatusCode::CONFLICT,
                "profile name already exists for this tenant (case-insensitive)",
            )
                .into_response());
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response());
    }
    Ok(Some(BootstrapProfileResult {
        data_plane_path: format!("/{profile_id}/mcp"),
        profile_id,
    }))
}

fn issue_bootstrap_token(
    signer: &TenantSigner,
    tenant_id: &str,
    ttl_seconds: Option<u64>,
) -> Result<(String, u64), (StatusCode, String)> {
    let ttl = ttl_seconds.unwrap_or(31_536_000);
    let now = match now_unix_secs() {
        Ok(n) => n,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };
    let exp = now.saturating_add(ttl).max(now + 1);
    let payload = TenantTokenPayloadV1 {
        tenant_id: tenant_id.to_string(),
        exp_unix_secs: exp,
    };
    match signer.sign_v1(&payload) {
        Ok(token) => Ok((token, exp)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

pub(super) async fn bootstrap_tenant(
    Extension(state): Extension<Arc<AdminState>>,
    Json(req): Json<BootstrapTenantRequest>,
) -> impl IntoResponse {
    // Safety: only enabled explicitly.
    if !state.bootstrap_enabled {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    let tenant_id = req.tenant_id.trim();
    if tenant_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "tenantId is required").into_response();
    }

    // Only allow bootstrapping on an empty DB.
    let existing = match store.list_tenants().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !existing.is_empty() {
        return (StatusCode::CONFLICT, "already bootstrapped").into_response();
    }

    if let Err(e) = store.put_tenant(tenant_id, true).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let bootstrap_profile = match create_bootstrap_profile(store, tenant_id, &req).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let (token, exp_unix_secs) =
        match issue_bootstrap_token(&state.tenant_signer, tenant_id, req.ttl_seconds) {
            Ok(v) => v,
            Err((status, message)) => return (status, message).into_response(),
        };

    Json(BootstrapTenantResponse {
        ok: true,
        tenant_id: tenant_id.to_string(),
        token,
        exp_unix_secs,
        profile_id: bootstrap_profile.as_ref().map(|p| p.profile_id.clone()),
        data_plane_path: bootstrap_profile.map(|p| p.data_plane_path),
    })
    .into_response()
}
