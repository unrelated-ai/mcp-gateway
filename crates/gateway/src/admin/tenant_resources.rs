use super::*;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(super) enum PutToolSourceBody {
    Http {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(flatten)]
        config: HttpServerConfig,
    },
    Openapi {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(flatten)]
        config: ApiServerConfig,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolSourceResponse {
    id: String,
    #[serde(rename = "type")]
    tool_type: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolSourcesResponse {
    sources: Vec<ToolSourceResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PutSecretBody {
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretsResponse {
    secrets: Vec<TenantSecretMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PutOidcPrincipalRequest {
    subject: String,
    /// If set, the principal is scoped to this profile. If omitted, principal is tenant-wide.
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DeleteOidcPrincipalQuery {
    #[serde(default)]
    profile_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OidcPrincipalsResponse {
    principals: Vec<OidcPrincipalBinding>,
}

fn is_valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains(':')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn tool_source_kind_str(k: ToolSourceKind) -> &'static str {
    match k {
        ToolSourceKind::Http => "http",
        ToolSourceKind::Openapi => "openapi",
    }
}

pub(super) async fn list_tool_sources(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.list_tool_sources(&tenant_id).await {
        Ok(list) => {
            let sources = list
                .into_iter()
                .map(|s| ToolSourceResponse {
                    id: s.id,
                    tool_type: tool_source_kind_str(s.kind).to_string(),
                    enabled: s.enabled,
                })
                .collect();
            Json(ToolSourcesResponse { sources }).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub(super) async fn get_tool_source(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, source_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.get_tool_source(&tenant_id, &source_id).await {
        Ok(Some(s)) => Json(ToolSourceResponse {
            id: s.id,
            tool_type: tool_source_kind_str(s.kind).to_string(),
            enabled: s.enabled,
        })
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "tool source not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub(super) async fn put_tool_source(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, source_id)): Path<(String, String)>,
    Json(body): Json<PutToolSourceBody>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let outcome =
        admin_put_tool_source_inner(state.as_ref(), store.as_ref(), &tenant_id, &source_id, body)
            .await;

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor::default(),
            action: "admin.tool_source_put",
            http_method: "PUT",
            http_route: "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}",
            status_code: i32::from(outcome.status.as_u16()),
            ok: outcome.ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "source_id": source_id,
                "kind": outcome.kind_for_meta,
                "enabled": outcome.enabled_for_meta,
            }),
            error: outcome.error,
        }))
        .await;

    outcome.resp
}

struct AdminPutToolSourceOutcome {
    resp: Response,
    status: StatusCode,
    ok: bool,
    error: Option<AuditError>,
    kind_for_meta: Option<String>,
    enabled_for_meta: Option<bool>,
}

impl AdminPutToolSourceOutcome {
    fn fail(status: StatusCode, message: impl Into<String>, error: AuditError) -> Self {
        let msg = message.into();
        Self {
            resp: (status, msg.clone()).into_response(),
            status,
            ok: false,
            error: Some(error),
            kind_for_meta: None,
            enabled_for_meta: None,
        }
    }

    fn fail_with_meta(
        status: StatusCode,
        message: impl Into<String>,
        error: AuditError,
        kind_for_meta: Option<String>,
        enabled_for_meta: Option<bool>,
    ) -> Self {
        let msg = message.into();
        Self {
            resp: (status, msg.clone()).into_response(),
            status,
            ok: false,
            error: Some(error),
            kind_for_meta,
            enabled_for_meta,
        }
    }

    fn ok(kind_for_meta: Option<String>, enabled_for_meta: Option<bool>) -> Self {
        Self {
            resp: Json(OkResponse { ok: true }).into_response(),
            status: StatusCode::OK,
            ok: true,
            error: None,
            kind_for_meta,
            enabled_for_meta,
        }
    }
}

async fn admin_put_tool_source_inner(
    state: &AdminState,
    store: &dyn AdminStore,
    tenant_id: &str,
    source_id: &str,
    body: PutToolSourceBody,
) -> AdminPutToolSourceOutcome {
    if let Err(outcome) =
        admin_put_tool_source_validate_request(state, store, tenant_id, source_id).await
    {
        return outcome;
    }

    let (enabled, kind, spec_res) = match body {
        PutToolSourceBody::Http { enabled, config } => (
            enabled,
            ToolSourceKind::Http,
            serde_json::to_value(&config).map_err(|e| e.to_string()),
        ),
        PutToolSourceBody::Openapi { enabled, config } => (
            enabled,
            ToolSourceKind::Openapi,
            serde_json::to_value(&config).map_err(|e| e.to_string()),
        ),
    };
    let kind_for_meta = Some(tool_source_kind_str(kind).to_string());
    let enabled_for_meta = Some(enabled);

    let spec = match spec_res {
        Ok(v) => v,
        Err(e) => {
            return AdminPutToolSourceOutcome::fail_with_meta(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.clone(),
                AuditError::new("internal_error", e),
                kind_for_meta,
                enabled_for_meta,
            );
        }
    };

    match store
        .put_tool_source(tenant_id, source_id, enabled, kind, spec)
        .await
    {
        Ok(()) => AdminPutToolSourceOutcome::ok(kind_for_meta, enabled_for_meta),
        Err(e) => {
            let msg = e.to_string();
            AdminPutToolSourceOutcome::fail_with_meta(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
                kind_for_meta,
                enabled_for_meta,
            )
        }
    }
}

async fn admin_put_tool_source_validate_request(
    state: &AdminState,
    store: &dyn AdminStore,
    tenant_id: &str,
    source_id: &str,
) -> Result<(), AdminPutToolSourceOutcome> {
    if !is_valid_source_id(source_id) {
        return Err(AdminPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "invalid source id (allowed: [a-zA-Z0-9_-], must not contain ':')",
            AuditError::new("bad_request", "invalid source id"),
        ));
    }
    if state.shared_source_ids.contains(source_id) {
        return Err(AdminPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "source id collides with a shared catalog source id",
            AuditError::new(
                "bad_request",
                "source id collides with a shared catalog source id",
            ),
        ));
    }
    if store.get_upstream(source_id).await.ok().flatten().is_some() {
        return Err(AdminPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "source id collides with an upstream id",
            AuditError::new("bad_request", "source id collides with an upstream id"),
        ));
    }

    match store.get_tenant(tenant_id).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(AdminPutToolSourceOutcome::fail(
            StatusCode::NOT_FOUND,
            "tenant not found",
            AuditError::new("not_found", "tenant not found"),
        )),
        Err(e) => {
            let msg = e.to_string();
            Err(AdminPutToolSourceOutcome::fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
            ))
        }
    }
}

pub(super) async fn delete_tool_source(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, source_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let tenant_id_for_audit = tenant_id.clone();
    let source_id_for_meta = source_id.clone();
    let (status, ok, error, resp) = match store.delete_tool_source(&tenant_id, &source_id).await {
        Ok(true) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            false,
            Some(AuditError::new("not_found", "tool source not found")),
            (StatusCode::NOT_FOUND, "tool source not found").into_response(),
        ),
        Err(e) => {
            let msg = e.to_string();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                Some(AuditError::new("internal_error", msg.clone())),
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
            )
        }
    };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "admin.tool_source_delete",
            http_method: "DELETE",
            http_route: "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "source_id": source_id_for_meta,
            }),
            error,
        }))
        .await;

    resp
}

pub(super) async fn list_secrets(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.list_secrets(&tenant_id).await {
        Ok(secrets) => Json(SecretsResponse { secrets }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub(super) async fn put_secret(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, name)): Path<(String, String)>,
    Json(req): Json<PutSecretBody>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();
    let tenant_id_for_audit = tenant_id.clone();
    let name_for_meta = name.clone();
    let value_len = req.value.len();

    if name.trim().is_empty() {
        let status = StatusCode::BAD_REQUEST;
        let resp = (status, "secret name is required").into_response();
        state
            .audit
            .record(crate::audit::http_event(HttpAuditEvent {
                tenant_id: tenant_id_for_audit,
                actor: AuditActor::default(),
                action: "admin.secret_put",
                http_method: "PUT",
                http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
                status_code: i32::from(status.as_u16()),
                ok: false,
                elapsed: started.elapsed(),
                meta: serde_json::json!({
                    "tenant_id": tenant_id,
                    "name": name,
                    "value_len": value_len,
                }),
                error: Some(AuditError::new("bad_request", "secret name is required")),
            }))
            .await;
        return resp;
    }
    if req.value.is_empty() {
        let status = StatusCode::BAD_REQUEST;
        let resp = (status, "secret value is required").into_response();
        state
            .audit
            .record(crate::audit::http_event(HttpAuditEvent {
                tenant_id: tenant_id_for_audit,
                actor: AuditActor::default(),
                action: "admin.secret_put",
                http_method: "PUT",
                http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
                status_code: i32::from(status.as_u16()),
                ok: false,
                elapsed: started.elapsed(),
                meta: serde_json::json!({
                    "tenant_id": tenant_id,
                    "name": name,
                    "value_len": value_len,
                }),
                error: Some(AuditError::new("bad_request", "secret value is required")),
            }))
            .await;
        return resp;
    }

    let (status, ok, error, resp) = match store.put_secret(&tenant_id, &name, &req.value).await {
        Ok(()) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Err(e) => {
            let msg = e.to_string();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                Some(AuditError::new("internal_error", msg.clone())),
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
            )
        }
    };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "admin.secret_put",
            http_method: "PUT",
            http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "name": name_for_meta,
                "value_len": value_len,
            }),
            error,
        }))
        .await;

    resp
}

pub(super) async fn delete_secret(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, name)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let tenant_id_for_audit = tenant_id.clone();
    let name_for_meta = name.clone();
    let (status, ok, error, resp) = match store.delete_secret(&tenant_id, &name).await {
        Ok(true) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            false,
            Some(AuditError::new("not_found", "secret not found")),
            (StatusCode::NOT_FOUND, "secret not found").into_response(),
        ),
        Err(e) => {
            let msg = e.to_string();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                Some(AuditError::new("internal_error", msg.clone())),
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
            )
        }
    };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "admin.secret_delete",
            http_method: "DELETE",
            http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "name": name_for_meta,
            }),
            error,
        }))
        .await;

    resp
}

fn is_valid_oidc_subject(subject: &str) -> bool {
    // For simplicity and to avoid path confusion, disallow '/'.
    // Cognito/Entra commonly use UUID-like subjects, so this is fine for the current scope.
    let s = subject.trim();
    !s.is_empty() && !s.contains('/')
}

pub(super) async fn list_oidc_principals(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let Some(issuer) = state.oidc_issuer.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuth not configured (set UNRELATED_GATEWAY_OAUTH_ISSUER)",
        )
            .into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match store.list_oidc_principals(&tenant_id, issuer).await {
        Ok(principals) => Json(OidcPrincipalsResponse { principals }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub(super) async fn put_oidc_principal(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(req): Json<PutOidcPrincipalRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let Some(issuer) = state.oidc_issuer.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuth not configured (set UNRELATED_GATEWAY_OAUTH_ISSUER)",
        )
            .into_response();
    };

    let subject = req.subject.trim().to_string();
    if !is_valid_oidc_subject(&subject) {
        return (StatusCode::BAD_REQUEST, "invalid OIDC subject").into_response();
    }

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    if let Some(profile_id) = req.profile_id.as_deref() {
        // Validate UUID and cross-tenant correctness.
        if Uuid::parse_str(profile_id)
            .ok()
            .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
            .is_none()
        {
            return (StatusCode::NOT_FOUND, "profile not found").into_response();
        }
        match store.get_profile(profile_id).await {
            Ok(Some(p)) if p.tenant_id == tenant_id => {}
            Ok(_) => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }

    if let Err(e) = store
        .put_oidc_principal(
            &tenant_id,
            issuer,
            &subject,
            req.profile_id.as_deref(),
            req.enabled,
        )
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    Json(OkResponse { ok: true }).into_response()
}

pub(super) async fn delete_oidc_principal(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, subject)): Path<(String, String)>,
    Query(q): Query<DeleteOidcPrincipalQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let Some(issuer) = state.oidc_issuer.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuth not configured (set UNRELATED_GATEWAY_OAUTH_ISSUER)",
        )
            .into_response();
    };

    let subject = subject.trim().to_string();
    if !is_valid_oidc_subject(&subject) {
        return (StatusCode::BAD_REQUEST, "invalid OIDC subject").into_response();
    }

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match store
        .delete_oidc_principal(&tenant_id, issuer, &subject, q.profile_id.as_deref())
        .await
    {
        Ok(0) => (StatusCode::NOT_FOUND, "oidc principal not found").into_response(),
        Ok(_) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
