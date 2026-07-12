use super::*;

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?;
    let token = auth.strip_prefix("Bearer ")?;
    if token.trim().is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn collect_scope_tokens_from_claim(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::String(s) => {
            for token in s.split([' ', ',']).map(str::trim).filter(|v| !v.is_empty()) {
                out.insert(token.to_string());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    for token in s.split([' ', ',']).map(str::trim).filter(|v| !v.is_empty()) {
                        out.insert(token.to_string());
                    }
                }
            }
        }
        _ => {}
    }
}

fn extract_machine_scopes(claims: &serde_json::Value) -> HashSet<String> {
    let mut out = HashSet::new();
    for key in ["scope", "scp", "roles", "role", "permissions"] {
        if let Some(value) = claims.get(key) {
            collect_scope_tokens_from_claim(value, &mut out);
        }
    }
    out
}

fn required_control_plane_scopes(state: &AdminState, method: &Method) -> Vec<String> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        vec![
            state.control_plane_scope_read.clone(),
            state.control_plane_scope_write.clone(),
        ]
    } else {
        vec![state.control_plane_scope_write.clone()]
    }
}

async fn authorize_control_plane(
    headers: &HeaderMap,
    state: &AdminState,
    required_scopes: &[String],
) -> Result<ControlPlanePrincipal, (StatusCode, String)> {
    let Some(token) = extract_bearer_token(headers) else {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    };

    if let Some(expected) = state.admin_token.as_deref() {
        let want = format!("Bearer {expected}");
        let got = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        if got == want {
            return Ok(ControlPlanePrincipal {
                auth_kind: "static-token",
                ..ControlPlanePrincipal::default()
            });
        }
    }

    let Some(oidc) = state.control_plane_oidc.as_ref() else {
        if state.admin_token.is_some() {
            return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
        }
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Admin API disabled (configure control-plane OIDC or UNRELATED_GATEWAY_ADMIN_TOKEN)"
                .to_string(),
        ));
    };

    let claims = oidc
        .validate(&token)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()))?;
    let scopes_set = extract_machine_scopes(&claims);
    if !required_scopes.is_empty()
        && !required_scopes
            .iter()
            .any(|required| scopes_set.contains(required))
    {
        return Err((StatusCode::FORBIDDEN, "Forbidden".to_string()));
    }

    let mut scopes = scopes_set.into_iter().collect::<Vec<_>>();
    scopes.sort();
    Ok(ControlPlanePrincipal {
        auth_kind: "oidc",
        issuer: claims
            .get("iss")
            .and_then(serde_json::Value::as_str)
            .map(std::string::ToString::to_string),
        subject: claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .map(std::string::ToString::to_string),
        scopes,
    })
}

async fn record_control_plane_auth_event(
    state: &AdminState,
    method: &Method,
    route: &str,
    status: StatusCode,
    required_scopes: &[String],
    principal: Option<&ControlPlanePrincipal>,
    elapsed: std::time::Duration,
) {
    let ok = status.is_success();
    let error_kind = (!ok).then_some("unauthorized".to_string());
    let error_message = (!ok).then_some(
        status
            .canonical_reason()
            .unwrap_or("Unauthorized")
            .to_string(),
    );
    state
        .audit
        .record(AuditEvent {
            tenant_id: "system".to_string(),
            profile_id: None,
            api_key_id: None,
            oidc_issuer: principal.and_then(|p| p.issuer.clone()),
            oidc_subject: principal.and_then(|p| p.subject.clone()),
            action: "admin.control_plane_auth".to_string(),
            http_method: Some(method.as_str().to_string()),
            http_route: Some(route.to_string()),
            status_code: Some(i32::from(status.as_u16())),
            tool_ref: None,
            tool_name_at_time: None,
            ok,
            duration_ms: duration_ms(elapsed),
            error_kind,
            error_message,
            meta: serde_json::json!({
                "auth_kind": principal.map_or("none", |p| p.auth_kind),
                "required_scopes": required_scopes,
                "granted_scopes": principal.map(|p| p.scopes.clone()).unwrap_or_default(),
            }),
        })
        .await;
}

pub(super) async fn control_plane_auth_middleware(
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(state) = req.extensions().get::<Arc<AdminState>>().cloned() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Admin state extension missing",
        )
            .into_response();
    };

    let method = req.method().clone();
    let route = req.uri().path().to_string();
    let started = Instant::now();
    let required_scopes = required_control_plane_scopes(state.as_ref(), &method);
    match authorize_control_plane(req.headers(), state.as_ref(), &required_scopes).await {
        Ok(principal) => {
            record_control_plane_auth_event(
                state.as_ref(),
                &method,
                &route,
                StatusCode::OK,
                &required_scopes,
                Some(&principal),
                started.elapsed(),
            )
            .await;
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        Err((status, message)) => {
            record_control_plane_auth_event(
                state.as_ref(),
                &method,
                &route,
                status,
                &required_scopes,
                None,
                started.elapsed(),
            )
            .await;
            (status, message).into_response()
        }
    }
}

pub(super) fn authz(headers: &HeaderMap, expected: Option<&str>) -> Result<(), impl IntoResponse> {
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if let Some(expected) = expected {
        let want = format!("Bearer {expected}");
        if got == want {
            return Ok(());
        }
    }
    if got.starts_with("Bearer ") {
        return Ok(());
    }
    Err((StatusCode::UNAUTHORIZED, "Unauthorized"))
}
