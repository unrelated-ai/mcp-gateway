use super::McpState;
use crate::session_token::{TokenAuthV1, TokenOidcV1};
use crate::store::DataPlaneAuthMode;
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header::WWW_AUTHENTICATE},
    response::IntoResponse as _,
    response::Response,
};
use std::collections::HashSet;

fn extract_api_key_secret(
    headers: &HeaderMap,
    accept_x_api_key: bool,
) -> Result<Option<String>, &'static str> {
    let has_authorization = headers.contains_key(axum::http::header::AUTHORIZATION);
    let has_x_api_key = headers.contains_key("x-api-key");
    if has_authorization && has_x_api_key {
        return Err("Unauthorized: provide only one API-key credential header");
    }

    if accept_x_api_key && let Some(value) = headers.get("x-api-key").and_then(|h| h.to_str().ok())
    {
        let value = value.trim();
        if !value.is_empty() {
            return Ok(Some(value.to_string()));
        }
    }

    let Some(authz) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    else {
        return Ok(None);
    };
    let Some(token) = authz.strip_prefix("Bearer ").map(str::trim) else {
        return Ok(None);
    };
    Ok((!token.is_empty()).then(|| token.to_string()))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let authz = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?;
    let token = authz.strip_prefix("Bearer ").map(str::trim)?;
    (!token.is_empty()).then(|| token.to_string())
}

pub(super) fn unauthorized(msg: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, msg).into_response()
}

fn escape_challenge_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn oauth_challenge(
    state: &McpState,
    profile: &crate::store::Profile,
    status: StatusCode,
    error: Option<&str>,
    message: &'static str,
) -> Response {
    let Some(oauth) = state.oauth.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "OAuth is not configured").into_response();
    };
    let challenge = build_oauth_challenge(
        &oauth.metadata_url(&profile.id),
        &profile.oauth_required_scopes,
        error,
    );
    let mut response = (status, message).into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}

fn build_oauth_challenge(metadata_url: &str, scopes: &[String], error: Option<&str>) -> String {
    let mut params = vec![format!(
        "resource_metadata=\"{}\"",
        escape_challenge_value(metadata_url)
    )];
    if let Some(error) = error {
        params.push(format!("error=\"{}\"", escape_challenge_value(error)));
    }
    params.push(format!(
        "scope=\"{}\"",
        escape_challenge_value(&scopes.join(" "))
    ));
    format!("Bearer {}", params.join(", "))
}

fn granted_scopes(claims: &serde_json::Value) -> HashSet<String> {
    let mut scopes = HashSet::new();
    for claim in ["scope", "scp"] {
        match claims.get(claim) {
            Some(serde_json::Value::String(value)) => {
                scopes.extend(value.split_ascii_whitespace().map(str::to_string));
            }
            Some(serde_json::Value::Array(values)) => {
                for value in values.iter().filter_map(serde_json::Value::as_str) {
                    scopes.extend(value.split_ascii_whitespace().map(str::to_string));
                }
            }
            _ => {}
        }
    }
    scopes
}

pub(super) async fn authorize_oauth_request(
    state: &McpState,
    profile: &crate::store::Profile,
    headers: &HeaderMap,
) -> Result<TokenOidcV1, Response> {
    let Some(jwt) = extract_bearer_token(headers) else {
        return Err(oauth_challenge(
            state,
            profile,
            StatusCode::UNAUTHORIZED,
            None,
            "Unauthorized: bearer token is required",
        ));
    };
    let Some(oauth) = state.oauth.as_ref() else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "OAuth is not configured").into_response());
    };

    let claims = match oauth.validate(&jwt, &profile.id).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(error = %error, "OAuth access-token validation failed");
            return Err(oauth_challenge(
                state,
                profile,
                StatusCode::UNAUTHORIZED,
                Some("invalid_token"),
                "Unauthorized: invalid bearer token",
            ));
        }
    };

    let scopes = granted_scopes(&claims);
    if profile
        .oauth_required_scopes
        .iter()
        .any(|required| !scopes.contains(required))
    {
        return Err(oauth_challenge(
            state,
            profile,
            StatusCode::FORBIDDEN,
            Some("insufficient_scope"),
            "Forbidden: access token is missing required scopes",
        ));
    }

    let subject = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .or_else(|| claims.get("oid").and_then(serde_json::Value::as_str))
        .ok_or_else(|| {
            oauth_challenge(
                state,
                profile,
                StatusCode::UNAUTHORIZED,
                Some("invalid_token"),
                "Unauthorized: bearer token missing subject",
            )
        })?;

    let allowed = state
        .store
        .is_oidc_principal_allowed(&profile.tenant_id, &profile.id, oauth.issuer(), subject)
        .await
        .map_err(super::internal_error_response("check OAuth principal"))?;
    if !allowed {
        return Err((StatusCode::FORBIDDEN, "Forbidden").into_response());
    }

    Ok(TokenOidcV1 {
        issuer: oauth.issuer().to_string(),
        subject: subject.to_string(),
    })
}

async fn enforce_oauth_in_session(
    state: &McpState,
    profile: &crate::store::Profile,
    headers: &HeaderMap,
    session_oauth: Option<&TokenOidcV1>,
) -> Result<(), Response> {
    let principal = authorize_oauth_request(state, profile, headers).await?;
    let session = session_oauth.ok_or_else(|| {
        unauthorized("Unauthorized: missing OAuth binding in session; re-initialize required")
    })?;
    if session.issuer != principal.issuer || session.subject != principal.subject {
        return Err(unauthorized(
            "Unauthorized: session token principal does not match bearer token",
        ));
    }
    Ok(())
}

pub(super) async fn authenticate_api_key_on_initialize(
    state: &McpState,
    profile: &crate::store::Profile,
    headers: &HeaderMap,
) -> Result<TokenAuthV1, Response> {
    let secret = extract_api_key_secret(headers, profile.accept_x_api_key).map_err(unauthorized)?;
    let Some(secret) = secret else {
        return Err(unauthorized("Unauthorized: API key is required"));
    };

    let api_key = state
        .store
        .authenticate_api_key(&profile.tenant_id, &profile.id, &secret)
        .await
        .map_err(super::internal_error_response("authenticate api key"))?
        .ok_or_else(|| unauthorized("Unauthorized: invalid API key"))?;
    state
        .store
        .touch_api_key(&api_key.tenant_id, &api_key.api_key_id)
        .await
        .map_err(super::internal_error_response("touch api key"))?;

    Ok(TokenAuthV1 {
        tenant_id: api_key.tenant_id,
        api_key_id: api_key.api_key_id,
    })
}

pub(super) async fn enforce_data_plane_auth(
    state: &McpState,
    profile: &crate::store::Profile,
    headers: &HeaderMap,
    session_auth: Option<&TokenAuthV1>,
    session_oauth: Option<&TokenOidcV1>,
) -> Result<(), Response> {
    match profile.data_plane_auth_mode {
        DataPlaneAuthMode::Disabled => Ok(()),
        DataPlaneAuthMode::ApiKey => {
            enforce_api_key_every_request(state, profile, headers, session_auth).await
        }
        DataPlaneAuthMode::OAuth => {
            enforce_oauth_in_session(state, profile, headers, session_oauth).await
        }
    }
}

async fn enforce_api_key_every_request(
    state: &McpState,
    profile: &crate::store::Profile,
    headers: &HeaderMap,
    session_auth: Option<&TokenAuthV1>,
) -> Result<(), Response> {
    let auth = session_auth.ok_or_else(|| {
        unauthorized("Unauthorized: missing API key in session; re-initialize required")
    })?;
    if auth.tenant_id != profile.tenant_id {
        return Err(unauthorized("Unauthorized"));
    }

    let secret = extract_api_key_secret(headers, profile.accept_x_api_key).map_err(unauthorized)?;
    let Some(secret) = secret else {
        return Err(unauthorized("Unauthorized: API key header is required"));
    };
    let api_key = state
        .store
        .authenticate_api_key(&profile.tenant_id, &profile.id, &secret)
        .await
        .map_err(super::internal_error_response("authenticate api key"))?
        .ok_or_else(|| unauthorized("Unauthorized: invalid API key"))?;
    if api_key.api_key_id != auth.api_key_id {
        return Err(unauthorized("Unauthorized"));
    }
    state
        .store
        .touch_api_key(&api_key.tenant_id, &api_key.api_key_id)
        .await
        .map_err(super::internal_error_response("touch api key"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_scope_and_entra_scp_string_or_array() {
        let claims = serde_json::json!({
            "scope": "mcp:access tools:read",
            "scp": ["tenant:read", "tenant:write audit:read"]
        });
        let scopes = granted_scopes(&claims);
        for expected in [
            "mcp:access",
            "tools:read",
            "tenant:read",
            "tenant:write",
            "audit:read",
        ] {
            assert!(scopes.contains(expected));
        }
    }

    #[test]
    fn rejects_ambiguous_api_key_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer key"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("key"));
        assert!(extract_api_key_secret(&headers, true).is_err());
    }

    #[test]
    fn builds_safe_oauth_challenges() {
        let scopes = vec!["mcp:access".to_string(), "tools:read".to_string()];
        let missing = build_oauth_challenge("https://mcp.example/meta", &scopes, None);
        assert!(missing.contains("resource_metadata=\"https://mcp.example/meta\""));
        assert!(missing.contains("scope=\"mcp:access tools:read\""));
        assert!(!missing.contains("error="));

        let invalid =
            build_oauth_challenge("https://mcp.example/meta", &scopes, Some("invalid_token"));
        assert!(invalid.contains("error=\"invalid_token\""));
        assert!(!invalid.contains('\n'));
    }
}
