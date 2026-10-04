//! The existing plain-text control-plane error contract.
use http::StatusCode;
use std::{borrow::Cow, fmt};

#[derive(Debug, Clone, Copy)]
pub enum StoreKind {
    Admin,
    Tenant,
}

#[derive(Debug, Clone, Copy)]
pub enum Resource {
    Tenant,
    Profile,
    Upstream,
    Endpoint,
    ToolSource,
    Secret,
    Deployment,
}

impl Resource {
    #[must_use]
    pub const fn not_found_message(self) -> &'static str {
        match self {
            Self::Tenant => "tenant not found",
            Self::Profile => "profile not found",
            Self::Upstream => "upstream not found",
            Self::Endpoint => "upstream endpoint not found",
            Self::ToolSource => "tool source not found",
            Self::Secret => "secret not found",
            Self::Deployment => "deployment request not found",
        }
    }
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: Cow<'static, str>,
}

impl ApiError {
    #[must_use]
    pub const fn store_unavailable(kind: StoreKind) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: Cow::Borrowed(match kind {
                StoreKind::Admin => "Admin store unavailable",
                StoreKind::Tenant => "Tenant store unavailable",
            }),
        }
    }

    #[must_use]
    pub const fn not_found(resource: Resource) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: Cow::Borrowed(resource.not_found_message()),
        }
    }

    #[must_use]
    pub fn internal(error: impl fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: Cow::Owned(error.to_string()),
        }
    }

    #[must_use]
    pub const fn invalid_tenant() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: Cow::Borrowed("invalid tenant"),
        }
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}
impl std::error::Error for ApiError {}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_errors_preserve_status_and_public_text() {
        for (error, status, message) in [
            (
                ApiError::store_unavailable(StoreKind::Admin),
                503,
                "Admin store unavailable",
            ),
            (
                ApiError::store_unavailable(StoreKind::Tenant),
                503,
                "Tenant store unavailable",
            ),
            (
                ApiError::not_found(Resource::Profile),
                404,
                "profile not found",
            ),
            (
                ApiError::not_found(Resource::Endpoint),
                404,
                "upstream endpoint not found",
            ),
            (ApiError::invalid_tenant(), 401, "invalid tenant"),
            (
                ApiError::internal("database unavailable"),
                500,
                "database unavailable",
            ),
        ] {
            assert_eq!(error.status().as_u16(), status);
            assert_eq!(error.to_string(), message);
            #[cfg(feature = "axum")]
            {
                use axum::response::IntoResponse as _;
                let response = error.into_response();
                assert_eq!(response.status().as_u16(), status);
                assert_eq!(
                    response.headers()[http::header::CONTENT_TYPE],
                    "text/plain; charset=utf-8"
                );
            }
        }
    }
}
