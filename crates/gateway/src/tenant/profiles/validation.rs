//! Profile validation and update planning, independent of HTTP responses and persistence.

use super::{CreateProfileRequest, PutProfileRequest};
use crate::profile_http::{
    DataPlaneAuthSettings, DataPlaneLimitsSettings, NullableString, resolve_nullable_u64,
    validate_tool_allowlist, validate_tool_timeout_and_policies,
};
use crate::store::{AdminProfile, DataPlaneAuthMode, McpProfileSettings};
use crate::tool_policy::ToolPolicy;

const OAUTH_NOT_CONFIGURED_MSG: &str = "OAuth is unavailable because data-plane OAuth is not configured on the Gateway. Configure UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL and UNRELATED_GATEWAY_OAUTH_ISSUER, or choose a different mode.";

#[derive(Debug)]
pub(super) struct ValidatedSettings {
    pub enabled_tools: Vec<String>,
    pub data_plane_auth: DataPlaneAuthSettings,
    pub data_plane_limits: DataPlaneLimitsSettings,
    pub tool_call_timeout_secs: Option<u64>,
    pub tool_policies: Vec<ToolPolicy>,
    pub mcp: McpProfileSettings,
}

#[derive(Debug)]
pub(super) struct ProfileUpdate {
    pub name: String,
    pub description: Option<String>,
    pub settings: ValidatedSettings,
}

#[derive(Debug)]
pub(super) enum ValidationError {
    NameRequired,
    Settings { message: String, detail: String },
}

impl ValidationError {
    pub(super) fn message(&self) -> &str {
        match self {
            Self::NameRequired => "name is required",
            Self::Settings { message, .. } => message,
        }
    }

    pub(super) fn detail(&self) -> &str {
        match self {
            Self::NameRequired => "name is required",
            Self::Settings { detail, .. } => detail,
        }
    }

    fn settings(message: impl Into<String>) -> Self {
        let message = message.into();
        Self::Settings {
            detail: message.clone(),
            message,
        }
    }
}

pub(super) fn validate_create(
    req: &CreateProfileRequest,
    oauth_available: bool,
) -> Result<ValidatedSettings, ValidationError> {
    validate_name(&req.name)?;
    let settings = ValidatedSettings {
        enabled_tools: req.tools.clone().unwrap_or_default(),
        data_plane_auth: req.data_plane_auth.clone().unwrap_or_default(),
        data_plane_limits: req
            .data_plane_limits
            .clone()
            .unwrap_or(DataPlaneLimitsSettings {
                rate_limit_enabled: false,
                rate_limit_tool_calls_per_minute: None,
                quota_enabled: false,
                quota_tool_calls: None,
            }),
        tool_call_timeout_secs: req.tool_call_timeout_secs,
        tool_policies: req.tool_policies.clone(),
        mcp: req.mcp.clone(),
    };
    validate_settings(settings, oauth_available, false)
}

pub(super) fn plan_update(
    req: &PutProfileRequest,
    existing: &AdminProfile,
    oauth_available: bool,
) -> Result<ProfileUpdate, ValidationError> {
    let name = req.name.clone().unwrap_or_else(|| existing.name.clone());
    validate_name(&name)?;
    let description = match &req.description {
        None => existing.description.clone(),
        Some(NullableString::Null) => None,
        Some(NullableString::Value(value)) => Some(value.clone()),
    };
    let settings = ValidatedSettings {
        // The existing API replaces the allowlist on PUT, even when omitted.
        enabled_tools: req.tools.clone().unwrap_or_default(),
        data_plane_auth: req.data_plane_auth.clone().unwrap_or_else(|| {
            DataPlaneAuthSettings::from_parts(
                existing.data_plane_auth_mode,
                existing.accept_x_api_key,
                existing.oauth_required_scopes.clone(),
            )
        }),
        data_plane_limits: req
            .data_plane_limits
            .clone()
            .unwrap_or(DataPlaneLimitsSettings {
                rate_limit_enabled: existing.rate_limit_enabled,
                rate_limit_tool_calls_per_minute: existing.rate_limit_tool_calls_per_minute,
                quota_enabled: existing.quota_enabled,
                quota_tool_calls: existing.quota_tool_calls,
            }),
        tool_call_timeout_secs: resolve_nullable_u64(
            req.tool_call_timeout_secs,
            existing.tool_call_timeout_secs,
        ),
        tool_policies: req
            .tool_policies
            .clone()
            .unwrap_or_else(|| existing.tool_policies.clone()),
        mcp: req.mcp.clone().unwrap_or_else(|| existing.mcp.clone()),
    };
    Ok(ProfileUpdate {
        name,
        description,
        settings: validate_settings(settings, oauth_available, true)?,
    })
}

fn validate_name(name: &str) -> Result<(), ValidationError> {
    if name.trim().is_empty() {
        return Err(ValidationError::NameRequired);
    }
    Ok(())
}

fn validate_settings(
    mut settings: ValidatedSettings,
    oauth_available: bool,
    updating: bool,
) -> Result<ValidatedSettings, ValidationError> {
    settings.data_plane_auth.validate().map_err(|detail| {
        // Keep the existing PUT response and its more detailed audit message.
        let message = if updating {
            "invalid OAuth scopes".to_string()
        } else {
            detail.clone()
        };
        ValidationError::Settings { message, detail }
    })?;
    if settings.data_plane_auth.mode() == DataPlaneAuthMode::OAuth && !oauth_available {
        return Err(ValidationError::settings(OAUTH_NOT_CONFIGURED_MSG));
    }
    settings
        .data_plane_limits
        .validate()
        .map_err(ValidationError::settings)?;
    validate_tool_timeout_and_policies(settings.tool_call_timeout_secs, &settings.tool_policies)
        .map_err(ValidationError::settings)?;
    validate_tool_allowlist(&settings.enabled_tools).map_err(ValidationError::settings)?;
    crate::transport_limits::validate_transport_limits_settings(
        &settings.mcp.security.transport_limits,
    )
    .map_err(ValidationError::settings)?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_http::NullableU64;
    use serde_json::json;

    fn existing() -> AdminProfile {
        AdminProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Original".to_string(),
            description: Some("Description".to_string()),
            tenant_id: "tenant".to_string(),
            enabled: true,
            allow_partial_upstreams: true,
            upstream_ids: vec![],
            source_ids: vec![],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: vec!["source:echo".to_string()],
            data_plane_auth_mode: DataPlaneAuthMode::ApiKey,
            accept_x_api_key: true,
            oauth_required_scopes: vec![],
            rate_limit_enabled: true,
            rate_limit_tool_calls_per_minute: Some(100),
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: Some(15),
            tool_policies: vec![ToolPolicy {
                tool: "source:echo".to_string(),
                timeout_secs: Some(10),
                retry: None,
            }],
            mcp: McpProfileSettings::default(),
        }
    }

    #[test]
    fn omitted_update_settings_preserve_existing_except_replacement_allowlist() {
        let request = serde_json::from_value(json!({"upstreams": []})).unwrap();
        let update = plan_update(&request, &existing(), false).unwrap();
        assert_eq!(update.name, "Original");
        assert_eq!(update.description.as_deref(), Some("Description"));
        assert_eq!(update.settings.tool_call_timeout_secs, Some(15));
        assert_eq!(update.settings.tool_policies[0].timeout_secs, Some(10));
        assert!(update.settings.enabled_tools.is_empty());
        assert!(update.settings.data_plane_auth.accept_x_api_key());
        assert_eq!(
            update
                .settings
                .data_plane_limits
                .rate_limit_tool_calls_per_minute,
            Some(100)
        );
    }

    #[test]
    fn explicit_clears_and_replacements_are_planned_without_mutating_existing() {
        let stored = existing();
        let mut request: PutProfileRequest = serde_json::from_value(json!({
            "upstreams": [], "name": "Changed", "toolPolicies": [],
            "tools": ["other:tool"], "dataPlaneAuth": {"mode": "disabled"}
        }))
        .unwrap();
        request.description = Some(NullableString::Null);
        request.tool_call_timeout_secs = Some(NullableU64::Null);
        let update = plan_update(&request, &stored, false).unwrap();
        assert_eq!(update.name, "Changed");
        assert!(update.description.is_none());
        assert!(update.settings.tool_call_timeout_secs.is_none());
        assert!(update.settings.tool_policies.is_empty());
        assert_eq!(update.settings.enabled_tools, ["other:tool"]);
        assert_eq!(
            update.settings.data_plane_auth.mode(),
            DataPlaneAuthMode::Disabled
        );
        assert_eq!(stored.description.as_deref(), Some("Description"));
        assert_eq!(stored.tool_call_timeout_secs, Some(15));
    }

    #[test]
    fn create_and_update_apply_same_validation_and_scope_normalization() {
        for payload in [
            json!({"name": " ", "upstreams": []}),
            json!({"name": "Valid", "upstreams": [], "toolCallTimeoutSecs": 0}),
            json!({"name": "Valid", "upstreams": [], "tools": ["*"]}),
            json!({"name": "Valid", "upstreams": [], "dataPlaneLimits": {"quotaEnabled": true}}),
        ] {
            let create: CreateProfileRequest = serde_json::from_value(payload.clone()).unwrap();
            let put: PutProfileRequest = serde_json::from_value(payload).unwrap();
            let create_error = validate_create(&create, false).unwrap_err();
            let update_error = plan_update(&put, &existing(), false).unwrap_err();
            assert_eq!(create_error.message(), update_error.message());
        }
        let payload = json!({"name": "OAuth", "upstreams": [], "dataPlaneAuth": {
            "mode": "oauth", "requiredScopes": ["mcp:access", "mcp:access"]
        }});
        let create: CreateProfileRequest = serde_json::from_value(payload.clone()).unwrap();
        let put: PutProfileRequest = serde_json::from_value(payload).unwrap();
        assert_eq!(
            validate_create(&create, false).unwrap_err().message(),
            OAUTH_NOT_CONFIGURED_MSG
        );
        assert_eq!(
            plan_update(&put, &existing(), false).unwrap_err().message(),
            OAUTH_NOT_CONFIGURED_MSG
        );
        assert_eq!(
            validate_create(&create, true)
                .unwrap()
                .data_plane_auth
                .required_scopes(),
            ["mcp:access"]
        );
        assert_eq!(
            plan_update(&put, &existing(), true)
                .unwrap()
                .settings
                .data_plane_auth
                .required_scopes(),
            ["mcp:access"]
        );
    }
}
