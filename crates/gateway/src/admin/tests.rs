use super::*;

#[test]
fn oauth_profiles_require_runtime_configuration() {
    assert!(validate_oauth_configured_if_needed(None, DataPlaneAuthMode::OAuth).is_err());
    assert!(
        validate_oauth_configured_if_needed(
            Some("https://login.example.com"),
            DataPlaneAuthMode::OAuth
        )
        .is_ok()
    );
    assert!(validate_oauth_configured_if_needed(None, DataPlaneAuthMode::ApiKey).is_ok());
}

#[test]
fn managed_mcp_status_filter_defaults_to_pending_and_reconciling() {
    let parsed = parse_managed_mcp_deployment_status_filter(None).expect("parse default");
    assert_eq!(
        parsed,
        vec![
            ManagedMcpDeploymentStatus::Pending,
            ManagedMcpDeploymentStatus::Reconciling
        ]
    );
}

#[test]
fn managed_mcp_status_filter_deduplicates_and_preserves_first_seen_order() {
    let parsed =
        parse_managed_mcp_deployment_status_filter(Some("pending, ready, pending, failed, ready"))
            .expect("parse statuses");
    assert_eq!(
        parsed,
        vec![
            ManagedMcpDeploymentStatus::Pending,
            ManagedMcpDeploymentStatus::Ready,
            ManagedMcpDeploymentStatus::Failed
        ]
    );
}

#[test]
fn managed_mcp_status_filter_rejects_unknown_values() {
    let err = parse_managed_mcp_deployment_status_filter(Some("pending,not-real"))
        .expect_err("should reject unsupported status");
    assert!(err.contains("unsupported status"));
}

#[test]
fn managed_mcp_reconciler_heartbeat_validation_rejects_none_mode_and_empty_id() {
    let req = PutManagedMcpReconcilerHeartbeatRequest {
        mode: ManagedMcpBackendMode::None,
        reconciler_id: "abc".to_string(),
    };
    let err =
        validate_managed_mcp_reconciler_heartbeat_request(&req).expect_err("reject mode=none");
    assert!(err.contains("mode must be k8s or docker"));

    let req = PutManagedMcpReconcilerHeartbeatRequest {
        mode: ManagedMcpBackendMode::K8s,
        reconciler_id: "   ".to_string(),
    };
    let err = validate_managed_mcp_reconciler_heartbeat_request(&req)
        .expect_err("reject empty reconcilerId");
    assert!(err.contains("reconcilerId is required"));
}

#[test]
fn managed_mcp_status_patch_validation_requires_upstream_when_ready() {
    let req = PatchManagedMcpDeploymentRequest {
        status: ManagedMcpDeploymentStatus::Ready,
        upstream_id: None,
        message: None,
    };
    let err = validate_managed_mcp_status_patch_request(&req).expect_err("ready requires upstream");
    assert!(err.contains("upstreamId is required"));

    let req = PatchManagedMcpDeploymentRequest {
        status: ManagedMcpDeploymentStatus::Ready,
        upstream_id: Some("managed_u1".to_string()),
        message: None,
    };
    validate_managed_mcp_status_patch_request(&req).expect("ready with upstream should pass");
}

#[test]
fn upstream_activity_ttl_uses_request_override_and_clamps_to_minimum() {
    assert_eq!(
        crate::pg_store::resolve_upstream_session_activity_ttl_secs(Some(42)),
        42
    );
    assert_eq!(
        crate::pg_store::resolve_upstream_session_activity_ttl_secs(Some(0)),
        1
    );
}
