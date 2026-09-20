//! Operator planning.
use super::*;

pub(super) fn build_managed_deployment_plan(
    request: GatewayDeploymentRequest,
    deployables: &[GatewayDeployable],
) -> Result<ManagedDeploymentPlan, ManagedDeploymentPlanError> {
    let desired_replicas = desired_replicas_for_request(&request);
    let request_id = request.id;
    let tenant_id = request.tenant_id;
    let deployable_id = request.deployable_id;
    let Some(deployable) = deployables.iter().find(|d| d.id == deployable_id).cloned() else {
        return Err(ManagedDeploymentPlanError {
            request_id,
            message: format!("deployable '{deployable_id}' is missing or disabled"),
        });
    };
    Ok(ManagedDeploymentPlan {
        request_id: request_id.clone(),
        tenant_id: tenant_id.clone(),
        desired_replicas,
        upstream_id: managed_upstream_id_for_request(&tenant_id, &request_id),
        endpoint_port: service_port_from_default_upstream_url(&deployable.default_upstream_url),
        endpoint_path: endpoint_path_from_default_upstream_url(&deployable.default_upstream_url),
        endpoint_scheme: endpoint_scheme_from_default_upstream_url(
            &deployable.default_upstream_url,
        ),
        deployable,
    })
}

pub(super) fn managed_upstream_id_for_request(tenant_id: &str, request_id: &str) -> String {
    let upstream_id = sanitize_identifier(&format!("managed_{tenant_id}_{request_id}"));
    if upstream_id.is_empty() {
        format!("managed_{request_id}")
    } else {
        upstream_id
    }
}

pub(super) fn desired_replicas_for_request(request: &GatewayDeploymentRequest) -> i32 {
    if !request.desired_enabled {
        return 0;
    }
    request.desired_replicas.max(1)
}

pub(super) fn mcpserver_name_for_request(request_id: &str) -> String {
    let suffix: String = request_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(MCPSERVER_NAME_SUFFIX_LEN)
        .collect();
    let suffix = if suffix.is_empty() {
        "request".to_string()
    } else {
        suffix.to_ascii_lowercase()
    };
    truncate_dns_label(&format!("managed-{suffix}"))
}

pub(super) fn endpoint_path_from_default_upstream_url(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return DEFAULT_ENDPOINT_PATH.to_string();
    };
    let path = parsed.path();
    if path.is_empty() || path == "/" {
        DEFAULT_ENDPOINT_PATH.to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

pub(super) fn endpoint_scheme_from_default_upstream_url(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return DEFAULT_ENDPOINT_SCHEME.to_string();
    };
    match parsed.scheme() {
        "http" | "https" => parsed.scheme().to_string(),
        _ => DEFAULT_ENDPOINT_SCHEME.to_string(),
    }
}

pub(super) fn service_port_from_default_upstream_url(url: &str) -> i32 {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return DEFAULT_SERVICE_PORT;
    };
    if let Some(port) = parsed.port() {
        return i32::from(port);
    }
    match parsed.scheme() {
        "http" => DEFAULT_HTTP_PORT,
        "https" => DEFAULT_HTTPS_PORT,
        _ => DEFAULT_SERVICE_PORT,
    }
}

pub(super) fn build_reconcile_plan(
    mcp_server: &McpServer,
    status: &McpServerStatus,
) -> Result<ReconcilePlan, ReconcileError> {
    let namespace = mcp_server
        .namespace()
        .ok_or(ReconcileError::MissingNamespace)?;
    let name = mcp_server.name_any();
    let rollback_requested = mcp_server
        .spec
        .rollout
        .as_ref()
        .and_then(|r| r.force_rollback)
        .unwrap_or(false);
    let desired_image = if rollback_requested {
        status.stable_image.clone().ok_or_else(|| {
            ReconcileError::Config(
                "rollback requested but no stable image is available in status".to_string(),
            )
        })?
    } else {
        mcp_server.spec.image.clone()
    };
    let service_name = desired_service_name(&name);
    let service_port = desired_service_port(&mcp_server.spec);
    let endpoint_path = desired_endpoint_path(&mcp_server.spec);
    let tenant_id = mcp_server
        .meta()
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_TENANT_ID))
        .cloned();

    Ok(ReconcilePlan {
        tenant_id,
        deployment_name: desired_deployment_name(&name),
        service_name: service_name.clone(),
        service_port,
        desired_replicas: mcp_server.spec.replicas.unwrap_or(1).max(0),
        desired_endpoint_id: endpoint_id_for_image(&desired_image),
        desired_upstream_id: desired_upstream_id(mcp_server, &namespace),
        endpoint_url: desired_endpoint_url(&service_name, &namespace, service_port, &endpoint_path),
        request_id: mcp_server
            .spec
            .gateway
            .as_ref()
            .and_then(|g| g.deployment_request_id.clone()),
        desired_image,
        rollback_requested,
        namespace,
    })
}

pub(super) fn desired_upstream_id(mcp_server: &McpServer, namespace: &str) -> String {
    if let Some(configured) = mcp_server
        .spec
        .gateway
        .as_ref()
        .and_then(|g| g.upstream_id.as_ref())
    {
        let sanitized = sanitize_identifier(configured);
        if !sanitized.is_empty() {
            return sanitized;
        }
    }
    let generated =
        sanitize_identifier(&format!("managed_{}_{}", namespace, mcp_server.name_any()));
    if generated.is_empty() {
        "managed_mcpserver".to_string()
    } else {
        generated
    }
}

pub(super) fn desired_deployment_name(name: &str) -> String {
    truncate_dns_label(&format!("{}-deploy", sanitize_dns_label(name)))
}

pub(super) fn desired_service_name(name: &str) -> String {
    truncate_dns_label(&format!("{}-svc", sanitize_dns_label(name)))
}

pub(super) fn desired_service_port(spec: &McpServerSpec) -> i32 {
    spec.service
        .as_ref()
        .and_then(|s| s.port)
        .filter(|p| (MIN_SERVICE_PORT..=MAX_SERVICE_PORT).contains(p))
        .unwrap_or(DEFAULT_SERVICE_PORT)
}

pub(super) fn desired_endpoint_path(spec: &McpServerSpec) -> String {
    let raw = spec
        .gateway
        .as_ref()
        .and_then(|g| g.endpoint_path.as_ref())
        .map_or(DEFAULT_ENDPOINT_PATH, String::as_str);
    if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("/{raw}")
    }
}

pub(super) fn desired_endpoint_url(
    service_name: &str,
    namespace: &str,
    port: i32,
    path: &str,
) -> String {
    let scheme = std::env::var("OPERATOR_SERVICE_ENDPOINT_SCHEME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_ENDPOINT_SCHEME.to_string());
    let domain = std::env::var("OPERATOR_SERVICE_DOMAIN_SUFFIX")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_CLUSTER_DOMAIN_SUFFIX.to_string());
    format!("{scheme}://{service_name}.{namespace}.{domain}:{port}{path}")
}

pub(super) fn endpoint_id_for_image(image: &str) -> String {
    let mut out = String::with_capacity(image.len().min(ENDPOINT_ID_MAX_LEN));
    let mut last_dash = false;
    for ch in image.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if normalized == '-' {
            if !last_dash {
                out.push('-');
                last_dash = true;
            }
        } else {
            out.push(normalized);
            last_dash = false;
        }
        if out.len() >= ENDPOINT_ID_MAX_LEN {
            break;
        }
    }
    let trimmed = out.trim_matches('-');
    let suffix = if trimmed.is_empty() { "image" } else { trimmed };
    format!("rev-{suffix}")
}

pub(super) fn sanitize_dns_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_dash = false;
    for ch in value.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if normalized == '-' {
            if !last_dash {
                out.push('-');
                last_dash = true;
            }
        } else {
            out.push(normalized);
            last_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

pub(super) fn truncate_dns_label(value: &str) -> String {
    const DNS_LIMIT: usize = 63;
    let mut out = value.to_string();
    if out.len() > DNS_LIMIT {
        out.truncate(DNS_LIMIT);
    }
    out.trim_matches('-').to_string()
}

pub(super) fn sanitize_identifier(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').to_string()
}

pub(super) fn admin_upstream_id(upstream: &str, tenant: Option<&str>) -> String {
    tenant.map_or_else(
        || upstream.to_owned(),
        |tenant| unrelated_mcp_support::tenant_upstream_id(tenant, upstream),
    )
}
