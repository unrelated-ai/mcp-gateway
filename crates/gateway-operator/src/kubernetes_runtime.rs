//! Operator kubernetes runtime.
use super::*;

pub(super) async fn run_k8s_operator(
    gateway: Option<GatewayClient>,
    managed_deployment_mode: ManagedDeploymentMode,
    reconciler_id: String,
    heartbeat_interval: Duration,
) -> anyhow::Result<()> {
    let gateway = require_gateway_registration(gateway, managed_deployment_mode)?;
    let client = Client::try_default().await.context("init kube client")?;
    ensure_crd_installed(client.clone()).await?;

    let leader_cfg = load_leader_election_config();
    if leader_cfg.enabled {
        wait_for_leadership(client.clone(), &leader_cfg).await?;
        spawn_lease_renew_loop(client.clone(), leader_cfg.clone());
    } else {
        info!("leader election disabled by config");
    }

    let namespace = std::env::var("OPERATOR_NAMESPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let watcher_cfg = {
        let mut cfg = watcher::Config::default();
        if let Some(selector) = std::env::var("OPERATOR_LABEL_SELECTOR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            cfg = cfg.labels(&selector);
        }
        cfg
    };

    let mcp_api: Api<McpServer> = if let Some(ns) = namespace.as_deref() {
        info!(namespace = %ns, "watching McpServer resources in namespace");
        Api::namespaced(client.clone(), ns)
    } else {
        info!("watching McpServer resources in all namespaces");
        Api::all(client.clone())
    };

    let ctx = Arc::new(AppContext {
        client: client.clone(),
        gateway: Some(gateway.clone()),
    });

    let request_namespace = std::env::var("OPERATOR_REQUEST_NAMESPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| namespace.clone())
        .unwrap_or_else(|| "default".to_string());
    spawn_deployment_request_intake_loop(
        client.clone(),
        gateway.clone(),
        request_namespace,
        managed_request_poll_interval_from_env(),
    );
    spawn_reconciler_heartbeat_loop(
        gateway,
        managed_deployment_mode,
        reconciler_id,
        heartbeat_interval,
    );

    Controller::new(mcp_api, watcher_cfg)
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj_ref, action)) => {
                    info!(
                        name = %obj_ref.name,
                        namespace = ?obj_ref.namespace,
                        action = ?action,
                        "reconciled McpServer"
                    );
                }
                Err(err) => {
                    error!(error = %err, "reconciliation failed");
                }
            }
        })
        .await;

    Ok(())
}

pub(super) async fn reconcile(
    mcp_server: Arc<McpServer>,
    ctx: Arc<AppContext>,
) -> Result<Action, ReconcileError> {
    let namespace = mcp_server
        .namespace()
        .ok_or(ReconcileError::MissingNamespace)?;
    let api: Api<McpServer> = Api::namespaced(ctx.client.clone(), &namespace);
    let name = mcp_server.name_any();

    if mcp_server.meta().deletion_timestamp.is_some() {
        cleanup_reconcile(&api, &mcp_server, ctx.as_ref()).await?;
        info!(name = %name, namespace = %namespace, "cleanup reconciled");
        return Ok(Action::await_change());
    }

    ensure_finalizer(&api, &mcp_server).await?;

    match reconcile_apply(&api, &mcp_server, ctx.as_ref()).await {
        Ok(action) => {
            info!(name = %name, namespace = %namespace, "apply reconciled");
            Ok(action)
        }
        Err(err) => {
            let _ = set_error_status(&api, &mcp_server, err.to_string()).await;
            if let Some(gateway) = ctx.gateway.as_ref()
                && let Some(request_id) = mcp_server
                    .spec
                    .gateway
                    .as_ref()
                    .and_then(|g| g.deployment_request_id.as_deref())
            {
                let _ = gateway
                    .patch_deployment_status(request_id, "failed", None, Some(err.to_string()))
                    .await;
            }
            Err(err)
        }
    }
}

pub(super) async fn reconcile_apply(
    api: &Api<McpServer>,
    mcp_server: &McpServer,
    ctx: &AppContext,
) -> Result<Action, ReconcileError> {
    let gateway = ctx.gateway.as_ref().ok_or_else(|| {
        ReconcileError::Config("gateway registration is not configured".to_string())
    })?;
    let mut status = mcp_server.status.clone().unwrap_or_default();
    let previous_active_endpoint_id = status.active_endpoint_id.clone();
    let plan = build_reconcile_plan(mcp_server, &status)?;

    mark_request_reconciling(gateway, &plan).await?;
    reconcile_workload_and_source(ctx, mcp_server, &plan, gateway).await?;
    seed_reconcile_status(&mut status, mcp_server, &plan);
    transition_previous_endpoint_to_draining(
        gateway,
        &plan,
        &mut status,
        previous_active_endpoint_id,
    )
    .await?;
    clear_self_draining_endpoint(&mut status, &plan);
    let strategy = evaluate_drain_and_finalize(gateway, mcp_server, &plan, &mut status).await?;

    set_status(api, mcp_server, status).await?;
    Ok(strategy.action())
}

pub(super) async fn mark_request_reconciling(
    gateway: &GatewayClient,
    plan: &ReconcilePlan,
) -> Result<(), ReconcileError> {
    if let Some(request_id) = plan.request_id.as_deref() {
        gateway
            .patch_deployment_status(
                request_id,
                "reconciling",
                Some(plan.desired_upstream_id.clone()),
                Some("Operator started reconciliation".to_string()),
            )
            .await
            .map_err(|e| ReconcileError::Gateway(e.to_string()))?;
    }
    Ok(())
}

pub(super) async fn mark_request_ready(
    gateway: &GatewayClient,
    plan: &ReconcilePlan,
    message: String,
) -> Result<(), ReconcileError> {
    if let Some(request_id) = plan.request_id.as_deref() {
        gateway
            .patch_deployment_status(
                request_id,
                "ready",
                Some(plan.desired_upstream_id.clone()),
                Some(message),
            )
            .await
            .map_err(|e| ReconcileError::Gateway(e.to_string()))?;
    }
    Ok(())
}

pub(super) async fn reconcile_workload_and_source(
    ctx: &AppContext,
    mcp_server: &McpServer,
    plan: &ReconcilePlan,
    gateway: &GatewayClient,
) -> Result<(), ReconcileError> {
    let workload = WorkloadApplySpec {
        namespace: &plan.namespace,
        deployment_name: &plan.deployment_name,
        service_name: &plan.service_name,
        replicas: plan.desired_replicas,
        service_port: plan.service_port,
        image: &plan.desired_image,
        rollout: mcp_server.spec.rollout.as_ref(),
    };
    apply_workload(ctx.client.clone(), &workload).await?;
    let endpoint_enabled = plan.desired_replicas > 0;
    let endpoint_lifecycle = if endpoint_enabled {
        "active"
    } else {
        "disabled"
    };
    gateway
        .upsert_endpoint(GatewayUpsertEndpointRequest {
            upstream_id: &plan.desired_upstream_id,
            tenant_id: plan.tenant_id.as_deref(),
            endpoint_id: &plan.desired_endpoint_id,
            endpoint_url: &plan.endpoint_url,
            enabled: endpoint_enabled,
            lifecycle: endpoint_lifecycle,
        })
        .await
        .map_err(|e| ReconcileError::Gateway(e.to_string()))?;
    Ok(())
}

pub(super) fn seed_reconcile_status(
    status: &mut McpServerStatus,
    mcp_server: &McpServer,
    plan: &ReconcilePlan,
) {
    status.phase = Some("Reconciling".to_string());
    status.message = Some("Workload reconciled and source registration in progress".to_string());
    status.observed_generation = mcp_server.metadata.generation;
    status.upstream_id = Some(plan.desired_upstream_id.clone());
    status.source_registered = true;
    status.active_image = Some(plan.desired_image.clone());
    status.active_endpoint_id = Some(plan.desired_endpoint_id.clone());
    set_condition(
        &mut status.conditions,
        "Reconciling",
        true,
        "ApplySucceeded",
        "Workload/service are reconciled",
    );
    set_condition(
        &mut status.conditions,
        "SourceRegistered",
        true,
        "Upserted",
        "Gateway upstream registration upsert succeeded",
    );
}

pub(super) async fn transition_previous_endpoint_to_draining(
    gateway: &GatewayClient,
    plan: &ReconcilePlan,
    status: &mut McpServerStatus,
    previous_active_endpoint_id: Option<String>,
) -> Result<(), ReconcileError> {
    let Some(previous_active_endpoint_id) =
        previous_active_endpoint_id.filter(|id| id != &plan.desired_endpoint_id)
    else {
        return Ok(());
    };

    if let Some(existing_draining) = status
        .draining_endpoint_id
        .clone()
        .filter(|id| id != &previous_active_endpoint_id && id != &plan.desired_endpoint_id)
    {
        cleanup_endpoint(
            gateway,
            &planning::admin_upstream_id(&plan.desired_upstream_id, plan.tenant_id.as_deref()),
            &existing_draining,
        )
        .await?;
    }
    gateway
        .mark_endpoint_draining(
            &planning::admin_upstream_id(&plan.desired_upstream_id, plan.tenant_id.as_deref()),
            &previous_active_endpoint_id,
        )
        .await
        .map_err(|e| ReconcileError::Gateway(e.to_string()))?;
    status.draining_endpoint_id = Some(previous_active_endpoint_id);
    status.rollout_phase = Some(if plan.rollback_requested {
        "RollbackDrainOldSessions".to_string()
    } else {
        "DrainOldSessions".to_string()
    });
    status
        .rollout_started_at_unix
        .get_or_insert_with(now_unix_secs_i64);
    Ok(())
}

pub(super) fn clear_self_draining_endpoint(status: &mut McpServerStatus, plan: &ReconcilePlan) {
    if status.draining_endpoint_id.as_deref() == Some(plan.desired_endpoint_id.as_str()) {
        status.draining_endpoint_id = None;
        status.rollout_started_at_unix = None;
    }
}

pub(super) async fn evaluate_drain_and_finalize(
    gateway: &GatewayClient,
    mcp_server: &McpServer,
    plan: &ReconcilePlan,
    status: &mut McpServerStatus,
) -> Result<RequeueStrategy, ReconcileError> {
    let Some(draining_endpoint_id) = status.draining_endpoint_id.clone() else {
        let message = if plan.rollback_requested {
            "Rollback completed and source registration is stable".to_string()
        } else {
            "Workload and source registration are ready".to_string()
        };
        mark_rollout_ready(status, plan, message, "Ready");
        mark_request_ready(gateway, plan, status.message.clone().unwrap_or_default()).await?;
        return Ok(RequeueStrategy::Normal);
    };

    let active_sessions = gateway
        .endpoint_active_sessions(
            &planning::admin_upstream_id(&plan.desired_upstream_id, plan.tenant_id.as_deref()),
            &draining_endpoint_id,
        )
        .await
        .map_err(|e| ReconcileError::Gateway(e.to_string()))?;
    let started_at = status
        .rollout_started_at_unix
        .unwrap_or_else(now_unix_secs_i64);
    let elapsed = now_unix_secs_i64().saturating_sub(started_at);
    let timeout_secs = rollout_timeout_secs(&mcp_server.spec, plan.rollback_requested);
    let timed_out = elapsed >= i64::try_from(timeout_secs).unwrap_or(i64::MAX);

    if active_sessions == 0 || timed_out {
        cleanup_endpoint(
            gateway,
            &planning::admin_upstream_id(&plan.desired_upstream_id, plan.tenant_id.as_deref()),
            &draining_endpoint_id,
        )
        .await?;
        let message = if active_sessions == 0 {
            "Draining completed; old endpoint cleaned up".to_string()
        } else {
            "Drain timeout reached; old endpoint cleanup policy applied".to_string()
        };
        mark_rollout_ready(status, plan, message, "DrainComplete");
        mark_request_ready(gateway, plan, status.message.clone().unwrap_or_default()).await?;
        return Ok(RequeueStrategy::Normal);
    }

    status.phase = Some("Reconciling".to_string());
    status.message = Some(format!(
        "Waiting for endpoint '{draining_endpoint_id}' to drain (active sessions: {active_sessions}, elapsed={elapsed}s/{timeout_secs}s)"
    ));
    set_condition(
        &mut status.conditions,
        "Ready",
        false,
        "Draining",
        status.message.clone().unwrap_or_default(),
    );
    Ok(RequeueStrategy::Fast)
}

pub(super) fn rollout_timeout_secs(spec: &McpServerSpec, rollback_requested: bool) -> u64 {
    if rollback_requested {
        spec.rollout
            .as_ref()
            .and_then(|r| r.rollback_timeout_secs)
            .unwrap_or(DEFAULT_ROLLBACK_TIMEOUT_SECS)
            .max(1)
    } else {
        spec.rollout
            .as_ref()
            .and_then(|r| r.drain_timeout_secs)
            .unwrap_or(DEFAULT_DRAIN_TIMEOUT_SECS)
            .max(1)
    }
}

pub(super) async fn cleanup_endpoint(
    gateway: &GatewayClient,
    upstream_id: &str,
    endpoint_id: &str,
) -> Result<(), ReconcileError> {
    match gateway.cleanup_mode {
        GatewayCleanupMode::DisableEndpoint => gateway
            .disable_endpoint(upstream_id, endpoint_id)
            .await
            .map_err(|e| ReconcileError::Gateway(e.to_string())),
        GatewayCleanupMode::DeleteEndpoint => gateway
            .delete_endpoint(upstream_id, endpoint_id)
            .await
            .map_err(|e| ReconcileError::Gateway(e.to_string())),
    }
}

pub(super) fn mark_rollout_ready(
    status: &mut McpServerStatus,
    plan: &ReconcilePlan,
    message: String,
    ready_reason: &str,
) {
    status.phase = Some("Ready".to_string());
    status.rollout_phase = Some(if plan.rollback_requested {
        "RollbackFinalize".to_string()
    } else {
        "Finalize".to_string()
    });
    status.rollout_started_at_unix = None;
    status.draining_endpoint_id = None;
    status.stable_image = Some(plan.desired_image.clone());
    status.stable_endpoint_id = Some(plan.desired_endpoint_id.clone());
    status.message = Some(message);
    set_condition(
        &mut status.conditions,
        "Ready",
        true,
        ready_reason,
        status.message.clone().unwrap_or_default(),
    );
    set_condition(
        &mut status.conditions,
        "Reconciling",
        false,
        "Idle",
        "No reconcile operations are pending",
    );
    set_condition(&mut status.conditions, "Error", false, "None", "No errors");
}

pub(super) fn error_policy(
    _obj: Arc<McpServer>,
    err: &ReconcileError,
    _ctx: Arc<AppContext>,
) -> Action {
    warn!(error = %err, "reconcile error; requeueing");
    Action::requeue(Duration::from_secs(ERROR_REQUEUE_SECS))
}

pub(super) async fn ensure_finalizer(
    api: &Api<McpServer>,
    obj: &McpServer,
) -> Result<(), kube::Error> {
    let mut finalizers = obj.meta().finalizers.clone().unwrap_or_default();
    if finalizers.iter().any(|f| f == FINALIZER_NAME) {
        return Ok(());
    }
    finalizers.push(FINALIZER_NAME.to_string());
    let patch = Patch::Merge(json!({
        "metadata": {
            "finalizers": finalizers
        }
    }));
    api.patch(&obj.name_any(), &PatchParams::default(), &patch)
        .await?;
    Ok(())
}

pub(super) async fn cleanup_reconcile(
    api: &Api<McpServer>,
    obj: &McpServer,
    ctx: &AppContext,
) -> Result<(), ReconcileError> {
    let namespace = obj.namespace().ok_or(ReconcileError::MissingNamespace)?;
    let name = obj.name_any();
    let deployment_name = desired_deployment_name(&name);
    let service_name = desired_service_name(&name);

    let deployments: Api<Deployment> = Api::namespaced(ctx.client.clone(), &namespace);
    let services: Api<Service> = Api::namespaced(ctx.client.clone(), &namespace);

    match deployments
        .delete(&deployment_name, &DeleteParams::background())
        .await
    {
        Ok(_) => {}
        Err(kube::Error::Api(ae)) if ae.code == 404 => {}
        Err(err) => return Err(ReconcileError::Kube(err)),
    }
    match services
        .delete(&service_name, &DeleteParams::background())
        .await
    {
        Ok(_) => {}
        Err(kube::Error::Api(ae)) if ae.code == 404 => {}
        Err(err) => return Err(ReconcileError::Kube(err)),
    }

    if let Some(gateway) = ctx.gateway.as_ref()
        && let Some(upstream_id) = obj.status.as_ref().and_then(|s| s.upstream_id.clone())
    {
        let tenant = obj
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_TENANT_ID))
            .map(String::as_str);
        let upstream_id = planning::admin_upstream_id(&upstream_id, tenant);
        let mut endpoints = HashSet::new();
        if let Some(status) = obj.status.as_ref() {
            if let Some(endpoint) = status.active_endpoint_id.as_ref() {
                endpoints.insert(endpoint.clone());
            }
            if let Some(endpoint) = status.stable_endpoint_id.as_ref() {
                endpoints.insert(endpoint.clone());
            }
            if let Some(endpoint) = status.draining_endpoint_id.as_ref() {
                endpoints.insert(endpoint.clone());
            }
        }
        for endpoint_id in endpoints {
            let result = match gateway.cleanup_mode {
                GatewayCleanupMode::DisableEndpoint => {
                    gateway.disable_endpoint(&upstream_id, &endpoint_id).await
                }
                GatewayCleanupMode::DeleteEndpoint => {
                    gateway.delete_endpoint(&upstream_id, &endpoint_id).await
                }
            };
            if let Err(err) = result {
                return Err(ReconcileError::Gateway(err.to_string()));
            }
        }

        if let Some(request_id) = obj
            .spec
            .gateway
            .as_ref()
            .and_then(|g| g.deployment_request_id.as_deref())
        {
            let _ = gateway
                .patch_deployment_status(
                    request_id,
                    "failed",
                    None,
                    Some("McpServer deleted before deployment completion".to_string()),
                )
                .await;
        }
    }

    let mut finalizers = obj.meta().finalizers.clone().unwrap_or_default();
    if finalizers.is_empty() {
        return Ok(());
    }
    finalizers.retain(|f| f != FINALIZER_NAME);
    let patch = Patch::Merge(json!({
        "metadata": {
            "finalizers": finalizers
        }
    }));
    api.patch(&obj.name_any(), &PatchParams::default(), &patch)
        .await?;
    let mut status = obj.status.clone().unwrap_or_default();
    status.phase = Some("Deleting".to_string());
    status.observed_generation = obj.metadata.generation;
    status.message = Some("Finalizer cleanup completed".to_string());
    set_condition(
        &mut status.conditions,
        "Ready",
        false,
        "Deleting",
        "Resource deletion in progress",
    );
    let _ = set_status(api, obj, status).await;
    Ok(())
}

/// Preserve condition transition times and omit status writes that would only
/// retrigger the watch. A steady Ready resource must settle until its next poll.
pub(super) fn status_change(
    previous: Option<&McpServerStatus>,
    mut status: McpServerStatus,
) -> Option<serde_json::Value> {
    if let Some(previous) = previous {
        for condition in &mut status.conditions {
            if let Some(old) = previous
                .conditions
                .iter()
                .find(|old| old.r#type == condition.r#type && old.status == condition.status)
            {
                condition
                    .last_transition_time
                    .clone_from(&old.last_transition_time);
            }
        }
        if json!(previous) == json!(status) {
            return None;
        }
    }
    Some(json!(status))
}

pub(super) async fn set_status(
    api: &Api<McpServer>,
    obj: &McpServer,
    status: McpServerStatus,
) -> Result<(), kube::Error> {
    let Some(status) = status_change(obj.status.as_ref(), status) else {
        return Ok(());
    };
    let patch = Patch::Merge(json!({ "status": status }));
    api.patch_status(&obj.name_any(), &PatchParams::default(), &patch)
        .await?;
    Ok(())
}

pub(super) async fn set_error_status(
    api: &Api<McpServer>,
    obj: &McpServer,
    message: String,
) -> Result<(), kube::Error> {
    let mut status = obj.status.clone().unwrap_or_default();
    status.phase = Some("Error".to_string());
    status.observed_generation = obj.metadata.generation;
    status.message = Some(message.clone());
    set_condition(
        &mut status.conditions,
        "Error",
        true,
        "ReconcileFailed",
        message,
    );
    set_condition(
        &mut status.conditions,
        "Reconciling",
        false,
        "Error",
        "Reconcile failed",
    );
    set_condition(
        &mut status.conditions,
        "Ready",
        false,
        "Error",
        "Resource not ready",
    );
    set_status(api, obj, status).await
}

pub(super) fn set_condition(
    conditions: &mut Vec<McpServerCondition>,
    cond_type: &str,
    cond_status: bool,
    reason: impl Into<String>,
    message: impl Into<String>,
) {
    let condition = McpServerCondition {
        r#type: cond_type.to_string(),
        status: if cond_status {
            "True".to_string()
        } else {
            "False".to_string()
        },
        reason: Some(reason.into()),
        message: Some(message.into()),
        last_transition_time: Utc::now().to_rfc3339(),
    };
    if let Some(existing) = conditions.iter_mut().find(|c| c.r#type == cond_type) {
        *existing = condition;
    } else {
        conditions.push(condition);
    }
}

pub(super) async fn apply_workload(
    client: Client,
    spec: &WorkloadApplySpec<'_>,
) -> Result<(), ReconcileError> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), spec.namespace);
    let services: Api<Service> = Api::namespaced(client, spec.namespace);
    let app_label = spec.deployment_name.to_string();
    let max_unavailable = spec.rollout.and_then(|r| r.max_unavailable).unwrap_or(1);
    let max_surge = spec.rollout.and_then(|r| r.max_surge).unwrap_or(1);

    let deployment_patch = Patch::Apply(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": spec.deployment_name,
            "namespace": spec.namespace,
            "labels": {
                "app.kubernetes.io/name": "unrelated-mcp-server",
                "gateway.unrelated.ai/mcpserver": spec.deployment_name,
            }
        },
        "spec": {
            "replicas": spec.replicas,
            "selector": {
                "matchLabels": {
                    "app.kubernetes.io/name": app_label,
                }
            },
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {
                    "maxUnavailable": max_unavailable,
                    "maxSurge": max_surge,
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/name": app_label,
                    }
                },
                "spec": {
                    "containers": [{
                        "name": "mcp-server",
                        "image": spec.image,
                        "ports": [{
                            "name": "http",
                            "containerPort": spec.service_port,
                        }]
                    }]
                }
            }
        }
    }));
    deployments
        .patch(
            spec.deployment_name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &deployment_patch,
        )
        .await
        .map_err(ReconcileError::Kube)?;

    let service_patch = Patch::Apply(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": spec.service_name,
            "namespace": spec.namespace,
            "labels": {
                "app.kubernetes.io/name": "unrelated-mcp-server",
                "gateway.unrelated.ai/mcpserver": spec.deployment_name,
            }
        },
        "spec": {
            "selector": {
                "app.kubernetes.io/name": app_label,
            },
            "ports": [{
                "name": "http",
                "port": spec.service_port,
                "targetPort": spec.service_port,
            }]
        }
    }));
    services
        .patch(
            spec.service_name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &service_patch,
        )
        .await
        .map_err(ReconcileError::Kube)?;

    Ok(())
}
