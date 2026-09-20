//! Operator docker runtime.
use super::*;

impl DockerManagedRuntime {
    pub(super) fn from_env() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .context("connect to local Docker Engine (unix socket)")?;
        Ok(Self {
            docker,
            network: docker_network_from_env(),
            container_prefix: docker_container_prefix_from_env(),
        })
    }

    pub(super) async fn reconcile_request(
        &self,
        spec: &DockerManagedWorkloadSpec,
    ) -> anyhow::Result<Vec<ManagedDockerEndpoint>> {
        let desired_replicas = spec.desired_replicas.max(0);
        let mut existing_by_replica: HashMap<u32, DockerManagedContainer> = HashMap::new();
        let mut stale = Vec::new();

        for container in self.list_request_containers(&spec.request_id).await? {
            if let Some(replica_index) = container.replica_index {
                if existing_by_replica
                    .insert(replica_index, container.clone())
                    .is_some()
                {
                    stale.push(container);
                }
            } else {
                stale.push(container);
            }
        }
        for stale_container in stale {
            self.remove_container(&stale_container).await?;
        }

        let mut endpoints = Vec::new();
        let desired_replicas_u32 = u32::try_from(desired_replicas).unwrap_or(0);
        for replica in 0..desired_replicas_u32 {
            let container_name = docker_container_name_for_request(
                &self.container_prefix,
                &spec.request_id,
                replica,
            );
            let existing = existing_by_replica.remove(&replica);
            self.ensure_replica_container(spec, replica, &container_name, existing)
                .await?;

            endpoints.push(ManagedDockerEndpoint {
                endpoint_id: docker_endpoint_id_for_request(&spec.request_id, replica),
                endpoint_url: format!(
                    "{}://{}:{}{}",
                    spec.endpoint_scheme, container_name, spec.endpoint_port, spec.endpoint_path
                ),
            });
        }

        for extra_container in existing_by_replica.into_values() {
            self.remove_container(&extra_container).await?;
        }
        endpoints.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
        Ok(endpoints)
    }

    pub(super) async fn list_request_containers(
        &self,
        request_id: &str,
    ) -> anyhow::Result<Vec<DockerManagedContainer>> {
        let mut filters = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec![
                format!(
                    "{LABEL_MANAGED_MODE}={}",
                    ManagedDeploymentMode::Docker.as_str()
                ),
                format!("{LABEL_MANAGED_REQUEST_ID}={request_id}"),
            ],
        );
        let summaries = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::new()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await
            .with_context(|| {
                format!("list Docker containers for managed request '{request_id}' failed")
            })?;

        let mut containers = Vec::with_capacity(summaries.len());
        for summary in summaries {
            let name = summary
                .names
                .as_ref()
                .and_then(|names| names.first())
                .map_or_else(
                    || "unknown-container".to_string(),
                    |n| n.trim_start_matches('/').to_string(),
                );
            let id = summary.id.unwrap_or_else(|| name.clone());
            let replica_index = summary
                .labels
                .as_ref()
                .and_then(|labels| labels.get(LABEL_MANAGED_REPLICA_INDEX))
                .and_then(|v| v.parse::<u32>().ok());
            containers.push(DockerManagedContainer {
                id,
                name,
                image: summary.image,
                running: summary.state == Some(ContainerSummaryStateEnum::RUNNING),
                replica_index,
            });
        }
        Ok(containers)
    }

    pub(super) async fn ensure_replica_container(
        &self,
        spec: &DockerManagedWorkloadSpec,
        replica: u32,
        container_name: &str,
        existing: Option<DockerManagedContainer>,
    ) -> anyhow::Result<()> {
        if let Some(existing) = existing {
            let name_matches = existing.name == container_name;
            let image_matches = existing.image.as_deref() == Some(spec.image.as_str());
            if !name_matches || !image_matches {
                self.remove_container(&existing).await?;
                self.create_replica_container(spec, replica, container_name)
                    .await?;
                return Ok(());
            }
            self.ensure_running(&existing).await?;
            return Ok(());
        }

        self.create_replica_container(spec, replica, container_name)
            .await?;
        Ok(())
    }

    pub(super) async fn create_replica_container(
        &self,
        spec: &DockerManagedWorkloadSpec,
        replica: u32,
        container_name: &str,
    ) -> anyhow::Result<()> {
        let mut labels = HashMap::new();
        labels.insert(LABEL_MANAGED_REQUEST.to_string(), "true".to_string());
        labels.insert(
            LABEL_MANAGED_MODE.to_string(),
            ManagedDeploymentMode::Docker.as_str().to_string(),
        );
        labels.insert(
            LABEL_MANAGED_REQUEST_ID.to_string(),
            spec.request_id.clone(),
        );
        labels.insert(LABEL_MANAGED_REPLICA_INDEX.to_string(), replica.to_string());
        labels.insert(LABEL_DEPLOYABLE_ID.to_string(), spec.deployable_id.clone());
        labels.insert(LABEL_TENANT_ID.to_string(), spec.tenant_id.clone());

        let config = ContainerCreateBody {
            image: Some(spec.image.clone()),
            labels: Some(labels),
            host_config: Some(HostConfig {
                network_mode: Some(self.network.clone()),
                ..Default::default()
            }),
            ..Default::default()
        };

        self.docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::new()
                        .name(container_name)
                        .build(),
                ),
                config,
            )
            .await
            .with_context(|| {
                format!(
                    "create Docker container '{container_name}' for request '{}' failed (network='{}')",
                    spec.request_id, self.network
                )
            })?;

        self.docker
            .start_container(container_name, None)
            .await
            .with_context(|| {
                format!(
                    "start Docker container '{container_name}' for request '{}' failed",
                    spec.request_id
                )
            })?;
        self.verify_running(container_name).await?;
        Ok(())
    }

    pub(super) async fn ensure_running(
        &self,
        container: &DockerManagedContainer,
    ) -> anyhow::Result<()> {
        if !container.running {
            self.docker
                .start_container(&container.id, None)
                .await
                .with_context(|| format!("start Docker container '{}' failed", container.name))?;
        }
        self.verify_running(&container.id).await?;
        Ok(())
    }

    pub(super) async fn remove_container(
        &self,
        container: &DockerManagedContainer,
    ) -> anyhow::Result<()> {
        let res = self
            .docker
            .remove_container(
                &container.id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;
        match res {
            Ok(()) => Ok(()),
            Err(err) if err.to_string().contains("No such container") => Ok(()),
            Err(err) => Err(err)
                .with_context(|| format!("remove Docker container '{}' failed", container.name)),
        }
    }

    pub(super) async fn verify_running(&self, container_name_or_id: &str) -> anyhow::Result<()> {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let inspected = self
            .docker
            .inspect_container(container_name_or_id, None)
            .await
            .with_context(|| format!("inspect Docker container '{container_name_or_id}' failed"))?;
        let Some(state) = inspected.state else {
            return Err(anyhow!(
                "container '{container_name_or_id}' has no runtime state after start"
            ));
        };
        if state.status == Some(ContainerStateStatusEnum::RUNNING) {
            return Ok(());
        }
        let status = state
            .status
            .map_or_else(|| "unknown".to_string(), |s| s.to_string());
        let exit_code = state
            .exit_code
            .map_or_else(|| "n/a".to_string(), |v| v.to_string());
        let runtime_error = state.error.unwrap_or_default();
        if runtime_error.is_empty() {
            return Err(anyhow!(
                "container '{container_name_or_id}' is not running (status={status}, exitCode={exit_code})"
            ));
        }
        Err(anyhow!(
            "container '{container_name_or_id}' is not running (status={status}, exitCode={exit_code}, error={runtime_error})"
        ))
    }
}

pub(super) async fn run_docker_operator(
    gateway: Option<GatewayClient>,
    managed_deployment_mode: ManagedDeploymentMode,
    reconciler_id: String,
    heartbeat_interval: Duration,
) -> anyhow::Result<()> {
    let gateway = require_gateway_registration(gateway, managed_deployment_mode)?;
    let runtime = DockerManagedRuntime::from_env().context("load Docker runtime config")?;
    let poll_interval = managed_request_poll_interval_from_env();

    info!(
        docker_network = %runtime.network,
        container_prefix = %runtime.container_prefix,
        poll_interval_secs = poll_interval.as_secs(),
        "starting docker managed deployment controller"
    );

    spawn_docker_deployment_request_intake_loop(runtime, gateway.clone(), poll_interval);
    spawn_reconciler_heartbeat_loop(
        gateway,
        managed_deployment_mode,
        reconciler_id,
        heartbeat_interval,
    );

    tokio::signal::ctrl_c()
        .await
        .context("wait for shutdown signal")?;
    Ok(())
}

pub(super) async fn reconcile_pending_docker_deployment_requests(
    runtime: &DockerManagedRuntime,
    gateway: &GatewayClient,
) -> anyhow::Result<()> {
    let deployables = gateway.list_deployables().await?;
    let requests = gateway
        .list_pending_deployment_requests(DEFAULT_PENDING_DEPLOYMENT_REQUEST_LIMIT)
        .await?;
    if requests.is_empty() {
        return Ok(());
    }

    for request in requests {
        let request_id = request.id.clone();
        if let Err(err) =
            reconcile_pending_docker_deployment_request(runtime, gateway, &deployables, request)
                .await
        {
            warn!(
                request_id = %request_id,
                error = %err,
                "managed docker deployment request reconciliation failed"
            );
            let _ = gateway
                .patch_deployment_status(&request_id, "failed", None, Some(err.to_string()))
                .await;
        }
    }
    Ok(())
}

pub(super) async fn reconcile_pending_docker_deployment_request(
    runtime: &DockerManagedRuntime,
    gateway: &GatewayClient,
    deployables: &[GatewayDeployable],
    request: GatewayDeploymentRequest,
) -> anyhow::Result<()> {
    let plan = match build_managed_deployment_plan(request, deployables) {
        Ok(plan) => plan,
        Err(err) => {
            gateway
                .patch_deployment_status(&err.request_id, "failed", None, Some(err.message))
                .await?;
            return Ok(());
        }
    };

    gateway
        .patch_deployment_status(
            &plan.request_id,
            "reconciling",
            Some(plan.upstream_id.clone()),
            Some("Docker controller started reconciliation".to_string()),
        )
        .await?;

    let workload = DockerManagedWorkloadSpec {
        request_id: plan.request_id.clone(),
        tenant_id: plan.tenant_id.clone(),
        deployable_id: plan.deployable.id.clone(),
        image: plan.deployable.image.clone(),
        desired_replicas: plan.desired_replicas,
        endpoint_scheme: plan.endpoint_scheme.clone(),
        endpoint_port: plan.endpoint_port,
        endpoint_path: plan.endpoint_path.clone(),
    };
    // Withdraw stale endpoints before removing their containers, so initialization
    // cannot select replicas that have already been scaled down.
    retire_scaled_down_endpoints(
        gateway,
        &planning::admin_upstream_id(&plan.upstream_id, Some(&plan.tenant_id)),
        &plan.request_id,
        plan.desired_replicas,
    )
    .await?;
    let endpoints = runtime.reconcile_request(&workload).await?;
    let upstream_enabled = plan.desired_replicas > 0;
    let endpoint_lifecycle = if upstream_enabled {
        "active"
    } else {
        "disabled"
    };
    let gateway_endpoints: Vec<GatewayPutEndpoint> = endpoints
        .into_iter()
        .map(|ep| GatewayPutEndpoint {
            id: ep.endpoint_id,
            url: ep.endpoint_url,
            enabled: upstream_enabled,
            lifecycle: endpoint_lifecycle,
        })
        .collect();

    gateway
        .upsert_upstream(
            &plan.upstream_id,
            Some(plan.tenant_id.as_str()),
            upstream_enabled,
            gateway_endpoints,
        )
        .await?;

    let message = if upstream_enabled {
        format!(
            "Docker controller reconciled deployment with {} replica(s)",
            plan.desired_replicas
        )
    } else {
        "Docker controller disabled deployment (desired replicas is 0)".to_string()
    };
    gateway
        .patch_deployment_status(
            &plan.request_id,
            "ready",
            Some(plan.upstream_id),
            Some(message),
        )
        .await?;
    Ok(())
}

pub(super) fn spawn_docker_deployment_request_intake_loop(
    runtime: DockerManagedRuntime,
    gateway: GatewayClient,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = reconcile_pending_docker_deployment_requests(&runtime, &gateway).await
            {
                warn!(error = %err, "managed docker deployment request intake failed");
            }
            tokio::time::sleep(poll_interval).await;
        }
    });
}

pub(super) fn docker_network_from_env() -> String {
    std::env::var("OPERATOR_DOCKER_NETWORK")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_DOCKER_NETWORK.to_string())
}

pub(super) fn docker_container_prefix_from_env() -> String {
    std::env::var("OPERATOR_DOCKER_CONTAINER_PREFIX")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| sanitize_dns_label(&s))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_DOCKER_CONTAINER_PREFIX.to_string())
}

pub(super) fn docker_container_name_for_request(
    prefix: &str,
    request_id: &str,
    replica: u32,
) -> String {
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
    truncate_dns_label(&format!(
        "{}-{}-r{}",
        sanitize_dns_label(prefix),
        suffix,
        replica
    ))
}

pub(super) fn docker_endpoint_id_for_request(request_id: &str, replica: u32) -> String {
    let suffix: String = request_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(12)
        .collect();
    let suffix = if suffix.is_empty() {
        "request".to_string()
    } else {
        suffix.to_ascii_lowercase()
    };
    let mut endpoint_id = format!("docker-{suffix}-r{replica}");
    if endpoint_id.len() > ENDPOINT_ID_MAX_LEN {
        endpoint_id.truncate(ENDPOINT_ID_MAX_LEN);
    }
    endpoint_id.trim_matches('-').to_string()
}

async fn retire_scaled_down_endpoints(
    gateway: &GatewayClient,
    upstream: &str,
    request: &str,
    replicas: i32,
) -> anyhow::Result<()> {
    let desired: HashSet<_> = (0..u32::try_from(replicas).unwrap_or(0))
        .map(|index| docker_endpoint_id_for_request(request, index))
        .collect();
    let sample = docker_endpoint_id_for_request(request, 0);
    let prefix = sample.strip_suffix('0').expect("replica index suffix");
    for endpoint in gateway.registered_endpoint_ids(upstream).await? {
        if endpoint.starts_with(prefix) && !desired.contains(&endpoint) {
            match gateway.cleanup_mode {
                GatewayCleanupMode::DisableEndpoint => {
                    gateway.disable_endpoint(upstream, &endpoint).await?;
                }
                GatewayCleanupMode::DeleteEndpoint => {
                    gateway.delete_endpoint(upstream, &endpoint).await?;
                }
            }
        }
    }
    Ok(())
}
