mod docker_runtime;
use docker_runtime::run_docker_operator;
mod kubernetes_runtime;
use kubernetes_runtime::run_k8s_operator;
mod leader_election;
use leader_election::{load_leader_election_config, try_acquire_or_renew_lease};
mod planning;
use planning::{
    build_managed_deployment_plan, build_reconcile_plan, desired_deployment_name,
    desired_service_name, mcpserver_name_for_request, sanitize_dns_label, truncate_dns_label,
};
mod registration;

use anyhow::{Context as _, anyhow};
use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, ContainerStateStatusEnum, ContainerSummaryStateEnum, HostConfig,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, ListContainersOptionsBuilder, RemoveContainerOptionsBuilder,
};
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use futures::StreamExt as _;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::Service;
use kube::api::{DeleteParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Api, Client, CustomResource, CustomResourceExt, Resource, ResourceExt};
use reqwest::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal as _;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{error, info, warn};

const FINALIZER_NAME: &str = "gateway.unrelated.ai/finalizer";
const FIELD_MANAGER: &str = "unrelated-mcp-gateway-operator";
const DEFAULT_SERVICE_PORT: i32 = 8080;
const DEFAULT_ENDPOINT_PATH: &str = "/mcp";
const DEFAULT_ENDPOINT_SCHEME: &str = "http";
const DEFAULT_HTTP_PORT: i32 = 80;
const DEFAULT_HTTPS_PORT: i32 = 443;
const DEFAULT_CLUSTER_DOMAIN_SUFFIX: &str = "svc.cluster.local";
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 300;
const DEFAULT_ROLLBACK_TIMEOUT_SECS: u64 = 120;
const DEFAULT_GATEWAY_TIMEOUT_SECS: u64 = 15;
const DEFAULT_GATEWAY_RETRY_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_GATEWAY_RETRY_BASE_DELAY_MS: u64 = 500;
const MIN_GATEWAY_RETRY_BASE_DELAY_MS: u64 = 50;
const DEFAULT_GATEWAY_SESSION_ACTIVITY_TTL_SECS: u64 = 300;
const DEFAULT_GATEWAY_UPSTREAM_NETWORK_CLASS: &str = "cluster-internal-managed";
const DEFAULT_GATEWAY_CLEANUP_MODE: &str = "disable-endpoint";
const DEFAULT_MANAGED_DEPLOYMENT_MODE: &str = "k8s";
const DEFAULT_RECONCILER_HEARTBEAT_INTERVAL_SECS: u64 = 5;
const DEFAULT_DOCKER_NETWORK: &str = "bridge";
const DEFAULT_DOCKER_CONTAINER_PREFIX: &str = "unrelated-managed";
const DEFAULT_LEADER_ELECTION_LEASE_NAME: &str = "unrelated-mcp-gateway-operator";
const DEFAULT_LEADER_ELECTION_LEASE_NAMESPACE: &str = "default";
const DEFAULT_LEADER_ELECTION_LEASE_DURATION_SECS: i32 = 30;
const MIN_LEADER_ELECTION_LEASE_DURATION_SECS: i32 = 5;
const DEFAULT_LEADER_ELECTION_RENEW_INTERVAL_SECS: u64 = 10;
const MIN_LEADER_ELECTION_RENEW_INTERVAL_SECS: u64 = 2;
const DEFAULT_LEADER_ELECTION_RETRY_INTERVAL_SECS: u64 = 5;
const MIN_LEADER_ELECTION_RETRY_INTERVAL_SECS: u64 = 1;
const DEFAULT_PENDING_DEPLOYMENT_REQUEST_LIMIT: u32 = 100;
const MCPSERVER_NAME_SUFFIX_LEN: usize = 16;
const FAST_REQUEUE_SECS: u64 = 5;
const NORMAL_REQUEUE_SECS: u64 = 30;
const ERROR_REQUEUE_SECS: u64 = 10;
const MIN_SERVICE_PORT: i32 = 1;
const MAX_SERVICE_PORT: i32 = 65_535;
const ENDPOINT_ID_MAX_LEN: usize = 40;
const LABEL_MANAGED_REQUEST: &str = "gateway.unrelated.ai/managed-request";
const LABEL_DEPLOYABLE_ID: &str = "gateway.unrelated.ai/deployable-id";
const LABEL_TENANT_ID: &str = "gateway.unrelated.ai/tenant-id";
const LABEL_MANAGED_REQUEST_ID: &str = "gateway.unrelated.ai/managed-request-id";
const LABEL_MANAGED_REPLICA_INDEX: &str = "gateway.unrelated.ai/managed-replica-index";
const LABEL_MANAGED_MODE: &str = "gateway.unrelated.ai/managed-mode";

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpServerServiceSpec {
    #[serde(default)]
    pub port: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpServerRolloutSpec {
    #[serde(default)]
    pub max_unavailable: Option<i32>,
    #[serde(default)]
    pub max_surge: Option<i32>,
    #[serde(default)]
    pub drain_timeout_secs: Option<u64>,
    #[serde(default)]
    pub rollback_timeout_secs: Option<u64>,
    #[serde(default)]
    pub force_rollback: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpServerGatewaySpec {
    #[serde(default)]
    pub upstream_id: Option<String>,
    #[serde(default)]
    pub deployment_request_id: Option<String>,
    #[serde(default)]
    pub endpoint_path: Option<String>,
}

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.unrelated.ai",
    version = "v1alpha1",
    kind = "McpServer",
    plural = "mcpservers",
    namespaced,
    status = "McpServerStatus",
    shortname = "mcpsrv"
)]
#[serde(rename_all = "camelCase")]
pub struct McpServerSpec {
    pub image: String,
    #[serde(default)]
    pub replicas: Option<i32>,
    #[serde(default)]
    pub service: Option<McpServerServiceSpec>,
    #[serde(default)]
    pub rollout: Option<McpServerRolloutSpec>,
    #[serde(default)]
    pub gateway: Option<McpServerGatewaySpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpServerCondition {
    pub r#type: String,
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    pub last_transition_time: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpServerStatus {
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub observed_generation: Option<i64>,
    #[serde(default)]
    pub conditions: Vec<McpServerCondition>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub upstream_id: Option<String>,
    #[serde(default)]
    pub source_registered: bool,
    #[serde(default)]
    pub active_image: Option<String>,
    #[serde(default)]
    pub stable_image: Option<String>,
    #[serde(default)]
    pub active_endpoint_id: Option<String>,
    #[serde(default)]
    pub stable_endpoint_id: Option<String>,
    #[serde(default)]
    pub draining_endpoint_id: Option<String>,
    #[serde(default)]
    pub rollout_phase: Option<String>,
    #[serde(default)]
    pub rollout_started_at_unix: Option<i64>,
}

#[derive(Clone)]
struct AppContext {
    client: Client,
    gateway: Option<GatewayClient>,
}

#[derive(Debug, Clone)]
struct LeaderElectionConfig {
    enabled: bool,
    lease_name: String,
    lease_namespace: String,
    holder_identity: String,
    lease_duration_secs: i32,
    renew_interval_secs: u64,
    retry_interval_secs: u64,
}

#[derive(Debug, Error)]
enum ReconcileError {
    #[error("kube api error: {0}")]
    Kube(#[from] kube::Error),
    #[error("missing namespace for namespaced resource")]
    MissingNamespace,
    #[error("operator configuration error: {0}")]
    Config(String),
    #[error("gateway registration error: {0}")]
    Gateway(String),
}

#[derive(Debug, Clone, Copy)]
enum GatewayNetworkClass {
    External,
    ClusterInternalManaged,
}

impl GatewayNetworkClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::External => "external",
            Self::ClusterInternalManaged => "cluster-internal-managed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum GatewayCleanupMode {
    DisableEndpoint,
    DeleteEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedDeploymentMode {
    K8s,
    Docker,
}

impl ManagedDeploymentMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::K8s => "k8s",
            Self::Docker => "docker",
        }
    }
}

#[derive(Clone)]
struct GatewayClient {
    http: reqwest::Client,
    base_url: String,
    bearer_token: String,
    retry_max_attempts: u32,
    retry_base_delay: Duration,
    session_activity_ttl_secs: u64,
    network_class: GatewayNetworkClass,
    cleanup_mode: GatewayCleanupMode,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayPutEndpoint {
    id: String,
    url: String,
    enabled: bool,
    lifecycle: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayPutUpstreamRequest {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    enabled: bool,
    network_class: &'static str,
    endpoints: Vec<GatewayPutEndpoint>,
}

#[derive(Debug, Clone, Copy)]
struct GatewayUpsertEndpointRequest<'a> {
    upstream_id: &'a str,
    tenant_id: Option<&'a str>,
    endpoint_id: &'a str,
    endpoint_url: &'a str,
    enabled: bool,
    lifecycle: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayPatchEndpointRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayPatchDeploymentRequest {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayReconcilerHeartbeatRequest<'a> {
    mode: &'a str,
    reconciler_id: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewaySessionActivityResponse {
    endpoints: Vec<GatewayEndpointActivity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayEndpointActivity {
    endpoint_id: String,
    active_sessions: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayDeployablesResponse {
    deployables: Vec<GatewayDeployable>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayDeployable {
    id: String,
    image: String,
    default_upstream_url: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayDeploymentRequestsResponse {
    requests: Vec<GatewayDeploymentRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayDeploymentRequest {
    id: String,
    tenant_id: String,
    deployable_id: String,
    #[serde(default = "default_request_desired_enabled")]
    desired_enabled: bool,
    #[serde(default = "default_request_desired_replicas")]
    desired_replicas: i32,
}

#[derive(Debug, Clone)]
struct ManagedDockerEndpoint {
    endpoint_id: String,
    endpoint_url: String,
}

#[derive(Debug, Clone)]
struct DockerManagedWorkloadSpec {
    request_id: String,
    tenant_id: String,
    deployable_id: String,
    image: String,
    desired_replicas: i32,
    endpoint_scheme: String,
    endpoint_port: i32,
    endpoint_path: String,
}

#[derive(Debug, Clone)]
struct DockerManagedContainer {
    id: String,
    name: String,
    image: Option<String>,
    running: bool,
    replica_index: Option<u32>,
}

#[derive(Clone)]
struct DockerManagedRuntime {
    docker: Docker,
    network: String,
    container_prefix: String,
}

const fn default_request_desired_enabled() -> bool {
    true
}

const fn default_request_desired_replicas() -> i32 {
    1
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let gateway = GatewayClient::from_env().context("load gateway registration config")?;
    let managed_deployment_mode =
        managed_deployment_mode_from_env().context("load managed deployment mode")?;
    let reconciler_id = reconciler_id_from_env();
    let heartbeat_interval = Duration::from_secs(reconciler_heartbeat_interval_secs_from_env());
    info!(
        managed_deployment_mode = managed_deployment_mode.as_str(),
        reconciler_id = %reconciler_id,
        heartbeat_interval_secs = heartbeat_interval.as_secs(),
        "managed deployment mode configured"
    );

    match managed_deployment_mode {
        ManagedDeploymentMode::K8s => {
            run_k8s_operator(
                gateway,
                managed_deployment_mode,
                reconciler_id,
                heartbeat_interval,
            )
            .await
        }
        ManagedDeploymentMode::Docker => {
            run_docker_operator(
                gateway,
                managed_deployment_mode,
                reconciler_id,
                heartbeat_interval,
            )
            .await
        }
    }
}

fn init_tracing() {
    let is_tty = std::io::stdout().is_terminal();
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if is_tty {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    }
}

async fn ensure_crd_installed(client: Client) -> anyhow::Result<()> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let crd_name = "mcpservers.gateway.unrelated.ai";
    let patch = Patch::Apply(McpServer::crd());
    crds.patch(crd_name, &PatchParams::apply(FIELD_MANAGER).force(), &patch)
        .await
        .with_context(|| format!("apply CRD {crd_name}"))?;
    info!(crd = crd_name, "CRD ensured");
    Ok(())
}

async fn wait_for_leadership(client: Client, cfg: &LeaderElectionConfig) -> anyhow::Result<()> {
    info!(
        lease = %cfg.lease_name,
        namespace = %cfg.lease_namespace,
        holder = %cfg.holder_identity,
        "waiting for leader lease"
    );
    loop {
        match try_acquire_or_renew_lease(client.clone(), cfg).await {
            Ok(true) => {
                info!("leader lease acquired");
                return Ok(());
            }
            Ok(false) => {
                tokio::time::sleep(Duration::from_secs(cfg.retry_interval_secs)).await;
            }
            Err(err) => {
                warn!(error = %err, "leader lease check failed");
                tokio::time::sleep(Duration::from_secs(cfg.retry_interval_secs)).await;
            }
        }
    }
}

fn spawn_lease_renew_loop(client: Client, cfg: LeaderElectionConfig) {
    tokio::spawn(async move {
        let sleep_for = Duration::from_secs(cfg.renew_interval_secs);
        loop {
            tokio::time::sleep(sleep_for).await;
            if let Err(err) = try_acquire_or_renew_lease(client.clone(), &cfg).await {
                warn!(error = %err, "failed to renew leader lease");
            }
        }
    });
}

fn managed_deployment_mode_from_env() -> anyhow::Result<ManagedDeploymentMode> {
    let raw = std::env::var("OPERATOR_MANAGED_DEPLOYMENT_MODE")
        .ok()
        .unwrap_or_else(|| DEFAULT_MANAGED_DEPLOYMENT_MODE.to_string());
    parse_managed_deployment_mode(&raw).ok_or_else(|| {
        anyhow!(
            "unsupported OPERATOR_MANAGED_DEPLOYMENT_MODE value '{}'",
            raw.trim()
        )
    })
}

fn parse_managed_deployment_mode(raw: &str) -> Option<ManagedDeploymentMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "k8s" => Some(ManagedDeploymentMode::K8s),
        "docker" => Some(ManagedDeploymentMode::Docker),
        _ => None,
    }
}

fn reconciler_id_from_env() -> String {
    std::env::var("OPERATOR_MANAGED_DEPLOYMENT_RECONCILER_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}-{}",
                hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "unknown-host".to_string()),
                std::process::id()
            )
        })
}

fn reconciler_heartbeat_interval_secs_from_env() -> u64 {
    std::env::var("OPERATOR_MANAGED_DEPLOYMENT_HEARTBEAT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_RECONCILER_HEARTBEAT_INTERVAL_SECS)
        .max(1)
}

fn managed_request_poll_interval_from_env() -> Duration {
    let poll_secs = std::env::var("OPERATOR_DEPLOYMENT_REQUEST_POLL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    Duration::from_secs(poll_secs)
}

fn require_gateway_registration(
    gateway: Option<GatewayClient>,
    mode: ManagedDeploymentMode,
) -> anyhow::Result<GatewayClient> {
    gateway.ok_or_else(|| {
        anyhow!(
            "gateway registration is required for {} mode (set OPERATOR_GATEWAY_BASE_URL and OPERATOR_GATEWAY_BEARER_TOKEN)",
            mode.as_str()
        )
    })
}

fn spawn_reconciler_heartbeat_loop(
    gateway: GatewayClient,
    mode: ManagedDeploymentMode,
    reconciler_id: String,
    interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = gateway
                .publish_reconciler_heartbeat(mode, &reconciler_id)
                .await
            {
                warn!(
                    error = %err,
                    reconciler_id = %reconciler_id,
                    mode = mode.as_str(),
                    "failed to publish managed deployment reconciler heartbeat"
                );
            }
            tokio::time::sleep(interval).await;
        }
    });
}

fn spawn_deployment_request_intake_loop(
    client: Client,
    gateway: GatewayClient,
    namespace: String,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            if let Err(err) =
                reconcile_pending_deployment_requests(client.clone(), gateway.clone(), &namespace)
                    .await
            {
                warn!(error = %err, "managed deployment request intake failed");
            }
            tokio::time::sleep(poll_interval).await;
        }
    });
}

async fn reconcile_pending_deployment_requests(
    client: Client,
    gateway: GatewayClient,
    namespace: &str,
) -> anyhow::Result<()> {
    let deployables = gateway.list_deployables().await?;
    let requests = gateway
        .list_pending_deployment_requests(DEFAULT_PENDING_DEPLOYMENT_REQUEST_LIMIT)
        .await?;
    if requests.is_empty() {
        return Ok(());
    }

    let api: Api<McpServer> = Api::namespaced(client, namespace);
    for request in requests {
        let plan = match build_managed_deployment_plan(request, &deployables) {
            Ok(plan) => plan,
            Err(err) => {
                gateway
                    .patch_deployment_status(&err.request_id, "failed", None, Some(err.message))
                    .await?;
                continue;
            }
        };
        let name = mcpserver_name_for_request(&plan.request_id);
        let patch = Patch::Apply(json!({
            "apiVersion": "gateway.unrelated.ai/v1alpha1",
            "kind": "McpServer",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    (LABEL_MANAGED_REQUEST): "true",
                    (LABEL_DEPLOYABLE_ID): plan.deployable.id.clone(),
                    (LABEL_TENANT_ID): plan.tenant_id.clone(),
                }
            },
            "spec": {
                "image": plan.deployable.image.clone(),
                "replicas": plan.desired_replicas,
                "service": { "port": plan.endpoint_port },
                "gateway": {
                    "upstreamId": plan.upstream_id.clone(),
                    "deploymentRequestId": plan.request_id.clone(),
                    "endpointPath": plan.endpoint_path.clone(),
                }
            }
        }));
        api.patch(&name, &PatchParams::apply(FIELD_MANAGER).force(), &patch)
            .await
            .with_context(|| {
                format!("apply McpServer for deployment request {}", plan.request_id)
            })?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ManagedDeploymentPlan {
    request_id: String,
    tenant_id: String,
    desired_replicas: i32,
    upstream_id: String,
    endpoint_port: i32,
    endpoint_path: String,
    endpoint_scheme: String,
    deployable: GatewayDeployable,
}

#[derive(Debug)]
struct ManagedDeploymentPlanError {
    request_id: String,
    message: String,
}

#[derive(Debug, Clone)]
struct ReconcilePlan {
    namespace: String,
    tenant_id: Option<String>,
    deployment_name: String,
    service_name: String,
    service_port: i32,
    desired_replicas: i32,
    desired_image: String,
    desired_endpoint_id: String,
    desired_upstream_id: String,
    endpoint_url: String,
    request_id: Option<String>,
    rollback_requested: bool,
}

#[derive(Debug, Clone, Copy)]
enum RequeueStrategy {
    Fast,
    Normal,
}

impl RequeueStrategy {
    const fn action(self) -> Action {
        match self {
            Self::Fast => Action::requeue(Duration::from_secs(FAST_REQUEUE_SECS)),
            Self::Normal => Action::requeue(Duration::from_secs(NORMAL_REQUEUE_SECS)),
        }
    }
}

struct WorkloadApplySpec<'a> {
    namespace: &'a str,
    deployment_name: &'a str,
    service_name: &'a str,
    replicas: i32,
    service_port: i32,
    image: &'a str,
    rollout: Option<&'a McpServerRolloutSpec>,
}

fn now_unix_secs_i64() -> i64 {
    Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use crate::kubernetes_runtime::{set_condition, status_change};
    #[test]
    fn steady_status_does_not_retrigger_the_controller() {
        let mut before = McpServerStatus::default();
        set_condition(&mut before.conditions, "Ready", true, "Ready", "Available");
        before.conditions[0].last_transition_time = "2026-09-20T00:00:00Z".into();
        let mut after = before.clone();
        set_condition(&mut after.conditions, "Ready", true, "Ready", "Available");
        assert!(status_change(Some(&before), after.clone()).is_none());
        after.conditions[0].reason = Some("NewReason".into());
        let changed = status_change(Some(&before), after.clone()).unwrap();
        assert_eq!(
            changed["conditions"][0]["lastTransitionTime"],
            "2026-09-20T00:00:00Z"
        );
        after.conditions[0].status = "False".into();
        let changed = status_change(Some(&before), after).unwrap();
        assert_ne!(
            changed["conditions"][0]["lastTransitionTime"],
            "2026-09-20T00:00:00Z"
        );
    }

    #[tokio::test]
    async fn kubernetes_https_client_selects_a_crypto_provider() {
        // Constructing the TLS stack must work even when workspace dependencies
        // enable both Rustls providers. This never connects to a cluster.
        let config = kube::Config::new("https://127.0.0.1:6443".parse().unwrap());
        kube::Client::try_from(config).expect("construct Kubernetes HTTPS client");
    }

    use super::*;
    use crate::planning::*;
    use kube::core::ObjectMeta;
    use std::collections::BTreeMap;

    fn test_gateway_client() -> GatewayClient {
        GatewayClient {
            http: reqwest::Client::new(),
            base_url: "http://gateway.test".to_string(),
            bearer_token: "test-token".to_string(),
            retry_max_attempts: 3,
            retry_base_delay: Duration::from_millis(100),
            session_activity_ttl_secs: 300,
            network_class: GatewayNetworkClass::External,
            cleanup_mode: GatewayCleanupMode::DisableEndpoint,
        }
    }

    fn mk_server(
        name: &str,
        gateway: Option<McpServerGatewaySpec>,
        service_port: Option<i32>,
    ) -> McpServer {
        McpServer {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("ns".to_string()),
                ..ObjectMeta::default()
            },
            spec: McpServerSpec {
                image: "ghcr.io/acme/mcp:latest".to_string(),
                replicas: Some(1),
                service: Some(McpServerServiceSpec { port: service_port }),
                rollout: None,
                gateway,
            },
            status: None,
        }
    }

    fn mk_deployable(id: &str, url: &str) -> GatewayDeployable {
        GatewayDeployable {
            id: id.to_string(),
            image: "ghcr.io/example/managed:latest".to_string(),
            default_upstream_url: url.to_string(),
            enabled: true,
        }
    }

    fn mk_request(
        id: &str,
        tenant_id: &str,
        deployable_id: &str,
        desired_enabled: bool,
        desired_replicas: i32,
    ) -> GatewayDeploymentRequest {
        GatewayDeploymentRequest {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            deployable_id: deployable_id.to_string(),
            desired_enabled,
            desired_replicas,
        }
    }

    #[test]
    fn require_gateway_registration_rejects_missing_k8s_config() {
        let Err(err) = require_gateway_registration(None, ManagedDeploymentMode::K8s) else {
            panic!("k8s mode should require gateway config");
        };
        assert!(err.to_string().contains("required for k8s mode"));
    }

    #[test]
    fn require_gateway_registration_rejects_missing_docker_config() {
        let Err(err) = require_gateway_registration(None, ManagedDeploymentMode::Docker) else {
            panic!("docker mode should require gateway config");
        };
        assert!(err.to_string().contains("required for docker mode"));
    }

    #[test]
    fn require_gateway_registration_accepts_present_config() {
        let expected = test_gateway_client();
        let got = require_gateway_registration(Some(expected.clone()), ManagedDeploymentMode::K8s)
            .expect("present config should pass");
        assert_eq!(got.base_url, expected.base_url);
        assert_eq!(got.bearer_token, expected.bearer_token);
        assert_eq!(got.network_class.as_str(), expected.network_class.as_str());
    }

    #[test]
    fn build_managed_deployment_plan_rejects_missing_deployable() {
        let request = mk_request("req-1", "tenant-a", "missing", true, 1);
        let err = build_managed_deployment_plan(request, &[]).expect_err("missing deployable");
        assert_eq!(err.request_id, "req-1");
        assert!(err.message.contains("missing or disabled"));
    }

    #[test]
    fn build_managed_deployment_plan_normalizes_replicas_and_extracts_endpoint_parts() {
        let request = mk_request("req-1", "tenant-a", "dep-1", true, 0);
        let deployables = vec![mk_deployable("dep-1", "http://managed-service:8088/mcp")];
        let plan = build_managed_deployment_plan(request, &deployables).expect("plan");
        assert_eq!(plan.desired_replicas, 1);
        assert_eq!(plan.endpoint_scheme, "http");
        assert_eq!(plan.endpoint_port, 8088);
        assert_eq!(plan.endpoint_path, "/mcp");
        assert!(plan.upstream_id.starts_with("managed_"));
    }

    #[test]
    fn endpoint_id_is_stable_and_sanitized() {
        let id = endpoint_id_for_image("ghcr.io/acme/filesystem-mcp:1.2.3");
        assert!(id.starts_with("rev-"));
        assert!(id.len() <= 44);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );
    }

    #[test]
    fn endpoint_path_defaults_and_adds_slash() {
        let mut spec = McpServerSpec {
            image: "ghcr.io/acme/mcp:latest".to_string(),
            replicas: Some(1),
            service: Some(McpServerServiceSpec { port: Some(8080) }),
            rollout: None,
            gateway: None,
        };
        assert_eq!(desired_endpoint_path(&spec), "/mcp");
        spec.gateway = Some(McpServerGatewaySpec {
            upstream_id: None,
            deployment_request_id: None,
            endpoint_path: Some("custom".to_string()),
        });
        assert_eq!(desired_endpoint_path(&spec), "/custom");
    }

    #[test]
    fn sanitize_identifier_keeps_supported_chars() {
        assert_eq!(
            sanitize_identifier("Managed.Namespace/Name"),
            "managed_namespace_name"
        );
        assert_eq!(sanitize_identifier("___"), "");
    }

    #[test]
    fn truncate_dns_label_limits_length() {
        let input = "a".repeat(120);
        let truncated = truncate_dns_label(&input);
        assert_eq!(truncated.len(), 63);
    }

    #[test]
    fn desired_service_port_accepts_valid_and_falls_back_for_invalid_values() {
        let valid = mk_server("demo", None, Some(8081));
        assert_eq!(desired_service_port(&valid.spec), 8081);

        let zero = mk_server("demo", None, Some(0));
        assert_eq!(desired_service_port(&zero.spec), DEFAULT_SERVICE_PORT);

        let too_high = mk_server("demo", None, Some(70_000));
        assert_eq!(desired_service_port(&too_high.spec), DEFAULT_SERVICE_PORT);
    }

    #[test]
    fn desired_upstream_id_prefers_sanitized_override_and_falls_back_when_empty() {
        let with_override = mk_server(
            "demo.name",
            Some(McpServerGatewaySpec {
                upstream_id: Some("Managed/Custom.ID".to_string()),
                deployment_request_id: None,
                endpoint_path: None,
            }),
            Some(8080),
        );
        assert_eq!(
            desired_upstream_id(&with_override, "ns"),
            "managed_custom_id"
        );

        let empty_override = mk_server(
            "demo.name",
            Some(McpServerGatewaySpec {
                upstream_id: Some("___".to_string()),
                deployment_request_id: None,
                endpoint_path: None,
            }),
            Some(8080),
        );
        assert_eq!(
            desired_upstream_id(&empty_override, "ns"),
            "managed_ns_demo_name"
        );
    }

    #[test]
    fn build_reconcile_plan_uses_tenant_label_for_scoped_upstream_registration() {
        let mut server = mk_server("demo", None, Some(8080));
        server.metadata.labels = Some(BTreeMap::from([(
            LABEL_TENANT_ID.to_string(),
            "tenant-a".to_string(),
        )]));

        let plan = build_reconcile_plan(&server, &McpServerStatus::default())
            .expect("reconcile plan should build");
        assert_eq!(plan.tenant_id.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn service_port_from_default_url_prefers_explicit_port_then_scheme_defaults() {
        assert_eq!(
            service_port_from_default_upstream_url("http://demo-nginx:18080/mcp"),
            18_080
        );
        assert_eq!(
            service_port_from_default_upstream_url("http://demo-nginx/mcp"),
            80
        );
        assert_eq!(
            service_port_from_default_upstream_url("https://demo-nginx/mcp"),
            443
        );
        assert_eq!(
            service_port_from_default_upstream_url("not-a-valid-url"),
            DEFAULT_SERVICE_PORT
        );
    }

    #[test]
    fn desired_replicas_for_request_enforces_disable_and_minimum_enabled_replica() {
        let disabled = GatewayDeploymentRequest {
            id: "r1".to_string(),
            tenant_id: "t1".to_string(),
            deployable_id: "d1".to_string(),
            desired_enabled: false,
            desired_replicas: 5,
        };
        assert_eq!(desired_replicas_for_request(&disabled), 0);

        let enabled_zero = GatewayDeploymentRequest {
            id: "r2".to_string(),
            tenant_id: "t1".to_string(),
            deployable_id: "d1".to_string(),
            desired_enabled: true,
            desired_replicas: 0,
        };
        assert_eq!(desired_replicas_for_request(&enabled_zero), 1);

        let enabled_many = GatewayDeploymentRequest {
            id: "r3".to_string(),
            tenant_id: "t1".to_string(),
            deployable_id: "d1".to_string(),
            desired_enabled: true,
            desired_replicas: 3,
        };
        assert_eq!(desired_replicas_for_request(&enabled_many), 3);
    }

    #[test]
    fn parse_managed_deployment_mode_accepts_supported_values() {
        assert_eq!(
            parse_managed_deployment_mode("k8s"),
            Some(ManagedDeploymentMode::K8s)
        );
        assert_eq!(
            parse_managed_deployment_mode("docker"),
            Some(ManagedDeploymentMode::Docker)
        );
        assert_eq!(
            parse_managed_deployment_mode(" K8S "),
            Some(ManagedDeploymentMode::K8s)
        );
        assert_eq!(parse_managed_deployment_mode("other"), None);
    }
}
