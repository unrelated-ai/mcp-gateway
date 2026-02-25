use anyhow::{Context as _, anyhow};
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
use std::collections::HashSet;
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

#[derive(Debug, Deserialize)]
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

const fn default_request_desired_enabled() -> bool {
    true
}

const fn default_request_desired_replicas() -> i32 {
    1
}

impl GatewayClient {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let base_url = std::env::var("OPERATOR_GATEWAY_BASE_URL")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let bearer_token = std::env::var("OPERATOR_GATEWAY_BEARER_TOKEN")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        if base_url.is_none() && bearer_token.is_none() {
            info!(
                "gateway registration disabled (missing OPERATOR_GATEWAY_BASE_URL and OPERATOR_GATEWAY_BEARER_TOKEN)"
            );
            return Ok(None);
        }

        let base_url = base_url
            .ok_or_else(|| anyhow!("OPERATOR_GATEWAY_BASE_URL is required for registration"))?;
        let bearer_token = bearer_token
            .ok_or_else(|| anyhow!("OPERATOR_GATEWAY_BEARER_TOKEN is required for registration"))?;
        let timeout_secs = std::env::var("OPERATOR_GATEWAY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_GATEWAY_TIMEOUT_SECS)
            .max(1);
        let retry_max_attempts = std::env::var("OPERATOR_GATEWAY_RETRY_MAX_ATTEMPTS")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_GATEWAY_RETRY_MAX_ATTEMPTS)
            .max(1);
        let retry_base_delay_ms = std::env::var("OPERATOR_GATEWAY_RETRY_BASE_DELAY_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_GATEWAY_RETRY_BASE_DELAY_MS)
            .max(MIN_GATEWAY_RETRY_BASE_DELAY_MS);
        let session_activity_ttl_secs = std::env::var("OPERATOR_GATEWAY_SESSION_ACTIVITY_TTL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_GATEWAY_SESSION_ACTIVITY_TTL_SECS)
            .max(1);
        let network_class = match std::env::var("OPERATOR_GATEWAY_UPSTREAM_NETWORK_CLASS")
            .unwrap_or_else(|_| DEFAULT_GATEWAY_UPSTREAM_NETWORK_CLASS.to_string())
            .trim()
        {
            "cluster-internal-managed" => GatewayNetworkClass::ClusterInternalManaged,
            "external" => GatewayNetworkClass::External,
            other => {
                return Err(anyhow!(
                    "unsupported OPERATOR_GATEWAY_UPSTREAM_NETWORK_CLASS value '{other}'"
                ));
            }
        };
        let cleanup_mode = match std::env::var("OPERATOR_GATEWAY_CLEANUP_MODE")
            .unwrap_or_else(|_| DEFAULT_GATEWAY_CLEANUP_MODE.to_string())
            .trim()
        {
            "disable-endpoint" => GatewayCleanupMode::DisableEndpoint,
            "delete-endpoint" => GatewayCleanupMode::DeleteEndpoint,
            other => {
                return Err(anyhow!(
                    "unsupported OPERATOR_GATEWAY_CLEANUP_MODE value '{other}'"
                ));
            }
        };

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("build gateway HTTP client")?;

        info!(
            base_url = %base_url,
            network_class = %network_class.as_str(),
            cleanup_mode = ?cleanup_mode,
            "gateway registration enabled"
        );

        Ok(Some(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            bearer_token,
            retry_max_attempts,
            retry_base_delay: Duration::from_millis(retry_base_delay_ms),
            session_activity_ttl_secs,
            network_class,
            cleanup_mode,
        }))
    }

    async fn upsert_endpoint(
        &self,
        request: GatewayUpsertEndpointRequest<'_>,
    ) -> anyhow::Result<()> {
        let body = GatewayPutUpstreamRequest {
            id: request.upstream_id.to_string(),
            tenant_id: request.tenant_id.map(std::string::ToString::to_string),
            enabled: request.enabled,
            network_class: self.network_class.as_str(),
            endpoints: vec![GatewayPutEndpoint {
                id: request.endpoint_id.to_string(),
                url: request.endpoint_url.to_string(),
                enabled: request.enabled,
                lifecycle: request.lifecycle,
            }],
        };
        self.send_json(Method::POST, "/admin/v1/upstreams", Some(&body))
            .await?;
        Ok(())
    }

    async fn mark_endpoint_draining(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<()> {
        let body = GatewayPatchEndpointRequest {
            enabled: Some(true),
            lifecycle: Some("draining"),
        };
        self.send_json(
            Method::PATCH,
            &format!("/admin/v1/upstreams/{upstream_id}/endpoints/{endpoint_id}"),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    async fn disable_endpoint(&self, upstream_id: &str, endpoint_id: &str) -> anyhow::Result<()> {
        let body = GatewayPatchEndpointRequest {
            enabled: Some(false),
            lifecycle: Some("disabled"),
        };
        self.send_json(
            Method::PATCH,
            &format!("/admin/v1/upstreams/{upstream_id}/endpoints/{endpoint_id}"),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    async fn delete_endpoint(&self, upstream_id: &str, endpoint_id: &str) -> anyhow::Result<()> {
        self.send_json::<serde_json::Value>(
            Method::DELETE,
            &format!("/admin/v1/upstreams/{upstream_id}/endpoints/{endpoint_id}"),
            None,
        )
        .await?;
        Ok(())
    }

    async fn endpoint_active_sessions(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<u64> {
        let response = self
            .send::<GatewaySessionActivityResponse>(
                Method::GET,
                &format!(
                    "/admin/v1/upstreams/{upstream_id}/session-activity?ttlSecs={}",
                    self.session_activity_ttl_secs
                ),
            )
            .await?;
        Ok(response
            .endpoints
            .into_iter()
            .find(|ep| ep.endpoint_id == endpoint_id)
            .map_or(0, |ep| ep.active_sessions))
    }

    async fn list_deployables(&self) -> anyhow::Result<Vec<GatewayDeployable>> {
        let response = self
            .send::<GatewayDeployablesResponse>(Method::GET, "/admin/v1/managed-mcp/deployables")
            .await?;
        Ok(response
            .deployables
            .into_iter()
            .filter(|d| d.enabled)
            .collect())
    }

    async fn list_pending_deployment_requests(
        &self,
        limit: u32,
    ) -> anyhow::Result<Vec<GatewayDeploymentRequest>> {
        let response = self
            .send::<GatewayDeploymentRequestsResponse>(
                Method::GET,
                &format!(
                    "/admin/v1/managed-mcp/deployments?status=pending,reconciling&limit={}",
                    limit.max(1)
                ),
            )
            .await?;
        Ok(response.requests)
    }

    async fn patch_deployment_status(
        &self,
        request_id: &str,
        status: &'static str,
        upstream_id: Option<String>,
        message: Option<String>,
    ) -> anyhow::Result<()> {
        let body = GatewayPatchDeploymentRequest {
            status,
            upstream_id,
            message,
        };
        self.send_json(
            Method::PATCH,
            &format!("/admin/v1/managed-mcp/deployments/{request_id}"),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    async fn send_json<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
    ) -> anyhow::Result<()> {
        if let Some(b) = body {
            let value = serde_json::to_value(b).context("serialize request JSON body")?;
            self.send_with_retry(method, path, Some(value)).await?;
        } else {
            self.send_with_retry(method, path, None).await?;
        }
        Ok(())
    }

    async fn send<R: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
    ) -> anyhow::Result<R> {
        let text = self.send_with_retry(method, path, None).await?;
        serde_json::from_str::<R>(&text).with_context(|| {
            format!("decode response JSON from Gateway path '{path}' failed: body='{text}'")
        })
    }

    async fn send_with_retry(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<String> {
        let mut delay = self.retry_base_delay;
        let base_url = &self.base_url;
        let url = format!("{base_url}{path}");
        for attempt in 1..=self.retry_max_attempts {
            let mut request = self
                .http
                .request(method.clone(), &url)
                .bearer_auth(&self.bearer_token);
            if let Some(json_body) = body.as_ref() {
                request = request.json(json_body);
            }
            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    if status.is_success() {
                        return Ok(text);
                    }
                    let retryable = status.is_server_error() || status.as_u16() == 429;
                    if retryable && attempt < self.retry_max_attempts {
                        warn!(
                            attempt,
                            max_attempts = self.retry_max_attempts,
                            status = %status,
                            path = %path,
                            "gateway call failed with retryable status; backing off"
                        );
                        tokio::time::sleep(delay).await;
                        delay = delay.saturating_mul(2);
                        continue;
                    }
                    return Err(anyhow!(
                        "gateway call {method} {path} failed with status {status}: {text}"
                    ));
                }
                Err(err) => {
                    if attempt < self.retry_max_attempts {
                        warn!(
                            attempt,
                            max_attempts = self.retry_max_attempts,
                            error = %err,
                            path = %path,
                            "gateway call failed (transport); backing off"
                        );
                        tokio::time::sleep(delay).await;
                        delay = delay.saturating_mul(2);
                        continue;
                    }
                    let max_attempts = self.retry_max_attempts;
                    return Err(err).context(format!(
                        "gateway call {method} {path} failed after {max_attempts} attempts"
                    ));
                }
            }
        }
        Err(anyhow!(
            "gateway call {method} {path} failed without attempts"
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let client = Client::try_default().await.context("init kube client")?;
    let gateway = GatewayClient::from_env().context("load gateway registration config")?;

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
        gateway,
    });

    if let Some(gateway) = ctx.gateway.clone() {
        let request_namespace = std::env::var("OPERATOR_REQUEST_NAMESPACE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| namespace.clone())
            .unwrap_or_else(|| "default".to_string());
        let poll_secs = std::env::var("OPERATOR_DEPLOYMENT_REQUEST_POLL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(5)
            .max(1);
        spawn_deployment_request_intake_loop(
            client.clone(),
            gateway,
            request_namespace,
            Duration::from_secs(poll_secs),
        );
    }

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

fn load_leader_election_config() -> LeaderElectionConfig {
    let enabled = std::env::var("OPERATOR_LEADER_ELECTION_ENABLED")
        .ok()
        .is_none_or(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let lease_name = std::env::var("OPERATOR_LEADER_ELECTION_LEASE_NAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_LEADER_ELECTION_LEASE_NAME.to_string());
    let lease_namespace = std::env::var("OPERATOR_LEADER_ELECTION_LEASE_NAMESPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("OPERATOR_NAMESPACE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_LEADER_ELECTION_LEASE_NAMESPACE.to_string());
    let holder_identity = format!(
        "{}-{}",
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown-host".to_string()),
        std::process::id()
    );
    let lease_duration_secs = std::env::var("OPERATOR_LEADER_ELECTION_LEASE_DURATION_SECS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(DEFAULT_LEADER_ELECTION_LEASE_DURATION_SECS)
        .max(MIN_LEADER_ELECTION_LEASE_DURATION_SECS);
    let renew_interval_secs = std::env::var("OPERATOR_LEADER_ELECTION_RENEW_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LEADER_ELECTION_RENEW_INTERVAL_SECS)
        .max(MIN_LEADER_ELECTION_RENEW_INTERVAL_SECS);
    let retry_interval_secs = std::env::var("OPERATOR_LEADER_ELECTION_RETRY_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LEADER_ELECTION_RETRY_INTERVAL_SECS)
        .max(MIN_LEADER_ELECTION_RETRY_INTERVAL_SECS);
    LeaderElectionConfig {
        enabled,
        lease_name,
        lease_namespace,
        holder_identity,
        lease_duration_secs,
        renew_interval_secs,
        retry_interval_secs,
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

async fn try_acquire_or_renew_lease(
    client: Client,
    cfg: &LeaderElectionConfig,
) -> anyhow::Result<bool> {
    let leases: Api<Lease> = Api::namespaced(client, &cfg.lease_namespace);
    let now = Utc::now();
    let mut allow_takeover = true;
    if let Some(existing) = leases.get_opt(&cfg.lease_name).await?
        && let Some(spec) = existing.spec.as_ref()
    {
        let holder = spec.holder_identity.as_deref().unwrap_or_default();
        if !holder.is_empty() && holder != cfg.holder_identity && !lease_expired(spec, now) {
            allow_takeover = false;
        }
    }
    if !allow_takeover {
        return Ok(false);
    }

    let patch = Patch::Apply(json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {
            "name": cfg.lease_name,
            "namespace": cfg.lease_namespace,
        },
        "spec": {
            "holderIdentity": cfg.holder_identity,
            "leaseDurationSeconds": cfg.lease_duration_secs,
            "renewTime": now.to_rfc3339_opts(SecondsFormat::Micros, false),
        }
    }));
    leases
        .patch(
            &cfg.lease_name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &patch,
        )
        .await?;
    Ok(true)
}

fn lease_expired(spec: &LeaseSpec, now: DateTime<Utc>) -> bool {
    let Some(renew_time) = spec.renew_time.as_ref() else {
        return true;
    };
    let duration = i64::from(spec.lease_duration_seconds.unwrap_or(0));
    if duration <= 0 {
        return true;
    }
    let Ok(renew_at) = DateTime::parse_from_rfc3339(&renew_time.0.to_string()) else {
        return true;
    };
    now > renew_at.with_timezone(&Utc) + ChronoDuration::seconds(duration)
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
        let desired_replicas = desired_replicas_for_request(&request);
        let request_id = request.id;
        let tenant_id = request.tenant_id;
        let deployable_id = request.deployable_id;
        let Some(deployable) = deployables.iter().find(|d| d.id == deployable_id) else {
            gateway
                .patch_deployment_status(
                    &request_id,
                    "failed",
                    None,
                    Some(format!(
                        "deployable '{deployable_id}' is missing or disabled"
                    )),
                )
                .await?;
            continue;
        };

        let name = mcpserver_name_for_request(&request_id);
        let upstream_id = sanitize_identifier(&format!("managed_{tenant_id}_{request_id}"));
        let upstream_id = if upstream_id.is_empty() {
            format!("managed_{request_id}")
        } else {
            upstream_id
        };
        let service_port = service_port_from_default_upstream_url(&deployable.default_upstream_url);
        let patch = Patch::Apply(json!({
            "apiVersion": "gateway.unrelated.ai/v1alpha1",
            "kind": "McpServer",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    (LABEL_MANAGED_REQUEST): "true",
                    (LABEL_DEPLOYABLE_ID): deployable.id.clone(),
                    (LABEL_TENANT_ID): tenant_id.clone(),
                }
            },
            "spec": {
                "image": deployable.image.clone(),
                "replicas": desired_replicas,
                "service": { "port": service_port },
                "gateway": {
                    "upstreamId": upstream_id,
                    "deploymentRequestId": request_id.clone(),
                    "endpointPath": endpoint_path_from_default_upstream_url(&deployable.default_upstream_url),
                }
            }
        }));
        api.patch(&name, &PatchParams::apply(FIELD_MANAGER).force(), &patch)
            .await
            .with_context(|| format!("apply McpServer for deployment request {request_id}"))?;
    }
    Ok(())
}

fn desired_replicas_for_request(request: &GatewayDeploymentRequest) -> i32 {
    if !request.desired_enabled {
        return 0;
    }
    request.desired_replicas.max(1)
}

fn mcpserver_name_for_request(request_id: &str) -> String {
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

fn endpoint_path_from_default_upstream_url(url: &str) -> String {
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

fn service_port_from_default_upstream_url(url: &str) -> i32 {
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

async fn reconcile(
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

#[derive(Debug, Clone)]
struct ReconcilePlan {
    name: String,
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

async fn reconcile_apply(
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

    set_status(api, &plan.name, status).await?;
    Ok(strategy.action())
}

fn build_reconcile_plan(
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
        name,
    })
}

async fn mark_request_reconciling(
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

async fn mark_request_ready(
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

async fn reconcile_workload_and_source(
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

fn seed_reconcile_status(
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

async fn transition_previous_endpoint_to_draining(
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
        cleanup_endpoint(gateway, &plan.desired_upstream_id, &existing_draining).await?;
    }
    gateway
        .mark_endpoint_draining(&plan.desired_upstream_id, &previous_active_endpoint_id)
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

fn clear_self_draining_endpoint(status: &mut McpServerStatus, plan: &ReconcilePlan) {
    if status.draining_endpoint_id.as_deref() == Some(plan.desired_endpoint_id.as_str()) {
        status.draining_endpoint_id = None;
        status.rollout_started_at_unix = None;
    }
}

async fn evaluate_drain_and_finalize(
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
        .endpoint_active_sessions(&plan.desired_upstream_id, &draining_endpoint_id)
        .await
        .map_err(|e| ReconcileError::Gateway(e.to_string()))?;
    let started_at = status
        .rollout_started_at_unix
        .unwrap_or_else(now_unix_secs_i64);
    let elapsed = now_unix_secs_i64().saturating_sub(started_at);
    let timeout_secs = rollout_timeout_secs(&mcp_server.spec, plan.rollback_requested);
    let timed_out = elapsed >= i64::try_from(timeout_secs).unwrap_or(i64::MAX);

    if active_sessions == 0 || timed_out {
        cleanup_endpoint(gateway, &plan.desired_upstream_id, &draining_endpoint_id).await?;
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

fn rollout_timeout_secs(spec: &McpServerSpec, rollback_requested: bool) -> u64 {
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

async fn cleanup_endpoint(
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

fn mark_rollout_ready(
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

fn error_policy(_obj: Arc<McpServer>, err: &ReconcileError, _ctx: Arc<AppContext>) -> Action {
    warn!(error = %err, "reconcile error; requeueing");
    Action::requeue(Duration::from_secs(ERROR_REQUEUE_SECS))
}

async fn ensure_finalizer(api: &Api<McpServer>, obj: &McpServer) -> Result<(), kube::Error> {
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

async fn cleanup_reconcile(
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
    let _ = set_status(api, &obj.name_any(), status).await;
    Ok(())
}

async fn set_status(
    api: &Api<McpServer>,
    name: &str,
    status: McpServerStatus,
) -> Result<(), kube::Error> {
    let patch = Patch::Merge(json!({ "status": status }));
    api.patch_status(name, &PatchParams::default(), &patch)
        .await?;
    Ok(())
}

async fn set_error_status(
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
    set_status(api, &obj.name_any(), status).await
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

fn set_condition(
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

async fn apply_workload(
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

fn desired_upstream_id(mcp_server: &McpServer, namespace: &str) -> String {
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

fn desired_deployment_name(name: &str) -> String {
    truncate_dns_label(&format!("{}-deploy", sanitize_dns_label(name)))
}

fn desired_service_name(name: &str) -> String {
    truncate_dns_label(&format!("{}-svc", sanitize_dns_label(name)))
}

fn desired_service_port(spec: &McpServerSpec) -> i32 {
    spec.service
        .as_ref()
        .and_then(|s| s.port)
        .filter(|p| (MIN_SERVICE_PORT..=MAX_SERVICE_PORT).contains(p))
        .unwrap_or(DEFAULT_SERVICE_PORT)
}

fn desired_endpoint_path(spec: &McpServerSpec) -> String {
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

fn desired_endpoint_url(service_name: &str, namespace: &str, port: i32, path: &str) -> String {
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

fn endpoint_id_for_image(image: &str) -> String {
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

fn sanitize_dns_label(value: &str) -> String {
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

fn truncate_dns_label(value: &str) -> String {
    const DNS_LIMIT: usize = 63;
    let mut out = value.to_string();
    if out.len() > DNS_LIMIT {
        out.truncate(DNS_LIMIT);
    }
    out.trim_matches('-').to_string()
}

fn sanitize_identifier(value: &str) -> String {
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

fn now_unix_secs_i64() -> i64 {
    Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use std::collections::BTreeMap;

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
}
