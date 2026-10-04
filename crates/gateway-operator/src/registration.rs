//! Operator registration.
use super::*;
use unrelated_gateway_api::routes;

impl GatewayClient {
    pub(super) fn from_env() -> anyhow::Result<Option<Self>> {
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

    pub(super) async fn upsert_endpoint(
        &self,
        request: GatewayUpsertEndpointRequest<'_>,
    ) -> anyhow::Result<()> {
        self.upsert_upstream(
            request.upstream_id,
            request.tenant_id,
            request.enabled,
            vec![GatewayPutEndpoint {
                id: request.endpoint_id.to_string(),
                url: request.endpoint_url.to_string(),
                enabled: request.enabled,
                lifecycle: request.lifecycle,
            }],
        )
        .await
    }

    pub(super) async fn upsert_upstream(
        &self,
        upstream_id: &str,
        tenant_id: Option<&str>,
        enabled: bool,
        endpoints: Vec<GatewayPutEndpoint>,
    ) -> anyhow::Result<()> {
        let body = GatewayPutUpstreamRequest {
            id: upstream_id.to_string(),
            tenant_id: tenant_id.map(std::string::ToString::to_string),
            enabled,
            network_class: self.network_class.as_str(),
            endpoints,
        };
        self.send_json(
            Method::POST,
            routes::admin::UPSTREAMS.template(),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn registered_endpoint_ids(
        &self,
        upstream_id: &str,
    ) -> anyhow::Result<Vec<String>> {
        let response = self
            .http
            .get(format!(
                "{}{}",
                self.base_url,
                routes::admin::UPSTREAM.bind([upstream_id])?
            ))
            .bearer_auth(&self.bearer_token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        let body: serde_json::Value = response.error_for_status()?.json().await?;
        let endpoints = body["endpoints"]
            .as_array()
            .ok_or_else(|| anyhow!("upstream response lacks endpoints"))?;
        endpoints
            .iter()
            .map(|endpoint| {
                endpoint["id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("upstream endpoint lacks id"))
            })
            .collect()
    }

    pub(super) async fn mark_endpoint_draining(
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
            &routes::admin::ENDPOINT.bind([upstream_id, endpoint_id])?,
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn disable_endpoint(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<()> {
        let body = GatewayPatchEndpointRequest {
            enabled: Some(false),
            lifecycle: Some("disabled"),
        };
        self.send_json(
            Method::PATCH,
            &routes::admin::ENDPOINT.bind([upstream_id, endpoint_id])?,
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn delete_endpoint(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<()> {
        self.send_json::<serde_json::Value>(
            Method::DELETE,
            &routes::admin::ENDPOINT.bind([upstream_id, endpoint_id])?,
            None,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn endpoint_active_sessions(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<u64> {
        let response = self
            .send::<GatewaySessionActivityResponse>(
                Method::GET,
                &format!(
                    "{}?ttlSecs={}",
                    routes::admin::UPSTREAM_ACTIVITY.bind([upstream_id])?,
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

    pub(super) async fn list_deployables(&self) -> anyhow::Result<Vec<GatewayDeployable>> {
        let response = self
            .send::<GatewayDeployablesResponse>(Method::GET, routes::admin::DEPLOYABLES.template())
            .await?;
        Ok(response
            .deployables
            .into_iter()
            .filter(|d| d.enabled)
            .collect())
    }

    pub(super) async fn list_pending_deployment_requests(
        &self,
        limit: u32,
    ) -> anyhow::Result<Vec<GatewayDeploymentRequest>> {
        let response = self
            .send::<GatewayDeploymentRequestsResponse>(
                Method::GET,
                &format!(
                    "{}?status=pending,reconciling&limit={}",
                    routes::admin::DEPLOYMENTS.template(),
                    limit.max(1)
                ),
            )
            .await?;
        Ok(response.requests)
    }

    pub(super) async fn patch_deployment_status(
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
            &routes::admin::DEPLOYMENT.bind([request_id])?,
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn publish_reconciler_heartbeat(
        &self,
        mode: ManagedDeploymentMode,
        reconciler_id: &str,
    ) -> anyhow::Result<()> {
        let body = GatewayReconcilerHeartbeatRequest {
            mode: mode.as_str(),
            reconciler_id,
        };
        self.send_json(
            Method::POST,
            routes::admin::HEARTBEAT.template(),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn send_json<T: Serialize>(
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

    pub(super) async fn send<R: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
    ) -> anyhow::Result<R> {
        let text = self.send_with_retry(method, path, None).await?;
        serde_json::from_str::<R>(&text).with_context(|| {
            format!("decode response JSON from Gateway path '{path}' failed: body='{text}'")
        })
    }

    pub(super) async fn send_with_retry(
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
