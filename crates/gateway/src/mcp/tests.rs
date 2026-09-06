use super::*;
use crate::config::GatewayConfig;
use crate::store::DataPlaneAuthMode;
use crate::tool_policy::{RetryPolicy, ToolPolicy};
use crate::tools_cache::{CachedToolsSurface, ToolRoute, ToolRouteKind, profile_fingerprint};
use async_trait::async_trait;
use axum::{
    Router,
    routing::{get, post},
};
use rmcp::model::{ClientCapabilities, Implementation, InitializeRequest, InitializeRequestParams};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

#[test]
fn tools_call_args_validation_reports_unknown_param_with_suggestion() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "petId": { "type": "integer" }
        },
        "required": ["petId"]
    });
    let schema_obj = schema.as_object().unwrap().clone();
    let tool = rmcp::model::Tool::new(
        "getPetById".to_string(),
        String::new(),
        Arc::new(schema_obj),
    );

    let (msg, data) =
        super::tool_call::validate_tool_arguments(&tool, &serde_json::json!({ "petID": 1 }))
            .unwrap_err();
    assert!(msg.contains("did you mean 'petId'"), "message: {msg}");
    assert_eq!(
        data.get("type").and_then(serde_json::Value::as_str),
        Some("validation-errors")
    );
    assert!(
        data.get("violations")
            .and_then(serde_json::Value::as_array)
            .is_some(),
        "expected violations array"
    );
}

#[test]
fn tool_surface_adds_trusted_stable_refs_and_preserves_other_metadata() {
    use crate::mcp::surface::{ToolSourceTools, UNRELATED_TOOL_REF_META_KEY, merge_tools_surface};

    let mut upstream = rmcp::model::Tool::new(
        "get_messages".to_string(),
        "Read messages".to_string(),
        Arc::new(serde_json::Map::from_iter([(
            "type".to_string(),
            serde_json::json!("object"),
        )])),
    );
    upstream.meta = Some(rmcp::model::Meta(serde_json::Map::from_iter([
        (
            UNRELATED_TOOL_REF_META_KEY.to_string(),
            serde_json::json!("spoofed:tool"),
        ),
        ("vendor.example/hint".to_string(), serde_json::json!(true)),
    ])));
    let mut local = upstream.clone();
    local.meta = None;

    let profile = crate::store::Profile {
        id: "profile".to_string(),
        tenant_id: "tenant".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec!["telegram".to_string(), "local".to_string()],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: crate::store::McpProfileSettings::default(),
    };
    let merged = merge_tools_surface(
        "profile",
        &profile,
        vec![
            ToolSourceTools {
                kind: ToolRouteKind::Upstream,
                source_id: "telegram".to_string(),
                tools: vec![upstream],
            },
            ToolSourceTools {
                kind: ToolRouteKind::SharedLocal,
                source_id: "local".to_string(),
                tools: vec![local],
            },
        ],
    );

    assert_eq!(merged.tools.len(), 2);
    assert_eq!(merged.tools[0].name, "telegram:get_messages");
    assert_eq!(merged.tools[1].name, "local:get_messages");
    let meta = merged.tools[0].meta.as_ref().expect("tool metadata");
    assert_eq!(
        meta.0.get(UNRELATED_TOOL_REF_META_KEY),
        Some(&serde_json::json!("telegram:get_messages"))
    );
    assert_eq!(
        meta.0.get("vendor.example/hint"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        merged.tools[1]
            .meta
            .as_ref()
            .and_then(|meta| meta.0.get(UNRELATED_TOOL_REF_META_KEY)),
        Some(&serde_json::json!("local:get_messages"))
    );
}

#[test]
fn upstream_initialize_rewrite_strip_allowlist_and_clientinfo() {
    let caps: ClientCapabilities = serde_json::from_value(serde_json::json!({
        "roots": { "listChanged": true },
        "sampling": {},
        "elicitation": { "form": {}, "url": {} }
    }))
    .expect("valid client capabilities");

    let init = InitializeRequest::new(InitializeRequestParams::new(
        caps,
        Implementation::new("DownstreamClient", "0.1.0"),
    ));
    let msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::InitializeRequest(init),
    });

    // Strip capabilities.
    let strip_policy = crate::store::UpstreamSecurityPolicy {
        client_capabilities_mode: crate::store::UpstreamClientCapabilitiesMode::Strip,
        ..Default::default()
    };
    let rewritten = upstream::rewrite_upstream_initialize_message(&msg, &strip_policy);
    let stripped_caps = match &rewritten {
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            request: ClientRequest::InitializeRequest(init),
            ..
        }) => serde_json::to_value(&init.params.capabilities).expect("serialize caps"),
        other => panic!("expected initialize request, got {other:?}"),
    };
    assert!(
        stripped_caps
            .as_object()
            .is_some_and(serde_json::Map::is_empty),
        "expected empty capabilities, got {stripped_caps:?}"
    );

    // Allowlist only roots.
    let allow_policy = crate::store::UpstreamSecurityPolicy {
        client_capabilities_mode: crate::store::UpstreamClientCapabilitiesMode::Allowlist,
        client_capabilities_allow: vec!["roots".to_string()],
        ..Default::default()
    };
    let rewritten = upstream::rewrite_upstream_initialize_message(&msg, &allow_policy);
    let allow_caps = match &rewritten {
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            request: ClientRequest::InitializeRequest(init),
            ..
        }) => serde_json::to_value(&init.params.capabilities).expect("serialize caps"),
        other => panic!("expected initialize request, got {other:?}"),
    };
    assert!(
        allow_caps.get("roots").is_some(),
        "expected roots capability present, got {allow_caps:?}"
    );
    assert!(
        allow_caps.get("sampling").is_none(),
        "expected sampling stripped, got {allow_caps:?}"
    );
    assert!(
        allow_caps.get("elicitation").is_none(),
        "expected elicitation stripped, got {allow_caps:?}"
    );

    // Rewrite clientInfo (privacy).
    let ci_policy = crate::store::UpstreamSecurityPolicy {
        rewrite_client_info: true,
        ..Default::default()
    };
    let rewritten = upstream::rewrite_upstream_initialize_message(&msg, &ci_policy);
    let client_info = match &rewritten {
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            request: ClientRequest::InitializeRequest(init),
            ..
        }) => init.params.client_info.clone(),
        other => panic!("expected initialize request, got {other:?}"),
    };
    assert_eq!(client_info.name, "unrelated-mcp-gateway");
}

fn parse_server_notification(
    method: &str,
    params: Option<serde_json::Value>,
) -> ServerNotification {
    let mut payload = serde_json::Map::new();
    payload.insert("jsonrpc".to_string(), serde_json::json!("2.0"));
    payload.insert("method".to_string(), serde_json::json!(method));
    if let Some(params) = params {
        payload.insert("params".to_string(), params);
    }
    let msg: ServerJsonRpcMessage = serde_json::from_value(serde_json::Value::Object(payload))
        .expect("valid server notification json");
    match msg {
        ServerJsonRpcMessage::Notification(JsonRpcNotification { notification, .. }) => {
            notification
        }
        other => panic!("expected notification, got {other:?}"),
    }
}

fn default_effective_caps() -> EffectiveMcpCapabilities {
    crate::store::McpCapabilitiesPolicy::default().effective()
}

fn effective_caps_with_deny(deny: Vec<crate::store::McpCapability>) -> EffectiveMcpCapabilities {
    crate::store::McpCapabilitiesPolicy {
        allow: vec![],
        deny,
    }
    .effective()
}

#[test]
fn classify_server_notification_maps_all_known_and_custom_methods() {
    let cases: Vec<(&str, Option<serde_json::Value>)> = vec![
        (
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 1})),
        ),
        (
            "notifications/progress",
            Some(serde_json::json!({"progressToken": "p1", "progress": 1.0})),
        ),
        (
            "notifications/message",
            Some(serde_json::json!({"level": "info", "data": "hello"})),
        ),
        (
            "notifications/resources/updated",
            Some(serde_json::json!({"uri": "file:///r1"})),
        ),
        ("notifications/resources/list_changed", None),
        ("notifications/tools/list_changed", None),
        ("notifications/prompts/list_changed", None),
        (
            "notifications/elicitation/complete",
            Some(serde_json::json!({"elicitationId": "e1"})),
        ),
        (
            "notifications/tasks/status",
            Some(serde_json::json!({
                "taskId": "task-1",
                "status": "working",
                "createdAt": "2026-07-12T00:00:00Z",
                "lastUpdatedAt": "2026-07-12T00:00:00Z",
                "ttl": null
            })),
        ),
        (
            "notifications/custom/example",
            Some(serde_json::json!({"value": 1})),
        ),
    ];

    for (method, params) in cases {
        let notification = parse_server_notification(method, params);
        let kind = classify_server_notification(&notification);
        assert_eq!(
            kind.method(),
            method,
            "notification method mismatch for {method}"
        );
    }
}

#[test]
fn notification_policy_respects_capability_gates() {
    let filter = crate::store::McpNotificationFilter::default();

    let logging = classify_server_notification(&parse_server_notification(
        "notifications/message",
        Some(serde_json::json!({"level": "info", "data": "hello"})),
    ));
    assert!(notification_allowed(
        default_effective_caps(),
        &filter,
        &logging
    ));
    assert!(!notification_allowed(
        effective_caps_with_deny(vec![crate::store::McpCapability::Logging]),
        &filter,
        &logging
    ));

    let tools_list = classify_server_notification(&parse_server_notification(
        "notifications/tools/list_changed",
        None,
    ));
    assert!(notification_allowed(
        default_effective_caps(),
        &filter,
        &tools_list
    ));
    assert!(!notification_allowed(
        effective_caps_with_deny(vec![crate::store::McpCapability::ToolsListChanged]),
        &filter,
        &tools_list
    ));

    let resources_list = classify_server_notification(&parse_server_notification(
        "notifications/resources/list_changed",
        None,
    ));
    assert!(notification_allowed(
        default_effective_caps(),
        &filter,
        &resources_list
    ));
    assert!(!notification_allowed(
        effective_caps_with_deny(vec![crate::store::McpCapability::ResourcesListChanged]),
        &filter,
        &resources_list
    ));

    let prompts_list = classify_server_notification(&parse_server_notification(
        "notifications/prompts/list_changed",
        None,
    ));
    assert!(notification_allowed(
        default_effective_caps(),
        &filter,
        &prompts_list
    ));
    assert!(!notification_allowed(
        effective_caps_with_deny(vec![crate::store::McpCapability::PromptsListChanged]),
        &filter,
        &prompts_list
    ));
}

#[test]
fn notification_policy_respects_allow_and_deny_filters_for_all_variants() {
    let caps = default_effective_caps();
    let cases: Vec<(&str, Option<serde_json::Value>)> = vec![
        (
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 1})),
        ),
        (
            "notifications/progress",
            Some(serde_json::json!({"progressToken": "p1", "progress": 1.0})),
        ),
        (
            "notifications/message",
            Some(serde_json::json!({"level": "info", "data": "hello"})),
        ),
        (
            "notifications/resources/updated",
            Some(serde_json::json!({"uri": "file:///r1"})),
        ),
        ("notifications/resources/list_changed", None),
        ("notifications/tools/list_changed", None),
        ("notifications/prompts/list_changed", None),
        (
            "notifications/elicitation/complete",
            Some(serde_json::json!({"elicitationId": "e1"})),
        ),
        (
            "notifications/custom/example",
            Some(serde_json::json!({"value": 1})),
        ),
    ];

    for (method, params) in cases {
        let kind = classify_server_notification(&parse_server_notification(method, params));
        let allow_only = crate::store::McpNotificationFilter {
            allow: vec![method.to_string()],
            deny: vec![],
        };
        assert!(
            notification_allowed(caps, &allow_only, &kind),
            "allow filter should permit {method}"
        );

        let deny_only = crate::store::McpNotificationFilter {
            allow: vec![],
            deny: vec![method.to_string()],
        };
        assert!(
            !notification_allowed(caps, &deny_only, &kind),
            "deny filter should block {method}"
        );
    }
}

#[test]
fn elicitation_completion_notification_is_explicitly_covered() {
    let kind = classify_server_notification(&parse_server_notification(
        "notifications/elicitation/complete",
        Some(serde_json::json!({"elicitationId": "e1"})),
    ));
    assert_eq!(kind, NotificationKind::ElicitationCompletion);
    assert_eq!(kind.method(), "notifications/elicitation/complete");

    let caps = effective_caps_with_deny(vec![
        crate::store::McpCapability::Logging,
        crate::store::McpCapability::ToolsListChanged,
        crate::store::McpCapability::ResourcesListChanged,
        crate::store::McpCapability::PromptsListChanged,
    ]);
    assert!(
        allowed_by_caps_for_notification_kind(caps, &kind),
        "elicitation completion should not be capability-gated"
    );
}

#[test]
fn task_status_notification_is_blocked_until_tasks_are_routed() {
    let kind = classify_server_notification(&parse_server_notification(
        "notifications/tasks/status",
        Some(serde_json::json!({
            "taskId": "task-1",
            "status": "working",
            "createdAt": "2026-07-12T00:00:00Z",
            "lastUpdatedAt": "2026-07-12T00:00:00Z",
            "ttl": null
        })),
    ));
    assert_eq!(kind, NotificationKind::TaskStatus);
    assert!(!notification_allowed(
        default_effective_caps(),
        &crate::store::McpNotificationFilter::default(),
        &kind
    ));
}

#[derive(Clone)]
struct TestStore {
    profiles: HashMap<String, crate::store::Profile>,
    upstreams: HashMap<String, crate::store::Upstream>,
}

#[async_trait]
impl crate::store::Store for TestStore {
    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<crate::store::Profile>> {
        Ok(self.profiles.get(profile_id).cloned())
    }
    async fn get_upstream(
        &self,
        upstream_id: &str,
    ) -> anyhow::Result<Option<crate::store::Upstream>> {
        Ok(self.upstreams.get(upstream_id).cloned())
    }
    async fn get_tenant_tool_source(
        &self,
        _tenant_id: &str,
        _source_id: &str,
    ) -> anyhow::Result<Option<crate::store::TenantToolSource>> {
        Ok(None)
    }
    async fn get_tenant_secret_value(
        &self,
        _tenant_id: &str,
        _name: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
    async fn get_tenant_transport_limits(
        &self,
        _tenant_id: &str,
    ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
        Ok(None)
    }
    async fn authenticate_api_key(
        &self,
        _tenant_id: &str,
        _profile_id: &str,
        _secret: &str,
    ) -> anyhow::Result<Option<crate::store::ApiKeyAuth>> {
        Ok(None)
    }
    async fn is_api_key_active(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
    async fn touch_api_key(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn record_tool_call_attempt(
        &self,
        _tenant_id: &str,
        _api_key_id: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn check_and_apply_tool_call_limits(
        &self,
        _tenant_id: &str,
        _profile_id: &str,
        _api_key_id: &str,
        _rate_limit_tool_calls_per_minute: Option<i64>,
        _quota_tool_calls: Option<i64>,
    ) -> anyhow::Result<Option<crate::store::ToolCallLimitRejection>> {
        Ok(None)
    }
    async fn is_oidc_principal_allowed(
        &self,
        _tenant_id: &str,
        _profile_id: &str,
        _issuer: &str,
        _subject: &str,
    ) -> anyhow::Result<bool> {
        Ok(false)
    }
}

async fn start_server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn retry_delay_matches_temporal_style_backoff() {
    let policy = RetryPolicy {
        maximum_attempts: 5,
        initial_interval_ms: 100,
        backoff_coefficient: 2.0,
        maximum_interval_ms: Some(1_000),
        non_retryable_error_types: vec![],
    };
    assert_eq!(
        super::tool_call::retry_delay(&policy, 1),
        Duration::from_millis(100)
    );
    assert_eq!(
        super::tool_call::retry_delay(&policy, 2),
        Duration::from_millis(200)
    );
    assert_eq!(
        super::tool_call::retry_delay(&policy, 3),
        Duration::from_millis(400)
    );
    assert_eq!(
        super::tool_call::retry_delay(&policy, 4),
        Duration::from_millis(800)
    );
    assert_eq!(
        super::tool_call::retry_delay(&policy, 5),
        Duration::from_millis(1_000)
    ); // capped
}

#[test]
fn proxied_request_id_roundtrips_opaque_and_readable() {
    let original = RequestId::Number(42);

    // Opaque: base64 encodes upstream id so dots/utf8 are safe.
    let upstream_opaque = "u.one.two/✓";
    let proxied = make_proxied_request_id(
        RequestIdNamespacing::Opaque,
        upstream_opaque,
        &original,
        None,
    );
    let Some((got_upstream, got_original)) = parse_proxied_request_id(&proxied, None) else {
        panic!("failed to parse opaque proxied request id: {proxied:?}");
    };
    assert_eq!(got_upstream, upstream_opaque);
    assert_eq!(got_original, original);

    // Readable: upstream id is used as-is; parsing splits at last '.'.
    let upstream_readable = "u.one.two";
    let proxied = make_proxied_request_id(
        RequestIdNamespacing::Readable,
        upstream_readable,
        &original,
        None,
    );
    let Some((got_upstream, got_original)) = parse_proxied_request_id(&proxied, None) else {
        panic!("failed to parse readable proxied request id: {proxied:?}");
    };
    assert_eq!(got_upstream, upstream_readable);
    assert_eq!(got_original, original);

    // Signed v2: requires a key to parse/route (mitigates forged responses).
    let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
    let proxied = make_proxied_request_id(
        RequestIdNamespacing::Opaque,
        upstream_opaque,
        &original,
        Some(key),
    );
    let Some((got_upstream, got_original)) = parse_proxied_request_id(&proxied, Some(key)) else {
        panic!("failed to parse signed proxied request id: {proxied:?}");
    };
    assert_eq!(got_upstream, upstream_opaque);
    assert_eq!(got_original, original);
    assert!(
        parse_proxied_request_id(&proxied, None).is_none(),
        "signed proxied id should not parse without key"
    );

    // Forge: flip one character in the signature (must fail verification).
    let RequestId::String(s) = proxied.clone() else {
        panic!("expected string request id");
    };
    let mut parts: Vec<String> = s.split('.').map(std::string::ToString::to_string).collect();
    let sig = parts.last_mut().expect("sig part");
    if sig.starts_with('A') {
        sig.replace_range(0..1, "B");
    } else {
        sig.replace_range(0..1, "A");
    }
    let forged = RequestId::String(parts.join(".").into());
    assert!(parse_proxied_request_id(&forged, Some(key)).is_none());
}

#[test]
fn resource_collision_urn_is_deterministic_and_parsable() {
    let original = "https://example.com/a?b=c";
    let urn1 = resource_collision_urn("u1", original);
    let urn2 = resource_collision_urn("u1", original);
    assert_eq!(urn1, urn2);
    assert!(urn1.starts_with(super::ids::RESOURCE_URN_PREFIX));

    let (upstream_id, hash) = super::ids::parse_resource_collision_urn(&urn1).expect("parse urn");
    assert_eq!(upstream_id, "u1");
    assert!(!hash.is_empty());

    // Upstream id is part of the URN.
    let urn_other = resource_collision_urn("u2", original);
    assert_ne!(urn_other, urn1);
}

#[test]
fn session_token_expiry_maps_to_unauthorized_expired_message() {
    let signer =
        SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(0)).expect("signer");
    let payload = TokenPayloadV1 {
        profile_id: "p".to_string(),
        bindings: vec![],
        auth: None,
        oidc: None,
        iat: None,
        exp: None,
        proxy_key: None,
    };
    let token = signer.sign(payload).expect("token");

    // Ensure we're at least 1 unix-second after sign() so `now_secs > exp`.
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        == start
    {
        std::thread::yield_now();
    }

    let err = verify_session_token(&signer, &token, "p").unwrap_err();
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        err.1,
        "Unauthorized: session expired; re-initialize required"
    );
}

#[tokio::test]
async fn post_returns_jsonrpc_invalid_request_for_valid_json_invalid_shape_when_id_present() {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let profile = crate::store::Profile {
        id: profile_id.clone(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec![],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: crate::store::McpProfileSettings::default(),
    };

    let store = Arc::new(TestStore {
        profiles: HashMap::from([(profile_id.clone(), profile)]),
        upstreams: HashMap::new(),
    });
    let state = Arc::new(McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(SharedCatalog::default()),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    });

    let app = super::router(state);
    let (base, handle) = start_server(app).await;

    // Valid JSON, but invalid JSON-RPC/MCP shape (`method` must be a string).
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": 123,
        "params": {}
    });

    let resp = reqwest::Client::new()
        .post(format!("{base}/{profile_id}/mcp"))
        .header(
            reqwest::header::ACCEPT,
            format!("{JSON_MIME_TYPE}, {EVENT_STREAM_MIME_TYPE}"),
        )
        .header(reqwest::header::CONTENT_TYPE, JSON_MIME_TYPE)
        .body(body.to_string())
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with(EVENT_STREAM_MIME_TYPE),
        "expected SSE content-type"
    );

    let text = resp.text().await.expect("body text");
    assert!(
        text.contains(&format!("\"code\":{}", ErrorCode::INVALID_REQUEST.0)),
        "body: {text}"
    );
    assert!(text.contains("invalid-mcp-shape"), "body: {text}");

    handle.abort();
}

#[tokio::test]
async fn post_rejects_when_post_body_limit_exceeded() {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let mut mcp = crate::store::McpProfileSettings::default();
    mcp.security.transport_limits.max_post_body_bytes = Some(128);
    let profile = crate::store::Profile {
        id: profile_id.clone(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec![],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp,
    };

    let store = Arc::new(TestStore {
        profiles: HashMap::from([(profile_id.clone(), profile)]),
        upstreams: HashMap::new(),
    });
    let state = Arc::new(McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(SharedCatalog::default()),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    });

    let app = super::router(state);
    let (base, handle) = start_server(app).await;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": { "pad": "x".repeat(2_048) }
    });

    let resp = reqwest::Client::new()
        .post(format!("{base}/{profile_id}/mcp"))
        .header(
            reqwest::header::ACCEPT,
            format!("{JSON_MIME_TYPE}, {EVENT_STREAM_MIME_TYPE}"),
        )
        .header(reqwest::header::CONTENT_TYPE, JSON_MIME_TYPE)
        .body(body.to_string())
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let text = resp.text().await.expect("body text");
    assert!(text.contains("payload too large"), "body: {text}");

    handle.abort();
}

#[tokio::test]
async fn post_returns_jsonrpc_error_when_json_complexity_limit_exceeded() {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let mut mcp = crate::store::McpProfileSettings::default();
    mcp.security.transport_limits.max_json_depth = Some(2);
    let profile = crate::store::Profile {
        id: profile_id.clone(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec![],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp,
    };

    let store = Arc::new(TestStore {
        profiles: HashMap::from([(profile_id.clone(), profile)]),
        upstreams: HashMap::new(),
    });
    let state = Arc::new(McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(SharedCatalog::default()),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    });

    let app = super::router(state);
    let (base, handle) = start_server(app).await;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/list",
        "params": {
            "nested": {
                "v": {
                    "x": 1
                }
            }
        }
    });

    let resp = reqwest::Client::new()
        .post(format!("{base}/{profile_id}/mcp"))
        .header(
            reqwest::header::ACCEPT,
            format!("{JSON_MIME_TYPE}, {EVENT_STREAM_MIME_TYPE}"),
        )
        .header(reqwest::header::CONTENT_TYPE, JSON_MIME_TYPE)
        .body(body.to_string())
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let text = resp.text().await.expect("body text");
    assert!(
        text.contains(&format!("\"code\":{}", ErrorCode::INVALID_REQUEST.0)),
        "body: {text}"
    );
    assert!(text.contains("payload-too-complex"), "body: {text}");
    assert!(text.contains("maxJsonDepth"), "body: {text}");

    handle.abort();
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn initialize_profile_sources_fails_over_endpoints() {
    let bad = Router::new().route(
        "/mcp",
        post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "nope") }),
    );
    let (bad_base, bad_handle) = start_server(bad).await;
    let bad_url = format!("{bad_base}/mcp");

    let good = Router::new().route(
        "/mcp",
        post(|axum::Json(v): axum::Json<serde_json::Value>| async move {
            // Simulate a minimal MCP server over streamable HTTP:
            // - `initialize` returns a session id and a JSON response
            // - `notifications/initialized` returns 202 Accepted
            if v.get("method") == Some(&serde_json::json!("notifications/initialized")) {
                return (axum::http::StatusCode::ACCEPTED, "").into_response();
            }

            let id = v.get("id").cloned().unwrap_or_else(|| serde_json::json!(1));
            let resp = serde_json::json!({
              "jsonrpc": "2.0",
              "id": id,
              "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": { "name": "test", "version": "0" }
              }
            });
            let mut headers = HeaderMap::new();
            headers.insert(HEADER_SESSION_ID, HeaderValue::from_static("up-session"));
            (headers, axum::Json(resp)).into_response()
        }),
    );
    let (good_base, good_handle) = start_server(good).await;
    let good_url = format!("{good_base}/mcp");

    let store = Arc::new(TestStore {
        profiles: HashMap::new(),
        upstreams: HashMap::from([(
            "u1".to_string(),
            crate::store::Upstream {
                network_class: crate::store::UpstreamNetworkClass::External,
                endpoints: vec![
                    crate::store::UpstreamEndpoint {
                        id: "a".to_string(),
                        url: bad_url,
                        enabled: true,
                        lifecycle: crate::store::UpstreamEndpointLifecycle::Active,
                        auth: None,
                    },
                    crate::store::UpstreamEndpoint {
                        id: "b".to_string(),
                        url: good_url,
                        enabled: true,
                        lifecycle: crate::store::UpstreamEndpointLifecycle::Active,
                        auth: None,
                    },
                ],
            },
        )]),
    });

    let state = McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(SharedCatalog::default()),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    };

    let profile = crate::store::Profile {
        id: "p".to_string(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: false,
        source_ids: vec!["u1".to_string()],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: crate::store::McpProfileSettings::default(),
    };

    let init = InitializeRequest::new(InitializeRequestParams::new(
        ClientCapabilities::default(),
        Implementation::from_build_env(),
    ));
    let init_msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::InitializeRequest(init),
    });

    let (bindings, warnings) = initialize_profile_sources(&state, &profile, &init_msg, 0)
        .await
        .expect("init ok");
    assert!(warnings.is_empty(), "no upstream should be fully down");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].upstream, "u1");
    assert_eq!(bindings[0].endpoint, "b");
    assert_eq!(bindings[0].session, "up-session");

    bad_handle.abort();
    good_handle.abort();
}

#[allow(clippy::too_many_lines)] // Test includes full upstream mock + gateway wiring.
#[tokio::test]
async fn upstream_server_to_client_request_blocking_drops_event_and_errors_upstream() {
    use axum::response::sse::{Event, Sse};
    use futures::StreamExt as _;

    let posted: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let posted_for_post = posted.clone();

    let upstream = Router::new().route(
        "/mcp",
        get(|| async {
            // Server→client request (interactive).
            let data = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "roots/list",
                "params": {}
            })
            .to_string();

            let stream =
                futures::stream::iter(vec![Ok::<_, Infallible>(Event::default().data(data))]);
            Sse::new(stream)
        })
        .post(
            move |axum::Json(v): axum::Json<serde_json::Value>| async move {
                posted_for_post.lock().expect("lock").push(v);
                StatusCode::ACCEPTED
            },
        ),
    );
    let (up_base, up_handle) = start_server(upstream).await;
    let up_url = format!("{up_base}/mcp");

    let store = Arc::new(TestStore {
        profiles: HashMap::new(),
        upstreams: HashMap::from([(
            "u1".to_string(),
            crate::store::Upstream {
                network_class: crate::store::UpstreamNetworkClass::External,
                endpoints: vec![crate::store::UpstreamEndpoint {
                    id: "e1".to_string(),
                    url: up_url,
                    enabled: true,
                    lifecycle: crate::store::UpstreamEndpointLifecycle::Active,
                    auth: None,
                }],
            },
        )]),
    });

    let state = McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(SharedCatalog::default()),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    };

    let mut mcp = crate::store::McpProfileSettings::default();
    mcp.security.upstream_overrides.insert(
        "u1".to_string(),
        crate::store::UpstreamSecurityPolicy {
            server_requests: crate::store::McpServerRequestFilter {
                default_action: crate::store::McpPolicyAction::Deny,
                allow: vec![],
                deny: vec![],
            },
            ..Default::default()
        },
    );
    let profile = crate::store::Profile {
        id: "p".to_string(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec!["u1".to_string()],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp,
    };

    let bindings = vec![UpstreamSessionBinding {
        upstream: "u1".to_string(),
        endpoint: "e1".to_string(),
        session: "up-session".to_string(),
    }];

    let collision_counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let limits = crate::transport_limits::EffectiveTransportLimits::from_profile_and_tenant(
        &profile.mcp.security.transport_limits,
        None,
    );
    let last = ParsedLastEventId::default();
    let streams = open_upstream_streams(OpenUpstreamStreamsInputs {
        state: &state,
        profile: &profile,
        bindings: &bindings,
        last: &last,
        resource_collision_counts: collision_counts,
        proxy_key: None,
        hop: 0,
        limits,
        limits_shutdown: CancellationToken::new(),
    })
    .await
    .expect("open streams");
    assert_eq!(streams.len(), 1);

    let mut s = streams.into_iter().next().expect("stream");
    let next = tokio::time::timeout(Duration::from_secs(1), s.next())
        .await
        .expect("timeout");
    assert!(
        next.is_none(),
        "expected blocked upstream request to be dropped"
    );

    let posts = posted.lock().expect("lock").clone();
    assert_eq!(posts.len(), 1, "expected one error response to upstream");
    let err = &posts[0];
    assert_eq!(err.get("jsonrpc"), Some(&serde_json::json!("2.0")));
    assert_eq!(err.get("id"), Some(&serde_json::json!(1)));
    assert_eq!(
        err.get("error")
            .and_then(|e| e.get("code"))
            .and_then(serde_json::Value::as_i64),
        Some(i64::from(ErrorCode::METHOD_NOT_FOUND.0))
    );

    up_handle.abort();
}

#[derive(Clone)]
struct CountingStore {
    upstreams: HashMap<String, crate::store::Upstream>,
    tenant_sources: HashSet<String>,
    get_upstream_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl crate::store::Store for CountingStore {
    async fn get_profile(
        &self,
        _profile_id: &str,
    ) -> anyhow::Result<Option<crate::store::Profile>> {
        Ok(None)
    }

    async fn get_upstream(
        &self,
        upstream_id: &str,
    ) -> anyhow::Result<Option<crate::store::Upstream>> {
        self.get_upstream_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.upstreams.get(upstream_id).cloned())
    }

    async fn get_tenant_tool_source(
        &self,
        _tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<crate::store::TenantToolSource>> {
        if self.tenant_sources.contains(source_id) {
            // We don't need a usable spec for this test: we only need TenantCatalog::has_tool_source
            // to return true, which is based on presence.
            return Ok(Some(crate::store::TenantToolSource {
                id: source_id.to_string(),
                kind: crate::store::ToolSourceKind::Http,
                enabled: true,
                spec: crate::store::ToolSourceSpec::Http(
                    unrelated_http_tools::config::HttpServerConfig {
                        base_url: "https://example.com".to_string(),
                        auth: None,
                        defaults: unrelated_http_tools::config::EndpointDefaults::default(),
                        response_transforms: vec![],
                        tools: HashMap::new(),
                    },
                ),
            }));
        }
        Ok(None)
    }

    async fn get_tenant_secret_value(
        &self,
        _tenant_id: &str,
        _name: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(None)
    }

    async fn get_tenant_transport_limits(
        &self,
        _tenant_id: &str,
    ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
        Ok(None)
    }

    async fn authenticate_api_key(
        &self,
        _tenant_id: &str,
        _profile_id: &str,
        _secret: &str,
    ) -> anyhow::Result<Option<crate::store::ApiKeyAuth>> {
        Ok(None)
    }

    async fn is_api_key_active(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<bool> {
        Ok(false)
    }

    async fn touch_api_key(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn record_tool_call_attempt(
        &self,
        _tenant_id: &str,
        _api_key_id: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn check_and_apply_tool_call_limits(
        &self,
        _tenant_id: &str,
        _profile_id: &str,
        _api_key_id: &str,
        _rate_limit_tool_calls_per_minute: Option<i64>,
        _quota_tool_calls: Option<i64>,
    ) -> anyhow::Result<Option<crate::store::ToolCallLimitRejection>> {
        Ok(None)
    }

    async fn is_oidc_principal_allowed(
        &self,
        _tenant_id: &str,
        _profile_id: &str,
        _issuer: &str,
        _subject: &str,
    ) -> anyhow::Result<bool> {
        Ok(false)
    }
}

#[tokio::test]
async fn initialize_profile_sources_skips_shared_and_tenant_local_sources() -> anyhow::Result<()> {
    let cfg: GatewayConfig = serde_yaml::from_str(
        r"
tenants: {}
profiles: {}
upstreams: {}
sharedSources:
  s_local:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      local_ping:
        method: GET
        path: /ping
",
    )
    .expect("valid yaml");
    let shared = SharedCatalog::from_config(&cfg).await?;

    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(CountingStore {
        upstreams: HashMap::from([(
            "u1".to_string(),
            crate::store::Upstream {
                network_class: crate::store::UpstreamNetworkClass::External,
                endpoints: vec![crate::store::UpstreamEndpoint {
                    id: "e1".to_string(),
                    url: "http://127.0.0.1:1/mcp".to_string(),
                    enabled: true,
                    lifecycle: crate::store::UpstreamEndpointLifecycle::Active,
                    auth: None,
                }],
            },
        )]),
        tenant_sources: HashSet::from(["t_local".to_string()]),
        get_upstream_calls: calls.clone(),
    });

    let state = McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(shared),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    };

    let profile = crate::store::Profile {
        id: "p".to_string(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec![
            "s_local".to_string(),
            "t_local".to_string(),
            "u1".to_string(),
        ],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: crate::store::McpProfileSettings::default(),
    };

    let init = InitializeRequest::new(InitializeRequestParams::new(
        ClientCapabilities::default(),
        Implementation::from_build_env(),
    ));
    let init_msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::InitializeRequest(init),
    });

    // We expect this to try resolving exactly one upstream id ("u1"), skipping local sources.
    // It will fail to initialize because endpoint is unreachable, but allow_partial_upstreams
    // should make it return a warning instead of an error.
    let (_bindings, warnings) = initialize_profile_sources(&state, &profile, &init_msg, 0)
        .await
        .expect("init ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(warnings.len(), 1);
    Ok(())
}

#[tokio::test]
async fn tools_surface_prefixes_on_collision_across_shared_sources() -> anyhow::Result<()> {
    let cfg: GatewayConfig = serde_yaml::from_str(
        r"
tenants: {}
profiles: {}
upstreams: {}
sharedSources:
  s1:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      ping:
        method: GET
        path: /ping
  s2:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      ping:
        method: GET
        path: /ping
",
    )
    .expect("valid yaml");
    let shared = SharedCatalog::from_config(&cfg).await?;

    let store = Arc::new(TestStore {
        profiles: HashMap::new(),
        upstreams: HashMap::new(),
    });
    let state = McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(shared),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    };

    let profile = crate::store::Profile {
        id: "p".to_string(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec!["s1".to_string(), "s2".to_string()],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: crate::store::McpProfileSettings::default(),
    };
    let payload = TokenPayloadV1 {
        profile_id: profile.id.clone(),
        bindings: vec![],
        auth: None,
        oidc: None,
        iat: None,
        exp: None,
        proxy_key: None,
    };

    let surface = super::surface::build_tools_surface(&state, &profile.id, &profile, &payload, 0)
        .await
        .expect("build tools surface");
    assert!(surface.ambiguous_names.contains("ping"));
    assert!(!surface.routes.contains_key("ping"));
    assert!(surface.routes.contains_key("s1:ping"));
    assert!(surface.routes.contains_key("s2:ping"));

    let r1 = surface.routes.get("s1:ping").expect("s1 route");
    assert_eq!(r1.kind, ToolRouteKind::SharedLocal);
    assert_eq!(r1.source_id, "s1");
    assert_eq!(r1.original_name, "ping");

    Ok(())
}

#[tokio::test]
async fn tools_surface_allows_optional_prefix_when_not_ambiguous() -> anyhow::Result<()> {
    let cfg: GatewayConfig = serde_yaml::from_str(
        r"
tenants: {}
profiles: {}
upstreams: {}
sharedSources:
  s1:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      ping:
        method: GET
        path: /ping
",
    )
    .expect("valid yaml");
    let shared = SharedCatalog::from_config(&cfg).await?;

    let store = Arc::new(TestStore {
        profiles: HashMap::new(),
        upstreams: HashMap::new(),
    });
    let state = McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(shared),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    };

    let profile = crate::store::Profile {
        id: "p".to_string(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: true,
        source_ids: vec!["s1".to_string()],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: crate::store::McpProfileSettings::default(),
    };
    let payload = TokenPayloadV1 {
        profile_id: profile.id.clone(),
        bindings: vec![],
        auth: None,
        oidc: None,
        iat: None,
        exp: None,
        proxy_key: None,
    };

    let surface = super::surface::build_tools_surface(&state, &profile.id, &profile, &payload, 0)
        .await
        .expect("build tools surface");
    assert!(!surface.ambiguous_names.contains("ping"));
    assert!(surface.routes.contains_key("ping"));
    assert!(surface.routes.contains_key("s1:ping"));

    let base = surface.routes.get("ping").expect("base route");
    let pref = surface.routes.get("s1:ping").expect("pref route");
    assert_eq!(base.kind, ToolRouteKind::SharedLocal);
    assert_eq!(pref.kind, ToolRouteKind::SharedLocal);
    assert_eq!(base.source_id, "s1");
    assert_eq!(pref.source_id, "s1");
    assert_eq!(base.original_name, "ping");
    assert_eq!(pref.original_name, "ping");
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn tool_call_propagates_timeout_budget_meta_and_retries_when_configured() {
    let seen_timeout_ms = Arc::new(Mutex::new(None::<u64>));
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new().route(
        "/mcp",
        post({
            let seen_timeout_ms = seen_timeout_ms.clone();
            let calls = calls.clone();
            move |axum::Json(v): axum::Json<serde_json::Value>| async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                let timeout_ms = v
                    .get("params")
                    .and_then(|p| p.get("_meta"))
                    .and_then(|m| m.get("unrelated"))
                    .and_then(|m| m.get("timeoutMs"))
                    .and_then(serde_json::Value::as_u64);
                *seen_timeout_ms.lock().expect("lock") = timeout_ms;

                // Fail the first attempt to force a retry.
                if n == 0 {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "try again").into_response();
                }

                let id = v.get("id").cloned().unwrap_or_else(|| serde_json::json!(1));
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": "ok" }],
                        "isError": false
                    }
                });
                axum::Json(resp).into_response()
            }
        }),
    );
    let (base, handle) = start_server(app).await;
    let url = format!("{base}/mcp");

    let store = Arc::new(TestStore {
        profiles: HashMap::new(),
        upstreams: HashMap::from([(
            "u1".to_string(),
            crate::store::Upstream {
                network_class: crate::store::UpstreamNetworkClass::External,
                endpoints: vec![crate::store::UpstreamEndpoint {
                    id: "e1".to_string(),
                    url,
                    enabled: true,
                    lifecycle: crate::store::UpstreamEndpointLifecycle::Active,
                    auth: None,
                }],
            },
        )]),
    });

    let state = McpState {
        store,
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60)).expect("signer"),
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(SharedCatalog::default()),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    };

    let profile = crate::store::Profile {
        id: "p".to_string(),
        tenant_id: "t".to_string(),
        allow_partial_upstreams: false,
        source_ids: vec!["u1".to_string()],
        transforms: unrelated_tool_transforms::TransformPipeline::default(),
        enabled_tools: Vec::new(),
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![ToolPolicy {
            tool: "u1:foo".to_string(),
            timeout_secs: Some(2),
            retry: Some(RetryPolicy {
                maximum_attempts: 2,
                initial_interval_ms: 0,
                backoff_coefficient: 1.0,
                maximum_interval_ms: None,
                non_retryable_error_types: vec![],
            }),
        }],
        mcp: crate::store::McpProfileSettings::default(),
    };

    let payload = TokenPayloadV1 {
        profile_id: profile.id.clone(),
        bindings: vec![UpstreamSessionBinding {
            upstream: "u1".to_string(),
            endpoint: "e1".to_string(),
            session: "s".to_string(),
        }],
        auth: None,
        oidc: None,
        iat: None,
        exp: None,
        proxy_key: None,
    };

    // Seed tool routing cache so we don't have to build the full tools surface.
    let fp = profile_fingerprint(&profile);
    let routes = Arc::new(HashMap::from([(
        "foo".to_string(),
        ToolRoute {
            kind: ToolRouteKind::Upstream,
            source_id: "u1".to_string(),
            original_name: "foo".to_string(),
        },
    )]));
    let surface = CachedToolsSurface {
        tools: Arc::new(Vec::new()),
        routes,
        ambiguous_names: Arc::new(HashSet::new()),
    };
    state.tools_cache.put("p", "tok".to_string(), fp, surface);

    let mut msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::CallToolRequest(rmcp::model::CallToolRequest::new(
            CallToolRequestParams::new(Cow::Owned("foo".to_string())),
        )),
    });

    let resp = route_and_proxy_tools_call(
        &state,
        "p",
        &profile,
        &payload,
        "tok".to_string(),
        &mut msg,
        0,
    )
    .await
    .expect("tool call ok");

    assert_eq!(calls.load(Ordering::SeqCst), 2, "should retry once");
    let timeout_ms = seen_timeout_ms.lock().expect("lock").expect("timeout meta");
    assert!(timeout_ms > 0);
    assert!(
        timeout_ms <= 2_000,
        "should respect per-tool timeout override"
    );
    assert_eq!(resp.status(), StatusCode::OK);

    handle.abort();
}
