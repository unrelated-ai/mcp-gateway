use rmcp::model::{Prompt, Resource, Tool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractKind {
    Tools,
    Resources,
    Prompts,
}

impl ContractKind {
    #[must_use]
    pub fn list_changed_method(self) -> &'static str {
        match self {
            ContractKind::Tools => "notifications/tools/list_changed",
            ContractKind::Resources => "notifications/resources/list_changed",
            ContractKind::Prompts => "notifications/prompts/list_changed",
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ContractKind::Tools => "tools",
            ContractKind::Resources => "resources",
            ContractKind::Prompts => "prompts",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractChange {
    pub profile_id: String,
    pub kind: ContractKind,
    pub contract_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractEvent {
    pub profile_id: String,
    pub kind: ContractKind,
    pub contract_hash: String,
    pub event_id: u64,
}

#[derive(Debug, Default)]
struct SurfaceHashes {
    tools: Option<String>,
    resources: Option<String>,
    prompts: Option<String>,
}

/// Tracks "public contract" hashes (per profile) and provides best-effort notifications.
pub struct ContractTracker {
    hashes: Mutex<HashMap<String, SurfaceHashes>>,
    notifiers: Mutex<HashMap<String, broadcast::Sender<ContractEvent>>>,
    global: broadcast::Sender<ContractEvent>,
    next_event_id: AtomicU64,
}

impl ContractTracker {
    #[must_use]
    pub fn new() -> Self {
        // Global event stream: used for internal watchers (cache invalidation, metrics, etc.).
        // Larger buffer than per-profile, since consumers may be slower.
        let (global, _rx) = broadcast::channel::<ContractEvent>(256);
        Self {
            hashes: Mutex::new(HashMap::new()),
            notifiers: Mutex::new(HashMap::new()),
            global,
            next_event_id: AtomicU64::new(1),
        }
    }

    /// Subscribe to contract change notifications for a profile.
    ///
    /// This is best-effort: no replay/buffering beyond the broadcast channel.
    pub fn subscribe(&self, profile_id: &str) -> broadcast::Receiver<ContractEvent> {
        let mut map = self.notifiers.lock().expect("lock notifiers");
        let sender = map.entry(profile_id.to_string()).or_insert_with(|| {
            // Small bounded buffer; lag is acceptable in v1.
            let (tx, _rx) = broadcast::channel::<ContractEvent>(64);
            tx
        });
        sender.subscribe()
    }

    /// Subscribe to all contract change notifications (across all profiles).
    ///
    /// This stream is best-effort (bounded buffer); receivers should tolerate lag.
    pub fn subscribe_all(&self) -> broadcast::Receiver<ContractEvent> {
        self.global.subscribe()
    }

    /// Update the tools contract hash and broadcast `notifications/tools/list_changed` if it changed.
    ///
    /// # Notes
    ///
    /// - On first observation of a profile, we record the hash but do not notify.
    /// - Notifications are best-effort; if no receivers exist, we drop the notification.
    pub fn update_tools_contract(
        &self,
        profile_id: &str,
        tools: &[Tool],
    ) -> Option<ContractChange> {
        let new_hash = tools_contract_hash(tools);
        self.update_contract_hash(profile_id, ContractKind::Tools, new_hash, false)
    }

    /// Update the resources contract hash and broadcast `notifications/resources/list_changed` if it changed.
    ///
    /// # Notes
    ///
    /// - On first observation of a profile, we record the hash but do not notify.
    /// - Notifications are best-effort; if no receivers exist, we drop the notification.
    pub fn update_resources_contract(
        &self,
        profile_id: &str,
        resources: &[Resource],
    ) -> Option<ContractChange> {
        let new_hash = resources_contract_hash(resources);
        self.update_contract_hash(profile_id, ContractKind::Resources, new_hash, false)
    }

    /// Update the prompts contract hash and broadcast `notifications/prompts/list_changed` if it changed.
    ///
    /// # Notes
    ///
    /// - On first observation of a profile, we record the hash but do not notify.
    /// - Notifications are best-effort; if no receivers exist, we drop the notification.
    pub fn update_prompts_contract(
        &self,
        profile_id: &str,
        prompts: &[Prompt],
    ) -> Option<ContractChange> {
        let new_hash = prompts_contract_hash(prompts);
        self.update_contract_hash(profile_id, ContractKind::Prompts, new_hash, false)
    }

    #[must_use]
    pub fn next_local_event_id(&self) -> u64 {
        self.next_event_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Apply a contract update that originated outside this node (e.g. via HA fanout).
    ///
    /// This is idempotent: if the hash is already current, it does nothing.
    pub fn apply_remote_event(&self, event: &ContractEvent) {
        if self
            .update_contract_hash(
                &event.profile_id,
                event.kind,
                event.contract_hash.clone(),
                true,
            )
            .is_some()
        {
            self.broadcast_event(event.clone());
        }
    }

    fn update_contract_hash(
        &self,
        profile_id: &str,
        kind: ContractKind,
        new_hash: String,
        notify_on_first: bool,
    ) -> Option<ContractChange> {
        let mut hashes = self.hashes.lock().expect("lock hashes");
        let entry = hashes.entry(profile_id.to_string()).or_default();

        let prev = match kind {
            ContractKind::Tools => entry.tools.clone(),
            ContractKind::Resources => entry.resources.clone(),
            ContractKind::Prompts => entry.prompts.clone(),
        };

        if prev.as_deref() == Some(&new_hash) {
            return None;
        }

        match kind {
            ContractKind::Tools => entry.tools = Some(new_hash.clone()),
            ContractKind::Resources => entry.resources = Some(new_hash.clone()),
            ContractKind::Prompts => entry.prompts = Some(new_hash.clone()),
        }
        drop(hashes);

        // First time: just record (unless explicitly asked to notify).
        if prev.is_none() && !notify_on_first {
            return None;
        }

        Some(ContractChange {
            profile_id: profile_id.to_string(),
            kind,
            contract_hash: new_hash,
        })
    }

    pub fn broadcast_event(&self, event: ContractEvent) {
        // Always publish to global stream (best-effort).
        let _ = self.global.send(event.clone());

        if let Some(sender) = self
            .notifiers
            .lock()
            .expect("lock notifiers")
            .get(&event.profile_id)
            .cloned()
        {
            let _ = sender.send(event);
        }
    }
}

#[must_use]
pub fn list_changed_notification_json(event: &ContractEvent) -> String {
    // Event id + contract hash are embedded in params for debugging; they are not part of MCP semantics.
    let v = serde_json::json!({
        "jsonrpc": "2.0",
        "method": event.kind.list_changed_method(),
        "params": { "eventId": event.event_id, "contractHash": event.contract_hash }
    });
    serde_json::to_string(&v).expect("valid json")
}

fn tools_contract_hash(tools: &[Tool]) -> String {
    // Canonical surface representation:
    // - sort tools by name
    // - include name + description + canonicalized input schema + canonicalized output schema
    let mut entries: Vec<(String, String, Value, Value, Value)> = tools
        .iter()
        .map(|t| {
            let name = t.name.to_string();
            let description = t.description.as_deref().unwrap_or_default().to_string();
            let input_schema = canonicalize_json(&Value::Object(t.input_schema.as_ref().clone()));
            let output_schema = t.output_schema.as_ref().map_or(Value::Null, |s| {
                canonicalize_json(&Value::Object(s.as_ref().clone()))
            });
            let annotations = serde_json::to_value(&t.annotations).unwrap_or(Value::Null);
            let annotations = canonicalize_json(&annotations);
            (name, description, input_schema, output_schema, annotations)
        })
        .collect();

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let v = Value::Array(
        entries
            .into_iter()
            .map(
                |(name, description, input_schema, output_schema, annotations)| {
                    serde_json::json!({
                        "name": name,
                        "description": description,
                        "inputSchema": input_schema,
                        "outputSchema": output_schema,
                        "annotations": annotations,
                    })
                },
            )
            .collect(),
    );

    let serialized = serde_json::to_string(&canonicalize_json(&v)).expect("valid json");
    hex::encode(sha2::Sha256::digest(serialized.as_bytes()))
}

fn resources_contract_hash(resources: &[Resource]) -> String {
    let mut entries: Vec<(String, Value)> = resources
        .iter()
        .map(|r| {
            let uri = r.uri.clone();
            let v = serde_json::to_value(r).expect("resource serializes");
            (uri, canonicalize_json(&v))
        })
        .collect();

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let v = Value::Array(entries.into_iter().map(|(_k, v)| v).collect());
    let serialized = serde_json::to_string(&canonicalize_json(&v)).expect("valid json");
    hex::encode(sha2::Sha256::digest(serialized.as_bytes()))
}

fn prompts_contract_hash(prompts: &[Prompt]) -> String {
    let mut entries: Vec<(String, Value)> = prompts
        .iter()
        .map(|p| {
            let name = p.name.clone();
            let v = serde_json::to_value(p).expect("prompt serializes");
            (name, canonicalize_json(&v))
        })
        .collect();

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let v = Value::Array(entries.into_iter().map(|(_k, v)| v).collect());
    let serialized = serde_json::to_string(&canonicalize_json(&v)).expect("valid json");
    hex::encode(sha2::Sha256::digest(serialized.as_bytes()))
}

fn canonicalize_json(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(val) = map.get(&k) {
                    out.insert(k, canonicalize_json(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_json).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContractEvent, ContractKind, ContractTracker, resources_contract_hash, tools_contract_hash,
    };
    use rmcp::model::{Annotated, JsonObject, Prompt, PromptArgument, RawResource, Resource, Tool};
    use std::sync::Arc;
    use tokio::sync::broadcast::error::TryRecvError;

    fn tool(name: &str) -> Tool {
        Tool::new(name.to_string(), "", Arc::new(JsonObject::new()))
    }

    fn resource(uri: &str, name: &str) -> Resource {
        Annotated::new(RawResource::new(uri.to_string(), name.to_string()), None)
    }

    #[test]
    fn tools_contract_first_observation_does_not_notify() {
        let tracker = ContractTracker::new();
        let mut rx = tracker.subscribe("p1");

        tracker.update_tools_contract("p1", &[tool("a")]);

        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn tools_contract_is_order_insensitive_and_only_notifies_on_change() {
        let tracker = ContractTracker::new();
        let mut rx = tracker.subscribe("p1");

        // First observation: record only.
        tracker.update_tools_contract("p1", &[tool("b"), tool("a")]);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

        // Same tool set, different order: no notify.
        tracker.update_tools_contract("p1", &[tool("a"), tool("b")]);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

        // Add a tool: notify.
        let change = tracker
            .update_tools_contract("p1", &[tool("a"), tool("b"), tool("c")])
            .expect("change");
        tracker.broadcast_event(ContractEvent {
            profile_id: change.profile_id,
            kind: change.kind,
            contract_hash: change.contract_hash,
            event_id: 1,
        });
        let evt = rx.try_recv().expect("notification event");
        assert_eq!(evt.kind, ContractKind::Tools);
    }

    #[test]
    fn resources_contract_hash_is_order_insensitive() {
        let a = resource("file:///a", "a");
        let b = resource("file:///b", "b");
        assert_eq!(
            resources_contract_hash(&[a.clone(), b.clone()]),
            resources_contract_hash(&[b, a])
        );
    }

    #[test]
    fn prompts_contract_first_observation_does_not_notify() {
        let tracker = ContractTracker::new();
        let mut rx = tracker.subscribe("p1");

        let p = Prompt::new("p1", Some("desc"), None);
        tracker.update_prompts_contract("p1", &[p]);

        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn prompts_contract_notifies_on_change() {
        let tracker = ContractTracker::new();
        let mut rx = tracker.subscribe("p1");

        // First observation: record only.
        let p = Prompt::new("p1", Some("desc"), None);
        tracker.update_prompts_contract("p1", &[p]);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

        // Add an argument: should notify.
        let arg = PromptArgument::new("x").with_required(true);
        let p2 = Prompt::new("p1", Some("desc"), Some(vec![arg]));
        let change = tracker
            .update_prompts_contract("p1", &[p2])
            .expect("change");
        tracker.broadcast_event(ContractEvent {
            profile_id: change.profile_id,
            kind: change.kind,
            contract_hash: change.contract_hash,
            event_id: 1,
        });
        let evt = rx.try_recv().expect("notification event");
        assert_eq!(evt.kind, ContractKind::Prompts);
    }

    #[test]
    fn tools_contract_hash_includes_schema_and_description() {
        let t1 = Tool::new(
            "a".to_string(),
            "d1".to_string(),
            Arc::new(JsonObject::new()),
        );
        let t2 = Tool::new(
            "a".to_string(),
            "d2".to_string(),
            Arc::new(JsonObject::new()),
        );
        assert_ne!(tools_contract_hash(&[t1]), tools_contract_hash(&[t2]));
    }
}
