//! Tool/resource/prompt aggregation and routing.

use crate::backend::{PromptInfo, ResourceInfo};
use parking_lot::{RwLock, RwLockReadGuard};
use rmcp::model::ToolAnnotations;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use unrelated_tool_transforms::TransformPipeline;

/// A parsed `server:name` identifier used for collision disambiguation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerPrefixed<'a> {
    server: &'a str,
    name: &'a str,
}

impl<'a> ServerPrefixed<'a> {
    fn new(server: &'a str, name: &'a str) -> Self {
        debug_assert!(!server.is_empty(), "server must not be empty");
        debug_assert!(!name.is_empty(), "name must not be empty");
        Self { server, name }
    }

    fn parse(s: &'a str) -> Option<Self> {
        let (server, name) = s.rsplit_once(':')?;
        if server.is_empty() || name.is_empty() {
            return None;
        }
        Some(Self { server, name })
    }
}

impl fmt::Display for ServerPrefixed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.server, self.name)
    }
}

/// Mapping information for a tool.
#[derive(Debug, Clone, Serialize)]
pub struct ToolMapping {
    /// Server that owns this tool
    pub server: String,
    /// Original tool name (without prefix)
    pub original_name: String,
    /// Exposed name (may include prefix if there’s a collision)
    pub exposed_name: String,
    /// Tool description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input schema
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    /// Output schema
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Optional MCP tool annotations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

/// Mapping information for a resource.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceMapping {
    /// Server that owns this resource
    pub server: String,
    /// Original URI
    pub original_uri: String,
    /// Exposed URI (may change if there’s a collision)
    pub exposed_uri: String,
    /// Resource name
    pub name: String,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Size in bytes (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Mapping information for a prompt.
#[derive(Debug, Clone, Serialize)]
pub struct PromptMapping {
    /// Server that owns this prompt
    pub server: String,
    /// Original prompt name
    pub original_name: String,
    /// Exposed name (may include prefix if there’s a collision)
    pub exposed_name: String,
    /// Prompt description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt arguments (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<rmcp::model::PromptArgument>>,
}

/// Tool information from MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<Value>,
    #[serde(default, rename = "outputSchema")]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub annotations: Option<ToolAnnotations>,
}

/// The aggregator manages tool/resource/prompt merging and routing.
pub struct Aggregator {
    /// Tool registry: `exposed_name` -> mapping
    tools: Arc<RwLock<HashMap<String, ToolMapping>>>,
    /// Resource registry: `exposed_uri` -> mapping
    resources: Arc<RwLock<HashMap<String, ResourceMapping>>>,
    /// Prompt registry: `exposed_name` -> mapping
    prompts: Arc<RwLock<HashMap<String, PromptMapping>>>,
    /// Track which names have collisions
    tool_collisions: Arc<RwLock<HashSet<String>>>,
    /// Track which resource URIs have collisions
    resource_collisions: Arc<RwLock<HashSet<String>>>,
    /// Track which prompt names have collisions
    prompt_collisions: Arc<RwLock<HashSet<String>>>,
}

impl Aggregator {
    /// Create a new empty aggregator.
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(RwLock::new(HashMap::new())),
            prompts: Arc::new(RwLock::new(HashMap::new())),
            tool_collisions: Arc::new(RwLock::new(HashSet::new())),
            resource_collisions: Arc::new(RwLock::new(HashSet::new())),
            prompt_collisions: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Register tools from a server.
    pub fn register_tools(
        &self,
        server: &str,
        tools: impl IntoIterator<Item = ToolInfo>,
        transforms: &TransformPipeline,
    ) {
        let mut registry = self.tools.write();
        let mut collisions = self.tool_collisions.write();

        for tool in tools {
            let ToolInfo {
                name: original_name,
                description,
                input_schema,
                output_schema,
                annotations,
            } = tool;

            let base_name = transforms.exposed_tool_name(&original_name).into_owned();

            // Check for collision
            let has_existing_other = registry.get(&base_name).is_some_and(|m| m.server != server);

            let exposed_name = if has_existing_other {
                // Collision detected!
                collisions.insert(base_name.clone());

                // Rename the existing entry if it wasn't already prefixed
                if let Some(existing) = registry.remove(&base_name) {
                    let prefixed_existing =
                        ServerPrefixed::new(&existing.server, &existing.exposed_name).to_string();
                    registry.insert(
                        prefixed_existing.clone(),
                        ToolMapping {
                            exposed_name: prefixed_existing,
                            ..existing
                        },
                    );
                }

                // Use prefixed name for new entry
                ServerPrefixed::new(server, &base_name).to_string()
            } else if collisions.contains(&base_name) {
                // This name previously collided, so keep using a prefix.
                ServerPrefixed::new(server, &base_name).to_string()
            } else {
                // No collision, use original name
                base_name.clone()
            };

            if registry.contains_key(&exposed_name) {
                tracing::warn!(
                    server = %server,
                    tool = %exposed_name,
                    "duplicate tool name; skipping"
                );
                continue;
            }

            let mapping = ToolMapping {
                server: server.to_string(),
                original_name,
                exposed_name: exposed_name.clone(),
                description,
                input_schema,
                output_schema,
                annotations,
            };
            registry.insert(exposed_name, mapping);
        }
    }

    /// Register resources from a server.
    pub fn register_resources(
        &self,
        server: &str,
        resources: impl IntoIterator<Item = ResourceInfo>,
    ) {
        let mut registry = self.resources.write();
        let mut collisions = self.resource_collisions.write();

        for res in resources {
            let ResourceInfo {
                uri: original_uri,
                name,
                description,
                mime_type,
                size,
            } = res;

            // Helper: create stable URN when a URI collides across servers
            let collision_uri = |srv: &str| {
                let hash = hex::encode(Sha256::digest(original_uri.as_bytes()));
                format!("urn:unrelated-mcp-adapter:resource:{srv}:{hash}")
            };

            // Detect collision by original_uri (not by exposed key)
            let has_existing_other = registry
                .values()
                .any(|m| m.original_uri == original_uri && m.server != server);

            let exposed_uri = if collisions.contains(&original_uri) {
                collision_uri(server)
            } else if has_existing_other {
                // Collision detected!
                collisions.insert(original_uri.clone());

                // Rename the existing entry (it will currently be keyed by original_uri)
                if let Some(existing) = registry.remove(&original_uri) {
                    let existing_key = collision_uri(&existing.server);
                    registry.insert(
                        existing_key.clone(),
                        ResourceMapping {
                            exposed_uri: existing_key,
                            ..existing
                        },
                    );
                }

                collision_uri(server)
            } else {
                original_uri.clone()
            };

            registry.insert(
                exposed_uri.clone(),
                ResourceMapping {
                    server: server.to_string(),
                    original_uri,
                    exposed_uri,
                    name,
                    description,
                    mime_type,
                    size,
                },
            );
        }
    }

    /// Register prompts from a server.
    pub fn register_prompts(&self, server: &str, prompts: impl IntoIterator<Item = PromptInfo>) {
        let mut registry = self.prompts.write();
        let mut collisions = self.prompt_collisions.write();

        for prompt in prompts {
            let PromptInfo {
                name: original_name,
                description,
                arguments,
            } = prompt;

            // Check for collision
            let has_existing_other = registry
                .values()
                .any(|m| m.original_name == original_name && m.server != server);

            let exposed_name = if has_existing_other {
                // Collision detected!
                collisions.insert(original_name.clone());

                // Rename the existing entry if it wasn't already prefixed
                if let Some(existing) = registry.remove(&original_name) {
                    let prefixed_existing =
                        ServerPrefixed::new(&existing.server, &existing.original_name).to_string();
                    registry.insert(
                        prefixed_existing.clone(),
                        PromptMapping {
                            exposed_name: prefixed_existing,
                            ..existing
                        },
                    );
                }

                // Use prefixed name for new entry
                ServerPrefixed::new(server, &original_name).to_string()
            } else if collisions.contains(&original_name) {
                // This name previously collided, so keep using a prefix.
                ServerPrefixed::new(server, &original_name).to_string()
            } else {
                // No collision, use original name
                original_name.clone()
            };

            registry.insert(
                exposed_name.clone(),
                PromptMapping {
                    server: server.to_string(),
                    original_name,
                    exposed_name,
                    description,
                    arguments,
                },
            );
        }
    }

    /// Route a tool call to the correct server.
    /// Returns (`server_name`, `original_tool_name`) or None if not found.
    pub fn route_tool(&self, tool_name: &str) -> Option<(String, String)> {
        let registry = self.tools.read();

        // Direct lookup
        if let Some(mapping) = registry.get(tool_name) {
            return Some((mapping.server.clone(), mapping.original_name.clone()));
        }

        // Check if it's a prefixed name (server:tool)
        if let Some(prefixed) = ServerPrefixed::parse(tool_name)
            && let Some(mapping) = registry
                .values()
                .find(|m| m.server == prefixed.server && m.exposed_name == prefixed.name)
        {
            // Maybe it was registered without prefix but user is using prefix
            return Some((mapping.server.clone(), mapping.original_name.clone()));
        }

        None
    }

    /// Route a resource read to the correct server.
    /// Returns (`server_name`, `original_uri`) or None if not found.
    pub fn route_resource(&self, uri: &str) -> Option<(String, String)> {
        let registry = self.resources.read();
        registry
            .get(uri)
            .map(|m| (m.server.clone(), m.original_uri.clone()))
    }

    /// Route a prompt get to the correct server.
    /// Returns (`server_name`, `original_prompt_name`) or None if not found.
    pub fn route_prompt(&self, prompt_name: &str) -> Option<(String, String)> {
        let registry = self.prompts.read();

        // Direct lookup
        if let Some(mapping) = registry.get(prompt_name) {
            return Some((mapping.server.clone(), mapping.original_name.clone()));
        }

        // Check if it's a prefixed name (server:prompt)
        if let Some(prefixed) = ServerPrefixed::parse(prompt_name)
            && let Some(mapping) = registry
                .values()
                .find(|m| m.server == prefixed.server && m.original_name == prefixed.name)
        {
            return Some((mapping.server.clone(), mapping.original_name.clone()));
        }

        None
    }

    /// Get all tool mappings for the /map endpoint.
    pub fn get_all_tools(&self) -> RwLockReadGuard<'_, HashMap<String, ToolMapping>> {
        self.tools.read()
    }

    /// Get all resource mappings for the /map endpoint.
    pub fn get_all_resources(&self) -> RwLockReadGuard<'_, HashMap<String, ResourceMapping>> {
        self.resources.read()
    }

    /// Resolve the *exposed* resource URI (as seen by Adapter clients) given a backend server name
    /// and that backend's original resource URI.
    ///
    /// This is used to rewrite `notifications/resources/updated` so clients receive URNs when
    /// collisions occur.
    pub fn exposed_resource_uri_for(&self, server: &str, original_uri: &str) -> Option<String> {
        let registry = self.resources.read();
        registry
            .values()
            .find(|m| m.server == server && m.original_uri == original_uri)
            .map(|m| m.exposed_uri.clone())
    }

    /// Get all prompt mappings for the /map endpoint.
    pub fn get_all_prompts(&self) -> RwLockReadGuard<'_, HashMap<String, PromptMapping>> {
        self.prompts.read()
    }

    /// Overwrite this aggregator's registries with another aggregator's state.
    ///
    /// Used to refresh the exposed tool/resource/prompt maps after backend restarts.
    pub fn overwrite_from(&self, other: &Aggregator) {
        self.tools.write().clone_from(&other.tools.read());
        self.resources.write().clone_from(&other.resources.read());
        self.prompts.write().clone_from(&other.prompts.read());
        self.tool_collisions
            .write()
            .clone_from(&other.tool_collisions.read());
        self.resource_collisions
            .write()
            .clone_from(&other.resource_collisions.read());
        self.prompt_collisions
            .write()
            .clone_from(&other.prompt_collisions.read());
    }
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use unrelated_tool_transforms::TransformPipeline;

    #[test]
    fn server_prefixed_roundtrip() {
        let key = ServerPrefixed::new("server", "tool");
        assert_eq!(key.to_string(), "server:tool");

        let parsed = ServerPrefixed::parse("server:tool").expect("parse server:tool");
        assert_eq!(parsed.server, "server");
        assert_eq!(parsed.name, "tool");
    }

    #[test]
    fn server_prefixed_parses_last_colon() {
        let parsed = ServerPrefixed::parse("a:b:c").expect("parse a:b:c");
        assert_eq!(parsed.server, "a:b");
        assert_eq!(parsed.name, "c");
    }

    #[test]
    fn server_prefixed_rejects_empty_parts() {
        assert!(ServerPrefixed::parse(":tool").is_none());
        assert!(ServerPrefixed::parse("server:").is_none());
        assert!(ServerPrefixed::parse(":").is_none());
    }

    #[test]
    fn test_no_collision() {
        let agg = Aggregator::new();
        let transforms = TransformPipeline::default();

        agg.register_tools(
            "server1",
            vec![ToolInfo {
                name: "tool_a".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );
        agg.register_tools(
            "server2",
            vec![ToolInfo {
                name: "tool_b".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );

        let tools = agg.get_all_tools();
        assert!(tools.contains_key("tool_a"));
        assert!(tools.contains_key("tool_b"));
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_collision_prefixing() {
        let agg = Aggregator::new();
        let transforms = TransformPipeline::default();

        agg.register_tools(
            "server1",
            vec![ToolInfo {
                name: "search".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );
        agg.register_tools(
            "server2",
            vec![ToolInfo {
                name: "search".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );

        let tools = agg.get_all_tools();
        assert!(tools.contains_key("server1:search"));
        assert!(tools.contains_key("server2:search"));
        assert!(!tools.contains_key("search"));
    }

    #[test]
    fn test_route_tool() {
        let agg = Aggregator::new();
        let transforms = TransformPipeline::default();

        agg.register_tools(
            "filesystem",
            vec![ToolInfo {
                name: "read_file".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );

        let result = agg.route_tool("read_file");
        assert_eq!(result, Some(("filesystem".into(), "read_file".into())));

        let result = agg.route_tool("nonexistent");
        assert_eq!(result, None);
    }

    #[test]
    fn tool_rename_changes_exposed_name_and_routes_to_original() {
        let agg = Aggregator::new();
        let transforms = TransformPipeline {
            tool_overrides: HashMap::from([(
                "tool_a".to_string(),
                unrelated_tool_transforms::ToolOverride {
                    rename: Some("renamed".to_string()),
                    ..Default::default()
                },
            )]),
        };

        agg.register_tools(
            "server1",
            vec![ToolInfo {
                name: "tool_a".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );

        assert!(agg.get_all_tools().contains_key("renamed"));
        assert_eq!(
            agg.route_tool("renamed"),
            Some(("server1".into(), "tool_a".into()))
        );

        // Allow optional prefix even when there is no collision.
        assert_eq!(
            agg.route_tool("server1:renamed"),
            Some(("server1".into(), "tool_a".into()))
        );
    }

    #[test]
    fn tool_rename_participates_in_collision_detection() {
        let agg = Aggregator::new();
        let transforms = TransformPipeline {
            tool_overrides: HashMap::from([(
                "tool_a".to_string(),
                unrelated_tool_transforms::ToolOverride {
                    rename: Some("search".to_string()),
                    ..Default::default()
                },
            )]),
        };

        agg.register_tools(
            "server1",
            vec![ToolInfo {
                name: "tool_a".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );
        agg.register_tools(
            "server2",
            vec![ToolInfo {
                name: "search".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                annotations: None,
            }],
            &transforms,
        );

        let tools = agg.get_all_tools();
        assert!(tools.contains_key("server1:search"));
        assert!(tools.contains_key("server2:search"));
        assert!(!tools.contains_key("search"));

        assert_eq!(
            agg.route_tool("server1:search"),
            Some(("server1".into(), "tool_a".into()))
        );
        assert_eq!(
            agg.route_tool("server2:search"),
            Some(("server2".into(), "search".into()))
        );
    }
}
