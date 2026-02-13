//! Backend trait for unified server management.
//!
//! This module defines the common interface for both stdio MCP servers
//! and OpenAPI-based API servers.

use crate::error::AdapterError;
use crate::error::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rmcp::model::{
    CallToolResult, CompleteRequestParams, CompleteResult, GetPromptResult, PromptArgument,
    ReadResourceResult, ToolAnnotations,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::time::Duration;

pub type JsonObject = serde_json::Map<String, Value>;

/// Type of backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    /// Stdio-based MCP server (child process)
    Stdio,
    /// `OpenAPI`-based HTTP API
    OpenApi,
    /// Manually configured HTTP backend (no `OpenAPI`)
    Http,
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendType::Stdio => write!(f, "stdio"),
            BackendType::OpenApi => write!(f, "openapi"),
            BackendType::Http => write!(f, "http"),
        }
    }
}

/// State of a backend server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendState {
    /// Server is starting up
    Starting,
    /// Server is running and ready
    Running,
    /// Server has crashed or been stopped
    Dead,
}

impl fmt::Display for BackendState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendState::Starting => write!(f, "starting"),
            BackendState::Running => write!(f, "running"),
            BackendState::Dead => write!(f, "dead"),
        }
    }
}

/// Information about a tool provided by a backend.
#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    /// Tool name (exposed name, may include prefix)
    pub name: String,
    /// Original tool name (without prefix)
    pub original_name: String,
    /// Tool description
    pub description: Option<String>,
    /// JSON Schema for input parameters
    pub input_schema: Value,
    /// Optional JSON Schema for tool output.
    ///
    /// MCP requires the root output schema to be an object. When present, this should already be
    /// a valid JSON Schema object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Optional MCP tool annotations (hints for clients/LLMs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

/// Information about a resource provided by a backend.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceInfo {
    /// Resource URI
    pub uri: String,
    /// Resource name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Optional MIME type
    pub mime_type: Option<String>,
    /// Optional size (bytes)
    pub size: Option<u32>,
}

/// Information about a prompt provided by a backend.
#[derive(Debug, Clone, Serialize)]
pub struct PromptInfo {
    /// Prompt name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Optional argument definitions (mirrors the MCP prompt model; omitted when absent).
    pub arguments: Option<Vec<PromptArgument>>,
}

/// Status information for a backend.
#[derive(Debug, Clone, Serialize)]
pub struct BackendStatus {
    /// Backend name
    pub name: String,
    /// Backend type
    pub backend_type: BackendType,
    /// Current state
    pub state: BackendState,
    /// Number of tools provided
    pub tool_count: usize,
    /// Additional info (e.g., spec URL for `OpenAPI`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_url: Option<String>,
    /// Restart count (for stdio backends)
    pub restart_count: u32,
    /// Timestamp of last successful start/restart (for stdio backends)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_restart: Option<DateTime<Utc>>,
}

/// Common interface for all backend types.
///
/// Both stdio MCP servers and `OpenAPI` backends implement this trait,
/// allowing the aggregator to manage them uniformly.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Get the backend's name.
    fn name(&self) -> &str;

    /// Get the backend type.
    fn backend_type(&self) -> BackendType;

    /// Get the current state.
    fn state(&self) -> BackendState;

    /// Get status information.
    fn status(&self) -> BackendStatus;

    /// List all tools provided by this backend.
    async fn list_tools(&self) -> Result<Vec<ToolInfo>>;

    /// Execute a tool call.
    ///
    /// # Arguments
    /// * `session_id` - MCP session id (if available). Backends may use this to implement
    ///   per-session process lifecycles or other session-scoped behavior.
    /// * `name` - The tool name (original name, without server prefix)
    /// * `arguments` - Tool arguments as JSON
    ///
    /// # Returns
    /// The tool result, or an error.
    async fn call_tool(
        &self,
        session_id: Option<&str>,
        name: &str,
        arguments: Value,
        timeout: Option<Duration>,
    ) -> Result<CallToolResult>;

    /// List all resources provided by this backend.
    async fn list_resources(&self) -> Result<Vec<ResourceInfo>>;

    /// Read a resource by URI.
    async fn read_resource(
        &self,
        session_id: Option<&str>,
        uri: &str,
    ) -> Result<ReadResourceResult>;

    /// List all prompts provided by this backend.
    async fn list_prompts(&self) -> Result<Vec<PromptInfo>>;

    /// Get a prompt by name.
    async fn get_prompt(
        &self,
        session_id: Option<&str>,
        name: &str,
        arguments: Option<JsonObject>,
    ) -> Result<GetPromptResult>;

    /// Subscribe to updates for a resource (`resources/subscribe`).
    async fn subscribe(&self, _session_id: Option<&str>, _uri: &str) -> Result<()> {
        Err(AdapterError::Runtime(
            "resources/subscribe is not supported by this backend".to_string(),
        ))
    }

    /// Unsubscribe from updates for a resource (`resources/unsubscribe`).
    async fn unsubscribe(&self, _session_id: Option<&str>, _uri: &str) -> Result<()> {
        Err(AdapterError::Runtime(
            "resources/unsubscribe is not supported by this backend".to_string(),
        ))
    }

    /// Completion suggestions for a prompt or resource argument (`completion/complete`).
    ///
    /// Backends that don't support completions can return an empty completion result.
    async fn complete(
        &self,
        _session_id: Option<&str>,
        _request: CompleteRequestParams,
    ) -> Result<CompleteResult> {
        Ok(CompleteResult::default())
    }

    /// Start the backend.
    ///
    /// For stdio backends, this spawns the child process.
    /// For `OpenAPI` backends, this validates the spec and prepares tools.
    async fn start(&self) -> Result<()>;

    /// Shutdown the backend gracefully.
    async fn shutdown(&self);

    /// Best-effort hook to release any resources tied to a specific MCP session.
    ///
    /// This is used by the streamable HTTP session manager to clean up per-session stdio
    /// processes when a client session is closed.
    async fn shutdown_session(&self, _session_id: &str) {}
}
