//! Error types for the MCP adapter.

use thiserror::Error;

/// Main error type for the adapter.
#[derive(Error, Debug)]
pub enum AdapterError {
    /// Configuration errors (invalid JSON/YAML, missing fields, conflicts)
    #[error("Configuration error: {0}")]
    Config(String),

    /// Startup errors (server failed to start)
    #[error("Startup error: {0}")]
    Startup(String),

    /// Runtime errors (server crashed, unavailable)
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// HTTP errors (failed API calls)
    #[error("HTTP error: {0}")]
    Http(String),

    /// `OpenAPI` errors (spec parsing, validation)
    #[error("OpenAPI error: {0}")]
    OpenApi(String),

    /// Parameter collision errors
    #[error("Parameter collision: {0}")]
    ParamCollision(String),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML parsing errors
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_saphyr::DeserializeError),
}

/// Result type alias for adapter operations.
pub type Result<T> = std::result::Result<T, AdapterError>;
