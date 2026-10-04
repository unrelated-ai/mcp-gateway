//! Error types for `unrelated-openapi-tools`.

use thiserror::Error;

/// Main error type for `OpenAPI` tooling.
#[derive(Error, Debug)]
pub enum OpenApiToolsError {
    /// Configuration errors (invalid config, missing fields, conflicts).
    #[error("Configuration error: {0}")]
    Config(String),

    /// Startup errors (spec failed to load, tool discovery failed).
    #[error("Startup error: {0}")]
    Startup(String),

    /// Runtime errors (tool call failed, invalid arguments).
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// HTTP errors (failed API calls).
    #[error("HTTP error: {0}")]
    Http(String),

    /// `OpenAPI` errors (spec parsing, validation).
    #[error("OpenAPI error: {0}")]
    OpenApi(String),

    #[error("OpenAPI error: failed to fetch spec from '{url}': {message}")]
    OpenApiSpecFetch { url: String, message: String },

    #[error("OpenAPI error: failed to read spec body from '{url}': {message}")]
    OpenApiSpecReadBody { url: String, message: String },

    #[error("OpenAPI error: failed to read spec file '{path}': {source}")]
    OpenApiSpecReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("OpenAPI error: failed to parse OpenAPI spec from '{location}': {source}")]
    OpenApiSpecParse {
        location: String,
        #[source]
        source: Box<serde_saphyr::DeserializeError>,
    },

    /// Parameter collision errors.
    #[error("Parameter collision: {0}")]
    ParamCollision(String),

    /// IO errors.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing errors.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML parsing errors.
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_saphyr::DeserializeError),

    /// HTTP client errors.
    #[error("Request error: {0}")]
    Request(String),
}

/// Result type alias for `OpenAPI` tooling operations.
pub type Result<T> = std::result::Result<T, OpenApiToolsError>;
