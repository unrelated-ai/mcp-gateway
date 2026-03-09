//! `OpenAPI` `$ref` resolver.
//!
//! The `openapiv3` crate models `$ref`s using `ReferenceOr<T>` but does not automatically resolve them.
//! Real-world `OpenAPI` specs frequently rely on external references split across files (or URLs).
//!
//! This resolver supports:
//! - Local refs (`#/...`)
//! - File refs (`./common.yaml#/...`, `/abs/path/spec.yaml#/...`, `file:///...#/...`)
//! - URL refs (`https://example.com/common.yaml#/...`)
//!
//! Key detail: `$ref` resolution is **relative to the document that contains the `$ref`**.
//! To ensure correctness across nested references, callers pass the current document id (`DocId`)
//! when resolving.

use crate::error::{OpenApiToolsError, Result};
use openapiv3::{OpenAPI, Parameter, PathItem, ReferenceOr, RequestBody, Response, Schema};
use parking_lot::RwLock;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use unrelated_http_tools::safety::{OutboundHttpSafety, sanitize_reqwest_error};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DocId {
    Url(Url),
    File(PathBuf),
}

impl DocId {
    /// Parse a root spec location into a document identifier (URL or file path).
    ///
    /// # Errors
    ///
    /// Returns an error if the location is an invalid URL or invalid file URL.
    pub fn parse(spec_location: &str) -> Result<Self> {
        if spec_location.starts_with("http://") || spec_location.starts_with("https://") {
            let url = Url::parse(spec_location).map_err(|e| {
                OpenApiToolsError::OpenApi(format!(
                    "Invalid OpenAPI spec URL '{spec_location}': {e}",
                ))
            })?;
            Ok(DocId::Url(strip_fragment(url)))
        } else if spec_location.starts_with("file://") {
            let url = Url::parse(spec_location).map_err(|e| {
                OpenApiToolsError::OpenApi(format!(
                    "Invalid OpenAPI spec file URL '{spec_location}': {e}",
                ))
            })?;
            let path = url.to_file_path().map_err(|()| {
                OpenApiToolsError::OpenApi(format!(
                    "Invalid file URL (cannot convert to path): {spec_location}",
                ))
            })?;
            Ok(DocId::File(canonicalize_best_effort(path)))
        } else {
            Ok(DocId::File(canonicalize_best_effort(PathBuf::from(
                spec_location,
            ))))
        }
    }

    fn display(&self) -> String {
        match self {
            DocId::Url(u) => u.to_string(),
            DocId::File(p) => p.display().to_string(),
        }
    }
}

fn strip_fragment(mut url: Url) -> Url {
    url.set_fragment(None);
    url
}

fn canonicalize_best_effort(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

#[derive(Debug)]
pub struct OpenApiResolver<'a> {
    root_doc: DocId,
    client: &'a Client,
    safety: &'a OutboundHttpSafety,
    docs: RwLock<HashMap<DocId, Arc<Value>>>,
}

impl<'a> OpenApiResolver<'a> {
    /// Create a new resolver for a root `OpenAPI` document.
    ///
    /// # Errors
    ///
    /// Returns an error if the root spec cannot be converted into JSON for caching.
    pub fn new(
        root_doc: DocId,
        spec: &OpenAPI,
        client: &'a Client,
        safety: &'a OutboundHttpSafety,
    ) -> Result<Self> {
        let root_value =
            serde_json::to_value(spec).map_err(|e| OpenApiToolsError::OpenApi(e.to_string()))?;
        let mut docs = HashMap::new();
        docs.insert(root_doc.clone(), Arc::new(root_value));
        Ok(Self {
            root_doc,
            client,
            safety,
            docs: RwLock::new(docs),
        })
    }

    #[must_use]
    pub fn root_doc(&self) -> &DocId {
        &self.root_doc
    }

    /// Resolve a `$ref` for a parameter.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference cannot be resolved, or if the referenced document
    /// cannot be loaded/parsed.
    pub async fn resolve_parameter(
        &self,
        current_doc: &DocId,
        param: &ReferenceOr<Parameter>,
    ) -> Result<(DocId, Parameter)> {
        self.resolve_reference_or(current_doc, param).await
    }

    /// Resolve a `$ref` for a request body.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference cannot be resolved, or if the referenced document
    /// cannot be loaded/parsed.
    pub async fn resolve_request_body(
        &self,
        current_doc: &DocId,
        body: &ReferenceOr<RequestBody>,
    ) -> Result<(DocId, RequestBody)> {
        self.resolve_reference_or(current_doc, body).await
    }

    /// Resolve a `$ref` for a schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference cannot be resolved, or if the referenced document
    /// cannot be loaded/parsed.
    pub async fn resolve_schema(
        &self,
        current_doc: &DocId,
        schema: &ReferenceOr<Schema>,
    ) -> Result<(DocId, Schema)> {
        self.resolve_reference_or(current_doc, schema).await
    }

    /// Resolve a `$ref` for a response.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference cannot be resolved, or if the referenced document
    /// cannot be loaded/parsed.
    pub async fn resolve_response(
        &self,
        current_doc: &DocId,
        response: &ReferenceOr<Response>,
    ) -> Result<(DocId, Response)> {
        self.resolve_reference_or(current_doc, response).await
    }

    /// Resolve a `$ref` for a path item.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference cannot be resolved, or if the referenced document
    /// cannot be loaded/parsed.
    pub async fn resolve_path_item(
        &self,
        current_doc: &DocId,
        item: &ReferenceOr<PathItem>,
    ) -> Result<(DocId, PathItem)> {
        self.resolve_reference_or(current_doc, item).await
    }

    async fn resolve_reference_or<T>(
        &self,
        current_doc: &DocId,
        r: &ReferenceOr<T>,
    ) -> Result<(DocId, T)>
    where
        T: Clone + DeserializeOwned,
    {
        let mut seen: HashSet<String> = HashSet::new();
        let mut doc = current_doc.clone();
        let mut cur: ReferenceOr<T> = r.clone();

        loop {
            match cur {
                ReferenceOr::Item(item) => return Ok((doc, item)),
                ReferenceOr::Reference { reference } => {
                    let key = Self::canonical_ref_key(&doc, &reference)?;
                    if !seen.insert(key) {
                        return Err(OpenApiToolsError::OpenApi(format!(
                            "Cyclic $ref detected while resolving: {reference}",
                        )));
                    }

                    let (target_doc, value) = self.resolve_ref_value(&doc, &reference).await?;
                    let next: ReferenceOr<T> = serde_json::from_value(value).map_err(|e| {
                        OpenApiToolsError::OpenApi(format!(
                            "Failed to deserialize referenced value '{}' (doc {}) as expected type: {}",
                            reference,
                            target_doc.display(),
                            e
                        ))
                    })?;

                    doc = target_doc;
                    cur = next;
                }
            }
        }
    }

    async fn resolve_ref_value(
        &self,
        current_doc: &DocId,
        reference: &str,
    ) -> Result<(DocId, Value)> {
        let (target_doc, pointer) = Self::parse_ref(current_doc, reference)?;
        let doc_value = self.load_doc(&target_doc).await?;

        let selected = if let Some(ptr) = pointer {
            doc_value.pointer(&ptr).cloned().ok_or_else(|| {
                OpenApiToolsError::OpenApi(format!(
                    "Unresolved $ref '{}' (doc {}, missing pointer '{}')",
                    reference,
                    target_doc.display(),
                    ptr
                ))
            })?
        } else {
            (*doc_value).clone()
        };

        Ok((target_doc, selected))
    }

    fn parse_ref(current_doc: &DocId, reference: &str) -> Result<(DocId, Option<String>)> {
        if let Some(frag) = reference.strip_prefix('#') {
            let ptr = if frag.is_empty() {
                None
            } else if frag.starts_with('/') {
                Some(frag.to_string())
            } else {
                return Err(OpenApiToolsError::OpenApi(format!(
                    "Unsupported $ref fragment (expected JSON pointer starting with '/'): {reference}",
                )));
            };
            return Ok((current_doc.clone(), ptr));
        }

        let (doc_part, frag_part) = match reference.split_once('#') {
            Some((d, f)) => (d, Some(f)),
            None => (reference, None),
        };

        let target_doc = Self::resolve_doc(current_doc, doc_part)?;

        let ptr = match frag_part {
            Some("") | None => None,
            Some(frag) if frag.starts_with('/') => Some(frag.to_string()),
            Some(_) => {
                return Err(OpenApiToolsError::OpenApi(format!(
                    "Unsupported $ref fragment (expected JSON pointer starting with '/'): {reference}",
                )));
            }
        };

        Ok((target_doc, ptr))
    }

    fn resolve_doc(current_doc: &DocId, doc_part: &str) -> Result<DocId> {
        if doc_part.is_empty() {
            return Ok(current_doc.clone());
        }

        // Absolute URL refs.
        if doc_part.starts_with("http://") || doc_part.starts_with("https://") {
            let url = Url::parse(doc_part).map_err(|e| {
                OpenApiToolsError::OpenApi(format!("Bad $ref URL '{doc_part}': {e}"))
            })?;
            return Ok(DocId::Url(strip_fragment(url)));
        }

        // file:// URL refs.
        if doc_part.starts_with("file://") {
            let url = Url::parse(doc_part).map_err(|e| {
                OpenApiToolsError::OpenApi(format!("Bad $ref file URL '{doc_part}': {e}"))
            })?;
            let path = url.to_file_path().map_err(|()| {
                OpenApiToolsError::OpenApi(format!("Bad $ref file URL (not a path): {doc_part}"))
            })?;
            return Ok(DocId::File(canonicalize_best_effort(path)));
        }

        match current_doc {
            DocId::Url(base) => {
                let joined = base.join(doc_part).map_err(|e| {
                    OpenApiToolsError::OpenApi(format!(
                        "Failed to resolve relative $ref '{doc_part}' against base {base}: {e}",
                    ))
                })?;
                Ok(DocId::Url(strip_fragment(joined)))
            }
            DocId::File(base) => {
                // Absolute paths should remain absolute.
                let resolved = if Path::new(doc_part).is_absolute() {
                    PathBuf::from(doc_part)
                } else {
                    base.parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(doc_part)
                };
                Ok(DocId::File(canonicalize_best_effort(resolved)))
            }
        }
    }

    fn canonical_ref_key(current_doc: &DocId, reference: &str) -> Result<String> {
        let (target_doc, pointer) = Self::parse_ref(current_doc, reference)?;
        let mut key = match &target_doc {
            DocId::Url(u) => format!("url:{u}"),
            DocId::File(p) => format!("file:{}", p.display()),
        };
        if let Some(ptr) = pointer {
            key.push('#');
            key.push_str(&ptr);
        }
        Ok(key)
    }

    async fn load_doc(&self, doc: &DocId) -> Result<Arc<Value>> {
        // Fast path: cache hit.
        if let Some(v) = self.docs.read().get(doc).cloned() {
            return Ok(v);
        }

        // Cache miss: load.
        let content = match doc {
            DocId::File(path) => std::fs::read_to_string(path).map_err(|e| {
                OpenApiToolsError::OpenApi(format!(
                    "Failed to read referenced file {}: {e}",
                    path.display(),
                ))
            })?,
            DocId::Url(url) => {
                self.safety
                    .check_url(url)
                    .await
                    .map_err(|e| OpenApiToolsError::Http(format!("Referenced URL blocked: {e}")))?;
                self.client
                    .get(url.clone())
                    .send()
                    .await
                    .map_err(|e| {
                        OpenApiToolsError::OpenApi(format!(
                            "Failed to fetch referenced URL {url}: {}",
                            sanitize_reqwest_error(&e)
                        ))
                    })?
                    .text()
                    .await
                    .map_err(|e| {
                        OpenApiToolsError::OpenApi(format!(
                            "Failed to read referenced URL body: {}",
                            sanitize_reqwest_error(&e)
                        ))
                    })?
            }
        };

        let parsed: Value = serde_json::from_str(&content)
            .or_else(|_| serde_yaml::from_str(&content))
            .map_err(|e| {
                OpenApiToolsError::OpenApi(format!(
                    "Failed to parse referenced document {}: {e}",
                    doc.display(),
                ))
            })?;

        let parsed = Arc::new(parsed);
        self.docs.write().insert(doc.clone(), Arc::clone(&parsed));
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unrelated_http_tools::safety::OutboundHttpSafety;

    #[tokio::test]
    async fn blocks_external_ref_urls_under_restrictive_safety_policy() {
        let spec_yaml = r#"
openapi: "3.0.0"
info:
  title: t
  version: "1"
paths:
  /pet:
    $ref: "http://127.0.0.1:8080/openapi.yaml#/paths/~1pet"
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).expect("parse spec");
        let root_doc = DocId::parse("inline-root.yaml").expect("root doc id");
        let client = Client::new();
        let safety = OutboundHttpSafety::gateway_default();
        let resolver = OpenApiResolver::new(root_doc, &spec, &client, &safety).expect("resolver");

        let path_ref = spec.paths.paths.get("/pet").expect("path ref");

        let err = resolver
            .resolve_path_item(resolver.root_doc(), path_ref)
            .await
            .expect_err("expected external ref URL to be blocked");
        assert!(
            err.to_string().contains("Referenced URL blocked"),
            "err={err}",
        );
    }
}
