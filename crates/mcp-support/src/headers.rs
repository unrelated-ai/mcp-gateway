//! Standard MCP routing headers. Always derive headers after request transforms.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderName, HeaderValue};
use rmcp::transport::common::http_header::{
    BASE64_HEADER_PREFIX, BASE64_HEADER_SUFFIX, HEADER_MCP_METHOD, HEADER_MCP_NAME,
    HEADER_MCP_PARAM_PREFIX,
};
use serde_json::Value;
use std::collections::HashSet;

pub const VERSION: &str = "2026-07-28";
pub const VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
pub const CLIENT_INFO_META: &str = "io.modelcontextprotocol/clientInfo";
pub const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// Headers derived from the request body, never forwarded from caller input.
#[must_use]
pub fn is_routing_header(name: &HeaderName) -> bool {
    name == HEADER_MCP_METHOD || name == HEADER_MCP_NAME || is_parameter_header(name)
}

fn is_parameter_header(name: &HeaderName) -> bool {
    name.as_str()
        .get(..HEADER_MCP_PARAM_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(HEADER_MCP_PARAM_PREFIX))
}

fn encode(value: &str) -> String {
    if !value.is_ascii()
        || value.bytes().any(|b| b < 0x20 || b == 0x7f)
        || value.trim() != value
        || (value.starts_with(BASE64_HEADER_PREFIX) && value.ends_with(BASE64_HEADER_SUFFIX))
    {
        format!(
            "{BASE64_HEADER_PREFIX}{}{BASE64_HEADER_SUFFIX}",
            STANDARD.encode(value)
        )
    } else {
        value.to_owned()
    }
}

fn decode(value: &str) -> Option<String> {
    if let Some(encoded) = value
        .strip_prefix(BASE64_HEADER_PREFIX)
        .and_then(|s| s.strip_suffix(BASE64_HEADER_SUFFIX))
    {
        String::from_utf8(STANDARD.decode(encoded).ok()?).ok()
    } else {
        Some(value.to_owned())
    }
}

fn insert(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), String> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid MCP header name")?;
    let value = HeaderValue::from_str(&encode(value)).map_err(|_| "invalid MCP header value")?;
    headers.insert(name, value);
    Ok(())
}

/// An annotation plus its exact path through nested object properties.
#[derive(Debug)]
struct Annotation {
    header: String,
    path: Vec<String>,
    kind: String,
}

fn annotations(schema: &Value) -> Result<Vec<Annotation>, String> {
    let mut out = Vec::new();
    collect_annotations(schema, &[], true, &mut HashSet::new(), &mut out)?;
    Ok(out)
}

fn collect_annotations(
    schema: &Value,
    path: &[String],
    reachable: bool,
    seen: &mut HashSet<String>,
    out: &mut Vec<Annotation>,
) -> Result<(), String> {
    if let Some(header) = schema.get("x-mcp-header") {
        let header = header.as_str().ok_or("x-mcp-header must be a string")?;
        let kind = schema.get("type").and_then(Value::as_str).unwrap_or("");
        if !reachable
            || path.is_empty()
            || header.is_empty()
            || HeaderName::from_bytes(header.as_bytes()).is_err()
            || !matches!(kind, "string" | "integer" | "boolean")
            || !seen.insert(header.to_ascii_lowercase())
        {
            return Err("invalid or duplicate x-mcp-header annotation".into());
        }
        out.push(Annotation {
            header: format!("{HEADER_MCP_PARAM_PREFIX}{header}"),
            path: path.to_vec(),
            kind: kind.into(),
        });
    }
    if let Some(object) = schema.as_object() {
        for (key, child) in object {
            if key == "properties" {
                if let Some(properties) = child.as_object() {
                    for (name, property) in properties {
                        let mut path = path.to_vec();
                        path.push(name.clone());
                        collect_annotations(property, &path, reachable, seen, out)?;
                    }
                }
            } else if key != "x-mcp-header" {
                // Any annotation behind composition, arrays or references is invalid.
                visit_unreachable(child, path, seen, out)?;
            }
        }
    }
    Ok(())
}

fn visit_unreachable(
    value: &Value,
    path: &[String],
    seen: &mut HashSet<String>,
    out: &mut Vec<Annotation>,
) -> Result<(), String> {
    if let Some(array) = value.as_array() {
        for value in array {
            visit_unreachable(value, path, seen, out)?;
        }
    } else if value.is_object() {
        collect_annotations(value, path, false, seen, out)?;
    }
    Ok(())
}

/// Validate a tool's routing annotations before advertising it over HTTP.
///
/// # Errors
/// Returns an error for invalid locations, types, names, or duplicate headers.
pub fn validate_tool_schema(schema: &Value) -> Result<(), String> {
    annotations(schema).map(|_| ())
}

/// Build method/name and promoted argument headers from a transformed request.
///
/// # Errors
/// Rejects malformed annotations or arguments that cannot be represented safely.
pub fn request_headers(request: &Value, schema: Option<&Value>) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    let method = request["method"].as_str().ok_or("missing method")?;
    insert(&mut headers, HEADER_MCP_METHOD, method)?;
    let key = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
        _ => None,
    };
    if let Some(key) = key {
        let name = request["params"][key]
            .as_str()
            .ok_or("missing request name")?;
        insert(&mut headers, HEADER_MCP_NAME, name)?;
    }
    if method == "tools/call"
        && let Some(schema) = schema
    {
        for annotation in annotations(schema)? {
            let mut value = &request["params"]["arguments"];
            for part in &annotation.path {
                value = &value[part];
            }
            if value.is_null() {
                continue;
            }
            let text = match annotation.kind.as_str() {
                "string" => value.as_str().map(str::to_owned),
                "boolean" => value.as_bool().map(|v| v.to_string()),
                "integer" => value
                    .as_i64()
                    .filter(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
                    .map(|v| v.to_string()),
                _ => None,
            }
            .ok_or("promoted argument has an invalid type or unsafe integer value")?;
            insert(&mut headers, &annotation.header, &text)?;
        }
    }
    Ok(headers)
}

/// Check the body is the source of truth, rejecting duplicate or forged mirrors.
///
/// # Errors
/// Returns a header mismatch explanation suitable for a protocol error.
pub fn validate_request_headers(
    headers: &HeaderMap,
    request: &Value,
    schema: Option<&Value>,
) -> Result<(), String> {
    let expected = request_headers(request, schema)?;
    for (name, value) in &expected {
        let mut supplied = headers.get_all(name).iter();
        let actual = supplied
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(decode);
        if supplied.next().is_some() || actual != value.to_str().ok().and_then(decode) {
            return Err(format!("missing or mismatched {name} header"));
        }
    }
    for name in headers.keys() {
        if (is_parameter_header(name) && schema.is_some() || name == HEADER_MCP_NAME)
            && !expected.contains_key(name)
        {
            return Err(format!("unexpected {name} header"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_parameters_unicode_and_sentinels_roundtrip() {
        let schema = json!({"type":"object","properties":{"scope":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"region"}}}}});
        let request = json!({"method":"tools/call","params":{"name":"tool 🛠","arguments":{"scope":{"region":"=?base64?literal?="}}}});
        let mut headers = request_headers(&request, Some(&schema)).unwrap();
        validate_request_headers(&headers, &request, Some(&schema)).unwrap();
        headers.insert("mcp-param-region", HeaderValue::from_static("forged"));
        assert!(validate_request_headers(&headers, &request, Some(&schema)).is_err());
    }

    #[test]
    fn rejects_unsafe_annotations_and_duplicate_headers() {
        for schema in [
            json!({"properties":{"x":{"type":"number","x-mcp-header":"x"}}}),
            json!({"items":{"type":"string","x-mcp-header":"x"}}),
            json!({"properties":{"x":{"type":"string","x-mcp-header":"x"},"y":{"type":"string","x-mcp-header":"X"}}}),
        ] {
            assert!(validate_tool_schema(&schema).is_err());
        }
        let request = json!({"method":"ping"});
        let mut headers = request_headers(&request, None).unwrap();
        headers.append("mcp-method", HeaderValue::from_static("ping"));
        assert!(validate_request_headers(&headers, &request, None).is_err());
    }
}
