//! Response shaping utilities (config-driven).
//!
//! This module provides a small transform pipeline that can:
//! - shape JSON-ish tool outputs at runtime (to reduce tokens / redact / normalize)
//! - shape output schemas at build time (so advertised schemas match the shaped outputs)
//!
//! The pipeline is intentionally conservative and best-effort: when a schema rewrite cannot be
//! applied safely, we return warnings and widen where possible (instead of failing).

use crate::config::{ResponseTransform, ResponseTransformChainConfig, TransformChainMode};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
enum CompiledTransform {
    DropNulls,
    PickTopLevelFields {
        fields: HashSet<String>,
    },
    RedactKeys {
        keys: HashSet<String>,
        replacement: String,
    },
    TruncateStrings {
        max_chars: usize,
    },
    LimitArrays {
        max_items: usize,
    },
}

/// A compiled response shaping pipeline.
///
/// This is safe to share across tasks (immutable after construction).
#[derive(Debug, Clone, Default)]
pub struct CompiledResponsePipeline {
    steps: Vec<CompiledTransform>,
}

/// Apply a tool-level chain on top of a base pipeline, producing an owned list of transforms.
///
/// - If `chain` is absent, returns `base.to_vec()`.
/// - If `mode=replace`, returns the chain pipeline only.
/// - If `mode=append`, returns `base + chain`.
#[must_use]
pub fn apply_chain(
    base: &[ResponseTransform],
    chain: Option<&ResponseTransformChainConfig>,
) -> Vec<ResponseTransform> {
    let Some(chain) = chain else {
        return base.to_vec();
    };
    let (mode, pipeline) = chain.mode_and_pipeline();
    match mode {
        TransformChainMode::Replace => pipeline.to_vec(),
        TransformChainMode::Append => {
            let mut out = base.to_vec();
            out.extend_from_slice(pipeline);
            out
        }
    }
}

/// Compile a response shaping pipeline from a base pipeline and an optional override chain.
///
/// Intended usage:
/// - HTTP tools: `compile_pipeline(&server.response_transforms, tool.response.transforms.as_ref())`
/// - `OpenAPI` tools: compile multiple layers by calling `apply_chain` repeatedly.
///
/// # Errors
///
/// Returns an error if:
/// - a transform configuration is invalid (e.g. an invalid JSON pointer for `pickPointers`)
pub fn compile_pipeline(
    base: &[ResponseTransform],
    chain: Option<&ResponseTransformChainConfig>,
) -> Result<Arc<CompiledResponsePipeline>, String> {
    let effective = apply_chain(base, chain);
    compile_pipeline_from_transforms(&effective)
}

/// Compile a pipeline from a finalized transform list.
///
/// # Errors
///
/// Returns an error if a transform configuration is invalid.
pub fn compile_pipeline_from_transforms(
    transforms: &[ResponseTransform],
) -> Result<Arc<CompiledResponsePipeline>, String> {
    let mut steps: Vec<CompiledTransform> = Vec::with_capacity(transforms.len());

    for t in transforms {
        match t {
            ResponseTransform::DropNulls => steps.push(CompiledTransform::DropNulls),
            ResponseTransform::PickPointers { pointers } => {
                let fields = compile_top_level_pointers(pointers)?;
                steps.push(CompiledTransform::PickTopLevelFields { fields });
            }
            ResponseTransform::RedactKeys { keys, replacement } => {
                let keys: HashSet<String> = keys.iter().cloned().collect();
                let replacement = replacement
                    .clone()
                    .unwrap_or_else(|| "***REDACTED***".to_string());
                steps.push(CompiledTransform::RedactKeys { keys, replacement });
            }
            ResponseTransform::TruncateStrings { max_chars } => {
                steps.push(CompiledTransform::TruncateStrings {
                    max_chars: *max_chars,
                });
            }
            ResponseTransform::LimitArrays { max_items } => {
                steps.push(CompiledTransform::LimitArrays {
                    max_items: *max_items,
                });
            }
        }
    }

    Ok(Arc::new(CompiledResponsePipeline { steps }))
}

impl CompiledResponsePipeline {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Apply the pipeline to a tool output value (in-place).
    pub fn apply_to_value(&self, v: &mut Value) {
        for step in &self.steps {
            match step {
                CompiledTransform::DropNulls => drop_nulls_in_place(v),
                CompiledTransform::PickTopLevelFields { fields } => {
                    pick_top_level_fields(v, fields);
                }
                CompiledTransform::RedactKeys { keys, replacement } => {
                    redact_keys_in_place(v, keys, replacement);
                }
                CompiledTransform::TruncateStrings { max_chars } => {
                    truncate_strings_in_place(v, *max_chars);
                }
                CompiledTransform::LimitArrays { max_items } => {
                    limit_arrays_in_place(v, *max_items);
                }
            }
        }
    }

    /// Apply schema transformations for the pipeline (best-effort).
    ///
    /// Returns a list of warnings (empty if all rewrites were applied cleanly).
    pub fn apply_to_schema(&self, schema: &mut Value) -> Vec<String> {
        let mut warnings = Vec::new();
        for step in &self.steps {
            match step {
                CompiledTransform::DropNulls => remove_required_recursively(schema),
                CompiledTransform::PickTopLevelFields { fields } => {
                    if !prune_schema_top_level_properties(schema, fields) {
                        // Best-effort widening: remove required to avoid overstating guarantees.
                        remove_required_recursively(schema);
                        warnings.push(
                            "pickPointers: cannot prune output schema (expected an object schema with properties at the root); widening by removing required".to_string()
                        );
                    }
                }
                CompiledTransform::RedactKeys { keys, .. } => {
                    // Best-effort: widen matching properties to allow `string`.
                    widen_schema_redacted_keys(schema, keys);
                }
                CompiledTransform::TruncateStrings { max_chars } => {
                    apply_max_length(schema, *max_chars);
                }
                CompiledTransform::LimitArrays { max_items } => {
                    apply_max_items(schema, *max_items);
                }
            }
        }
        warnings
    }
}

fn compile_top_level_pointers(pointers: &[String]) -> Result<HashSet<String>, String> {
    let mut fields: HashSet<String> = HashSet::new();
    for p in pointers {
        let field = parse_top_level_json_pointer(p.as_str())?;
        fields.insert(field);
    }
    Ok(fields)
}

fn parse_top_level_json_pointer(ptr: &str) -> Result<String, String> {
    if ptr.is_empty() {
        return Err("json pointer must not be empty".to_string());
    }
    if !ptr.starts_with('/') {
        return Err(format!("json pointer must start with '/', got '{ptr}'"));
    }
    let rest = &ptr[1..];
    if rest.is_empty() {
        return Err("json pointer must not be '/' (empty token)".to_string());
    }
    if rest.contains('/') {
        return Err(format!(
            "only top-level pointers are supported (e.g. '/id'); got '{ptr}'"
        ));
    }
    decode_pointer_token(rest)
}

fn decode_pointer_token(token: &str) -> Result<String, String> {
    // RFC 6901: "~1" => "/", "~0" => "~"
    if !token.contains('~') {
        return Ok(token.to_string());
    }
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c != '~' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            Some(other) => {
                return Err(format!(
                    "invalid json pointer escape '~{other}' in token '{token}'"
                ));
            }
            None => return Err(format!("dangling '~' in json pointer token '{token}'")),
        }
    }
    Ok(out)
}

fn drop_nulls_in_place(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                drop_nulls_in_place(v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                drop_nulls_in_place(v);
            }
        }
        _ => {}
    }
}

fn pick_top_level_fields(v: &mut Value, fields: &HashSet<String>) {
    let Value::Object(map) = v else {
        return;
    };
    map.retain(|k, _| fields.contains(k));
}

fn redact_keys_in_place(v: &mut Value, keys: &HashSet<String>, replacement: &str) {
    match v {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if keys.contains(k) {
                    *v = Value::String(replacement.to_string());
                    continue;
                }
                redact_keys_in_place(v, keys, replacement);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                redact_keys_in_place(v, keys, replacement);
            }
        }
        _ => {}
    }
}

fn truncate_strings_in_place(v: &mut Value, max_chars: usize) {
    match v {
        Value::String(s) => {
            if s.chars().count() <= max_chars {
                return;
            }
            *s = s.chars().take(max_chars).collect();
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                truncate_strings_in_place(v, max_chars);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                truncate_strings_in_place(v, max_chars);
            }
        }
        _ => {}
    }
}

fn limit_arrays_in_place(v: &mut Value, max_items: usize) {
    match v {
        Value::Array(arr) => {
            if arr.len() > max_items {
                arr.truncate(max_items);
            }
            for v in arr {
                limit_arrays_in_place(v, max_items);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                limit_arrays_in_place(v, max_items);
            }
        }
        _ => {}
    }
}

fn remove_required_recursively(schema: &mut Value) {
    match schema {
        Value::Object(map) => {
            map.remove("required");
            for v in map.values_mut() {
                remove_required_recursively(v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                remove_required_recursively(v);
            }
        }
        _ => {}
    }
}

fn prune_schema_top_level_properties(schema: &mut Value, fields: &HashSet<String>) -> bool {
    let Value::Object(map) = schema else {
        return false;
    };
    let Some(props) = map.get_mut("properties").and_then(Value::as_object_mut) else {
        return false;
    };

    props.retain(|k, _| fields.contains(k));

    if let Some(req) = map.get_mut("required").and_then(Value::as_array_mut) {
        req.retain(|v| v.as_str().is_some_and(|s| fields.contains(s)));
    }

    true
}

fn widen_schema_redacted_keys(schema: &mut Value, keys: &HashSet<String>) {
    match schema {
        Value::Object(map) => {
            // If this is an object schema with properties, widen matching properties.
            if let Some(props) = map.get_mut("properties").and_then(Value::as_object_mut) {
                for (k, sub) in props.iter_mut() {
                    if keys.contains(k) {
                        widen_to_allow_string(sub);
                    }
                }
            }
            for v in map.values_mut() {
                widen_schema_redacted_keys(v, keys);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                widen_schema_redacted_keys(v, keys);
            }
        }
        _ => {}
    }
}

fn widen_to_allow_string(schema: &mut Value) {
    if schema_allows_string(schema) {
        return;
    }
    let original = std::mem::replace(schema, Value::Null);
    *schema = json!({
        "anyOf": [
            original,
            { "type": "string" }
        ]
    });
}

fn schema_allows_string(schema: &Value) -> bool {
    let Value::Object(map) = schema else {
        return false;
    };

    if let Some(t) = map.get("type") {
        match t {
            Value::String(s) => {
                if s == "string" {
                    return true;
                }
            }
            Value::Array(arr) if arr.iter().any(|v| v.as_str() == Some("string")) => {
                return true;
            }
            _ => {}
        }
    }

    for key in ["anyOf", "oneOf", "allOf"] {
        if let Some(arr) = map.get(key).and_then(Value::as_array)
            && arr.iter().any(schema_allows_string)
        {
            return true;
        }
    }

    false
}

fn apply_max_length(schema: &mut Value, max_chars: usize) {
    let allow_string = schema_allows_string(schema);
    match schema {
        Value::Object(map) => {
            // If schema can be a string, clamp maxLength.
            if allow_string {
                clamp_numeric(map, "maxLength", max_chars);
            }
            for v in map.values_mut() {
                apply_max_length(v, max_chars);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                apply_max_length(v, max_chars);
            }
        }
        _ => {}
    }
}

fn apply_max_items(schema: &mut Value, max_items: usize) {
    let allow_array = schema_allows_array(schema);
    match schema {
        Value::Object(map) => {
            // If schema can be an array, clamp maxItems.
            if allow_array {
                clamp_numeric(map, "maxItems", max_items);
            }
            for v in map.values_mut() {
                apply_max_items(v, max_items);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                apply_max_items(v, max_items);
            }
        }
        _ => {}
    }
}

fn schema_allows_array(schema: &Value) -> bool {
    let Value::Object(map) = schema else {
        return false;
    };

    if let Some(t) = map.get("type") {
        match t {
            Value::String(s) => {
                if s == "array" {
                    return true;
                }
            }
            Value::Array(arr) if arr.iter().any(|v| v.as_str() == Some("array")) => {
                return true;
            }
            _ => {}
        }
    }

    for key in ["anyOf", "oneOf", "allOf"] {
        if let Some(arr) = map.get(key).and_then(Value::as_array)
            && arr.iter().any(schema_allows_array)
        {
            return true;
        }
    }

    false
}

fn clamp_numeric(map: &mut serde_json::Map<String, Value>, key: &str, max: usize) {
    let Some(v) = map.get(key) else {
        map.insert(
            key.to_string(),
            Value::Number(serde_json::Number::from(max as u64)),
        );
        return;
    };

    let Some(cur) = v.as_u64() else {
        // Ignore weird/non-integer user schema.
        return;
    };

    if cur > max as u64 {
        map.insert(
            key.to_string(),
            Value::Number(serde_json::Number::from(max as u64)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResponseTransform;

    #[test]
    fn drop_nulls_removes_null_fields_recursively() {
        let pipeline = compile_pipeline_from_transforms(&[ResponseTransform::DropNulls]).unwrap();
        let mut v = json!({
            "a": 1,
            "b": null,
            "c": { "x": null, "y": 2 },
            "d": [ { "k": null, "v": 1 } ]
        });
        pipeline.apply_to_value(&mut v);
        assert_eq!(
            v,
            json!({
                "a": 1,
                "c": { "y": 2 },
                "d": [ { "v": 1 } ]
            })
        );
    }

    #[test]
    fn pick_pointers_keeps_only_selected_fields() {
        let pipeline = compile_pipeline_from_transforms(&[ResponseTransform::PickPointers {
            pointers: vec!["/id".into(), "/name".into()],
        }])
        .unwrap();

        let mut v = json!({ "id": 1, "name": "x", "extra": true });
        pipeline.apply_to_value(&mut v);
        assert_eq!(v, json!({ "id": 1, "name": "x" }));
    }

    #[test]
    fn pick_pointers_rejects_nested_pointers() {
        let err = compile_pipeline_from_transforms(&[ResponseTransform::PickPointers {
            pointers: vec!["/a/b".into()],
        }])
        .unwrap_err();
        assert!(err.contains("top-level"));
    }

    #[test]
    fn schema_drop_nulls_removes_required() {
        let pipeline = compile_pipeline_from_transforms(&[ResponseTransform::DropNulls]).unwrap();
        let mut schema = json!({
            "type": "object",
            "properties": { "a": { "type": "string" } },
            "required": ["a"]
        });
        let warnings = pipeline.apply_to_schema(&mut schema);
        assert!(warnings.is_empty());
        assert!(schema.get("required").is_none());
    }

    #[test]
    fn schema_pick_pointers_prunes_properties_and_required() {
        let pipeline = compile_pipeline_from_transforms(&[ResponseTransform::PickPointers {
            pointers: vec!["/a".into()],
        }])
        .unwrap();
        let mut schema = json!({
            "type": "object",
            "properties": { "a": { "type": "string" }, "b": { "type": "string" } },
            "required": ["a", "b"]
        });
        let warnings = pipeline.apply_to_schema(&mut schema);
        assert!(warnings.is_empty());
        assert_eq!(
            schema.get("properties").unwrap(),
            &json!({ "a": { "type": "string" } })
        );
        assert_eq!(schema.get("required").unwrap(), &json!(["a"]));
    }
}
