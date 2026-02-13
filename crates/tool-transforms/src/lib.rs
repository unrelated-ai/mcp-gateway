//! Shared transforms applied to tool surfaces (names, parameters, defaults).
//!
//! This is intentionally small for now; we will grow it as we implement
//! per-tenant/per-profile policies in the Gateway and standalone transforms in the Adapter.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;

mod serde_helpers {
    // Serde's `default = "..."` expects helpers with the signature `fn() -> T`.
    pub const fn default_true() -> bool {
        true
    }
}

use serde_helpers::default_true;

/// A minimal transform pipeline for shaping tool surfaces.
///
/// This is designed to be shared by:
/// - the Gateway (per-tenant/per-profile policy)
/// - the Adapter (standalone single-tenant config)
///
/// The initial scope is intentionally small and only covers:
/// - tool name renames
/// - top-level argument renames
/// - top-level default argument injection
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransformPipeline {
    #[serde(default)]
    pub tool_overrides: HashMap<String, ToolOverride>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, ParamOverride>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParamOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    /// Whether this argument is exposed to clients in `tools/list`.
    ///
    /// When `false`, the parameter is removed from the exposed JSON Schema.
    #[serde(
        default = "default_true",
        skip_serializing_if = "std::clone::Clone::clone"
    )]
    pub visible: bool,
    /// If true (default), treat `null` like "missing" when applying defaults.
    ///
    /// If false, defaults are applied only when the argument is absent.
    #[serde(
        default = "default_true",
        skip_serializing_if = "std::clone::Clone::clone"
    )]
    pub treat_null_as_missing: bool,
}

impl Default for ParamOverride {
    fn default() -> Self {
        Self {
            rename: None,
            default: None,
            visible: true,
            treat_null_as_missing: true,
        }
    }
}

impl TransformPipeline {
    /// Map a tool name through configured renames.
    #[must_use]
    pub fn map_tool_name<'a>(&'a self, tool_name: &'a str) -> Cow<'a, str> {
        self.tool_overrides
            .get(tool_name)
            .and_then(|o| o.rename.as_ref())
            .map_or(Cow::Borrowed(tool_name), |t| Cow::Owned(t.clone()))
    }

    /// Apply transforms to a tool **name** for the exposed surface (`tools/list`).
    #[must_use]
    pub fn exposed_tool_name<'a>(&'a self, original_tool_name: &'a str) -> Cow<'a, str> {
        self.map_tool_name(original_tool_name)
    }

    /// Apply transforms to a tool input schema for the exposed surface (`tools/list`).
    ///
    /// This is intentionally limited to top-level JSON Schema rewrites:
    /// - `properties` key rename
    /// - `required` entries rename
    /// - best-effort `default` injection into `properties.<name>.default`
    pub fn apply_schema_transforms(&self, original_tool_name: &str, schema: &mut Value) {
        let Some(tool) = self.tool_overrides.get(original_tool_name) else {
            return;
        };

        // Rename `properties` keys.
        if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
            for (raw, o) in &tool.params {
                let Some(to) = o.rename.as_ref() else {
                    continue;
                };
                if raw == to {
                    continue;
                }
                if let Some(v) = props.remove(raw) {
                    // Do not override if destination exists.
                    props.entry(to.clone()).or_insert(v);
                }
            }
        }

        // Rename `required` entries.
        if let Some(req) = schema.get_mut("required").and_then(Value::as_array_mut) {
            for v in req.iter_mut() {
                let Some(s) = v.as_str() else {
                    continue;
                };
                if let Some(o) = tool.params.get(s)
                    && let Some(to) = o.rename.as_ref()
                {
                    *v = Value::String(to.clone());
                }
            }
        }

        // Hide params (after rename, since the exposed name is what exists in `properties`).
        if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
            for (raw, o) in &tool.params {
                if o.visible {
                    continue;
                }
                let exposed = o.rename.as_deref().unwrap_or(raw);
                props.remove(exposed);
            }
        }
        if let Some(req) = schema.get_mut("required").and_then(Value::as_array_mut) {
            req.retain(|v| {
                let Some(s) = v.as_str() else {
                    return true;
                };
                let Some((raw, _)) = tool
                    .params
                    .iter()
                    .find(|(raw, o)| o.rename.as_deref().unwrap_or(*raw) == s)
                else {
                    return true;
                };
                tool.params.get(raw).is_some_and(|o| o.visible)
            });
        }

        Self::apply_schema_defaults(tool, schema);
    }

    fn apply_schema_defaults(tool: &ToolOverride, schema: &mut Value) {
        let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) else {
            return;
        };

        for (raw_param, o) in &tool.params {
            let Some(default_value) = o.default.as_ref() else {
                continue;
            };
            let exposed = o.rename.as_deref().unwrap_or(raw_param);
            let Some(prop_schema) = props.get_mut(exposed) else {
                continue;
            };
            if let Some(obj) = prop_schema.as_object_mut() {
                obj.entry("default".to_string())
                    .or_insert_with(|| default_value.clone());
            }
        }
    }

    /// Rewrite incoming call arguments to the **original** tool/param names before execution.
    ///
    /// The input `args` is assumed to be in **exposed** parameter names (post-rename).
    /// This function:
    /// 1) rewrites exposed param names → original param names
    /// 2) injects defaults for missing/`null` original params
    pub fn apply_call_transforms(
        &self,
        original_tool_name: &str,
        args: &mut serde_json::Map<String, Value>,
    ) {
        // Invert rename map: original -> exposed  ==> exposed -> original
        if let Some(tool) = self.tool_overrides.get(original_tool_name) {
            for (raw, o) in &tool.params {
                let Some(exposed) = o.rename.as_ref() else {
                    continue;
                };
                if raw == exposed {
                    continue;
                }
                if args.contains_key(raw) {
                    // Destination already set: drop exposed to avoid ambiguity, but do not override.
                    args.remove(exposed);
                    continue;
                }
                if let Some(v) = args.remove(exposed) {
                    args.insert(raw.clone(), v);
                }
            }

            // Drop hidden params provided by the caller (both raw and exposed keys).
            for (raw, o) in &tool.params {
                if o.visible {
                    continue;
                }
                args.remove(raw);
                if let Some(exposed) = o.rename.as_ref() {
                    args.remove(exposed);
                }
            }

            // Defaults are configured by original param name.
            for (k, o) in &tool.params {
                let Some(v) = o.default.as_ref() else {
                    continue;
                };
                let is_missing_or_null = match args.get(k) {
                    None => true,
                    Some(cur) => o.treat_null_as_missing && cur.is_null(),
                };
                if is_missing_or_null {
                    args.insert(k.clone(), v.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TransformPipeline;
    use serde_json::{Value, json};
    use std::collections::HashMap;

    #[test]
    fn map_tool_name_is_noop_by_default() {
        let p = TransformPipeline::default();
        assert_eq!(p.map_tool_name("t").as_ref(), "t");
    }

    #[test]
    fn map_tool_name_applies_rename() {
        let mut p = TransformPipeline::default();
        p.tool_overrides.insert(
            "a".to_string(),
            super::ToolOverride {
                rename: Some("b".to_string()),
                ..Default::default()
            },
        );

        assert_eq!(p.map_tool_name("a").as_ref(), "b");
        assert_eq!(p.map_tool_name("x").as_ref(), "x");
    }

    #[test]
    fn apply_call_transforms_renames_and_defaults() {
        let mut p = TransformPipeline::default();

        p.tool_overrides.insert(
            "tool".to_string(),
            super::ToolOverride {
                params: HashMap::from([
                    (
                        "old".to_string(),
                        super::ParamOverride {
                            rename: Some("new".to_string()),
                            ..Default::default()
                        },
                    ),
                    (
                        "x".to_string(),
                        super::ParamOverride {
                            default: Some(json!(1)),
                            ..Default::default()
                        },
                    ),
                    (
                        "y".to_string(),
                        super::ParamOverride {
                            default: Some(json!("def")),
                            ..Default::default()
                        },
                    ),
                ]),
                ..Default::default()
            },
        );

        let mut args = serde_json::Map::from_iter([
            ("new".to_string(), json!("v")),
            ("y".to_string(), Value::Null),
        ]);

        p.apply_call_transforms("tool", &mut args);

        assert!(!args.contains_key("new"));
        assert_eq!(args.get("old"), Some(&json!("v")));
        assert_eq!(args.get("x"), Some(&json!(1)));
        assert_eq!(args.get("y"), Some(&json!("def")));
    }

    #[test]
    fn apply_call_transforms_does_not_override_destination_param() {
        let mut p = TransformPipeline::default();
        p.tool_overrides.insert(
            "tool".to_string(),
            super::ToolOverride {
                params: HashMap::from([(
                    "old".to_string(),
                    super::ParamOverride {
                        rename: Some("new".to_string()),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
        );

        let mut args = serde_json::Map::from_iter([
            ("new".to_string(), json!("drop-me")),
            ("old".to_string(), json!("keep-me")),
        ]);

        p.apply_call_transforms("tool", &mut args);

        assert!(!args.contains_key("new"));
        assert_eq!(args.get("old"), Some(&json!("keep-me")));
    }

    #[test]
    fn apply_schema_transforms_renames_properties_and_required_and_defaults() {
        let mut p = TransformPipeline::default();
        p.tool_overrides.insert(
            "tool".to_string(),
            super::ToolOverride {
                params: HashMap::from([(
                    "old".to_string(),
                    super::ParamOverride {
                        rename: Some("new".to_string()),
                        default: Some(json!(7)),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
        );

        let mut schema = json!({
            "type": "object",
            "properties": {
                "old": { "type": "integer" }
            },
            "required": ["old"]
        });

        p.apply_schema_transforms("tool", &mut schema);

        let props = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("properties");
        assert!(props.get("old").is_none());
        assert_eq!(
            props.get("new").and_then(|v| v.get("default")),
            Some(&json!(7))
        );

        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("required");
        assert_eq!(required, &vec![json!("new")]);
    }
}
