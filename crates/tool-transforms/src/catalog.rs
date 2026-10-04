//! Source-scoped resource and prompt policy. Original identities remain the configuration keys.
use crate::{TransformPipeline, default_true};
use anyhow::{Result, ensure};
use rmcp::model::{CompleteRequestParams, CompletionContext, Prompt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub type CatalogOverrides<T> = HashMap<String, HashMap<String, T>>;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromptParamOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
    /// Prompt arguments are strings. An empty string is a valid default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromptOverride {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, PromptParamOverride>,
}
impl Default for PromptOverride {
    fn default() -> Self {
        Self {
            enabled: true,
            rename: None,
            description: None,
            params: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceOverride {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
impl Default for ResourceOverride {
    fn default() -> Self {
        Self {
            enabled: true,
            name: None,
            title: None,
            description: None,
        }
    }
}

fn nonempty(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.trim() == value,
        "Names must be nonempty and have no surrounding whitespace"
    );
    Ok(())
}

impl TransformPipeline {
    /// Validate configured names without requiring available upstream catalogs.
    ///
    /// # Errors
    /// Returns an error for empty names, duplicate aliases, or malformed templates.
    pub fn validate_catalog_overrides(&self) -> Result<()> {
        for overrides in [&self.resource_overrides, &self.resource_template_overrides] {
            for (source, entries) in overrides {
                nonempty(source)?;
                for (id, entry) in entries {
                    nonempty(id)?;
                    if let Some(name) = &entry.name {
                        nonempty(name)?;
                    }
                }
            }
        }
        for entries in self.resource_template_overrides.values() {
            for template in entries.keys() {
                template_pattern(template)?;
            }
        }
        for (source, entries) in &self.prompt_overrides {
            nonempty(source)?;
            let mut names = HashSet::new();
            for (original, entry) in entries {
                nonempty(original)?;
                let name = entry.rename.as_deref().unwrap_or(original);
                nonempty(name)?;
                ensure!(
                    entry.rename.is_none() || !name.contains(':'),
                    "Prompt aliases cannot contain ':'"
                );
                ensure!(
                    !entry.enabled || names.insert(name),
                    "Duplicate prompt alias: {name}"
                );
                let mut arguments = HashSet::new();
                for (original, param) in &entry.params {
                    nonempty(original)?;
                    let name = param.rename.as_deref().unwrap_or(original);
                    nonempty(name)?;
                    ensure!(arguments.insert(name), "Duplicate prompt argument: {name}");
                }
            }
        }
        Ok(())
    }

    /// Disabled templates deny their entire URI family, including overlapping resources/templates.
    /// Expressions are conservatively matched as wildcards: this can deny more URIs, never fewer.
    #[must_use]
    pub fn resource_allowed(&self, source: &str, uri: &str) -> bool {
        if self
            .resource_overrides
            .get(source)
            .and_then(|entries| entries.get(uri))
            .is_some_and(|entry| !entry.enabled)
        {
            return false;
        }
        !self
            .resource_template_overrides
            .get(source)
            .is_some_and(|entries| {
                entries.iter().any(|(template, entry)| {
                    !entry.enabled
                        && (uri == template
                            || template_pattern(template)
                                .map_or(true, |pattern| pattern.is_match(uri)))
                })
            })
    }
}

/// Match literals exactly and allow any expansion of each URI-template expression.
/// The expression parser is deliberately not an inverse RFC 6570 implementation.
fn template_pattern(template: &str) -> Result<regex::Regex> {
    let mut pattern = String::from("(?s)\\A");
    let mut remaining = template;
    while let Some((literal, rest)) = remaining.split_once('{') {
        ensure!(!literal.contains('}'), "Invalid resource template");
        pattern.push_str(&regex::escape(literal));
        let (expression, rest) = rest
            .split_once('}')
            .ok_or_else(|| anyhow::anyhow!("Invalid resource template"))?;
        ensure!(
            !expression.is_empty() && !expression.contains('{'),
            "Invalid resource template"
        );
        pattern.push_str(".*");
        remaining = rest;
    }
    ensure!(!remaining.contains('}'), "Invalid resource template");
    pattern.push_str(&regex::escape(remaining));
    pattern.push_str("\\z");
    Ok(regex::Regex::new(&pattern)?)
}

impl PromptOverride {
    /// Apply client-facing names, descriptions, and argument optionality.
    ///
    /// # Errors
    /// Returns an error when names are empty or argument aliases collide.
    pub fn apply(&self, prompt: &mut Prompt) -> Result<()> {
        if let Some(name) = &self.rename {
            nonempty(name)?;
            prompt.name.clone_from(name);
        }
        if let Some(description) = &self.description {
            prompt.description = Some(description.clone());
        }
        let mut names = HashSet::new();
        for arg in prompt.arguments.iter_mut().flatten() {
            if let Some(rule) = self.params.get(&arg.name) {
                if let Some(name) = &rule.rename {
                    nonempty(name)?;
                    arg.name.clone_from(name);
                }
                if rule.default.is_some() {
                    arg.required = Some(false);
                }
            }
            ensure!(
                names.insert(arg.name.clone()),
                "Duplicate prompt argument: {}",
                arg.name
            );
        }
        Ok(())
    }

    /// Simultaneous renames support swaps and reject both raw and aliased input for the same argument.
    ///
    /// # Errors
    /// Returns an error for ambiguous aliases or input using a renamed original argument.
    pub fn map_arguments(
        &self,
        arguments: HashMap<String, String>,
    ) -> Result<HashMap<String, String>> {
        let mut result = HashMap::new();
        for (name, value) in arguments {
            let mut matches = self
                .params
                .iter()
                .filter(|(original, rule)| rule.rename.as_deref().unwrap_or(original) == name);
            let original = matches
                .next()
                .map_or(name.as_str(), |(original, _)| original.as_str());
            ensure!(
                matches.next().is_none(),
                "Ambiguous prompt argument: {name}"
            );
            // An original name that was renamed is not an alternate spelling of its alias.
            ensure!(
                original != name
                    || self.params.get(&name).is_none_or(|rule| rule
                        .rename
                        .as_deref()
                        .is_none_or(|alias| alias == name)),
                "Use the exposed prompt argument name for {name}"
            );
            ensure!(
                result.insert(original.to_owned(), value).is_none(),
                "Duplicate prompt argument: {name}"
            );
        }
        for (name, rule) in &self.params {
            if let Some(default) = &rule.default {
                result
                    .entry(name.clone())
                    .or_insert_with(|| default.clone());
            }
        }
        Ok(result)
    }

    /// Map the argument being completed and its previously resolved context.
    ///
    /// # Errors
    /// Returns an error when the argument or context has ambiguous aliases.
    pub fn map_completion(&self, params: &mut CompleteRequestParams) -> Result<()> {
        // Resolve the argument separately; defaults belong in the completion context.
        let mut one = self.clone();
        for rule in one.params.values_mut() {
            rule.default = None;
        }
        let mapped = one.map_arguments(HashMap::from([(
            params.argument.name.clone(),
            params.argument.value.clone(),
        )]))?;
        params.argument.name = mapped
            .into_keys()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing completion argument"))?;
        let mut context = self.map_arguments(
            params
                .context
                .as_ref()
                .and_then(|context| context.arguments.clone())
                .unwrap_or_default(),
        )?;
        context.remove(&params.argument.name);
        if !context.is_empty() || params.context.is_some() {
            params.context = Some(CompletionContext::with_arguments(context));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{ArgumentInfo, Reference};
    use serde_json::json;

    #[test]
    fn defaults_aliases_and_completion_context_use_original_argument_names() {
        let rule: PromptOverride = serde_json::from_value(
            json!({"rename":"review","description":"Review changes", "params":{
                "repo":{"rename":"repository","default":"demo"}, "language":{"default":""}
            }}),
        )
        .unwrap();
        let mut prompt: Prompt = serde_json::from_value(
            json!({"name":"raw","arguments":[{"name":"repo","required":true},{"name":"language"}]}),
        )
        .unwrap();
        rule.apply(&mut prompt).unwrap();
        assert_eq!(prompt.name, "review");
        assert_eq!(prompt.arguments.as_ref().unwrap()[0].name, "repository");
        assert_eq!(prompt.arguments.as_ref().unwrap()[0].required, Some(false));
        let mapped = rule
            .map_arguments(HashMap::from([("repository".into(), "chosen".into())]))
            .unwrap();
        assert_eq!(mapped["repo"], "chosen");
        assert_eq!(mapped["language"], "");
        assert!(
            rule.map_arguments(HashMap::from([("repo".into(), "bypass".into())]))
                .is_err()
        );
        let mut complete = CompleteRequestParams::new(
            Reference::for_prompt("review"),
            ArgumentInfo::new("repository", "de"),
        )
        .with_context(CompletionContext::with_arguments(HashMap::from([(
            "language".into(),
            "en".into(),
        )])));
        rule.map_completion(&mut complete).unwrap();
        assert_eq!(complete.argument.name, "repo");
        assert_eq!(complete.argument.value, "de");
        assert_eq!(
            complete.context.unwrap().arguments.unwrap(),
            HashMap::from([("language".into(), "en".into())])
        );
    }

    #[test]
    fn simultaneous_swaps_do_not_lose_values_and_collisions_are_rejected() {
        let rule: PromptOverride =
            serde_json::from_value(json!({"params":{"a":{"rename":"b"},"b":{"rename":"a"}}}))
                .unwrap();
        assert_eq!(
            rule.map_arguments(HashMap::from([
                ("a".into(), "one".into()),
                ("b".into(), "two".into())
            ]))
            .unwrap(),
            HashMap::from([("a".into(), "two".into()), ("b".into(), "one".into())])
        );
        let rule: PromptOverride =
            serde_json::from_value(json!({"params":{"a":{"rename":"b"}}})).unwrap();
        let mut prompt: Prompt =
            serde_json::from_value(json!({"name":"p","arguments":[{"name":"a"},{"name":"b"}]}))
                .unwrap();
        assert!(rule.apply(&mut prompt).is_err());
    }

    #[test]
    fn disabled_templates_and_exact_resources_are_scoped_and_fail_closed() {
        let rules: TransformPipeline = serde_json::from_value(json!({
            "resourceOverrides":{"source":{"test:///single":{"enabled":false}}},
            "resourceTemplateOverrides":{"source":{"test:///private/{id}{?format}":{"enabled":false}, "test:///optional{/path*}":{"enabled":false}}}
        })).unwrap();
        rules.validate_catalog_overrides().unwrap();
        for uri in [
            "test:///single",
            "test:///private/a%2Fb?format=text",
            "test:///private/{id}{?format}",
            "test:///optional",
            "test:///optional/a/b",
        ] {
            assert!(!rules.resource_allowed("source", uri), "{uri}");
            assert!(rules.resource_allowed("other", uri));
        }
        assert!(rules.resource_allowed("source", "test:///public/a"));
        let invalid: TransformPipeline = serde_json::from_value(
            json!({"resourceTemplateOverrides":{"source":{"{broken":{"enabled":false}}}}),
        )
        .unwrap();
        assert!(invalid.validate_catalog_overrides().is_err());
        assert!(!invalid.resource_allowed("source", "anything"));
    }

    #[test]
    fn catalog_contract_preserves_legacy_tool_settings_and_rejects_invalid_types() {
        let old: TransformPipeline =
            serde_json::from_value(json!({"toolOverrides":{"a":{"rename":"b"}}})).unwrap();
        assert!(old.resource_allowed("source", "test:///a"));
        assert_eq!(old.map_tool_name("a"), "b");
        assert!(
            serde_json::from_value::<PromptOverride>(json!({"params":{"x":{"default":5}}}))
                .is_err()
        );
        let invalid: TransformPipeline = serde_json::from_value(
            json!({"promptOverrides":{"source":{"a":{"rename":"same"},"b":{"rename":"same"}}}}),
        )
        .unwrap();
        assert!(invalid.validate_catalog_overrides().is_err());
    }
}
