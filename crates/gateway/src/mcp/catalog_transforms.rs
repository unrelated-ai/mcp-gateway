//! Shared catalog shaping and routes for discovery, legacy MCP, and native MCP.
use rmcp::model::{Prompt, Resource, ResourceTemplate};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use unrelated_tool_transforms::{PromptOverride, ResourceOverride, TransformPipeline};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CatalogEntry<T> {
    pub source_id: String,
    pub original: T,
    pub exposed: T,
    pub enabled: bool,
    pub error: Option<String>,
}

pub(super) fn resources(
    rules: &TransformPipeline,
    sources: Vec<(String, Vec<Resource>)>,
) -> Vec<CatalogEntry<Resource>> {
    // Count before filtering: disabling an entry must not change other resource URIs.
    let counts = super::surface::count_resource_uris(&sources);
    let mut entries = Vec::new();
    for (source, items) in sources {
        for original in items {
            let mut exposed = original.clone();
            if let Some(rule) = rules
                .resource_overrides
                .get(&source)
                .and_then(|entries| entries.get(&original.uri))
            {
                apply_metadata(
                    rule,
                    &mut exposed.name,
                    &mut exposed.title,
                    &mut exposed.description,
                );
            }
            if counts.get(&original.uri).copied().unwrap_or_default() > 1 {
                exposed.uri = super::ids::resource_collision_urn(&source, &original.uri);
            }
            let enabled = rules.resource_allowed(&source, &original.uri);
            let template_blocked = !enabled
                && rules
                    .resource_overrides
                    .get(&source)
                    .and_then(|entries| entries.get(&original.uri))
                    .is_none_or(|rule| rule.enabled);
            entries.push(CatalogEntry {
                enabled,
                source_id: source.clone(),
                original,
                exposed,
                error: template_blocked.then(|| "Blocked by a disabled resource template.".into()),
            });
        }
    }
    entries
}

pub(super) fn templates(
    rules: &TransformPipeline,
    sources: Vec<(String, Vec<ResourceTemplate>)>,
) -> Vec<CatalogEntry<ResourceTemplate>> {
    let mut entries = Vec::new();
    for (source, items) in sources {
        for original in items {
            let mut exposed = original.clone();
            let rule = rules
                .resource_template_overrides
                .get(&source)
                .and_then(|entries| entries.get(&original.uri_template));
            if let Some(rule) = rule {
                apply_metadata(
                    rule,
                    &mut exposed.name,
                    &mut exposed.title,
                    &mut exposed.description,
                );
            }
            exposed.uri_template =
                unrelated_mcp_support::resource_template_uri(&source, &original.uri_template);
            entries.push(CatalogEntry {
                enabled: rule.is_none_or(|rule| rule.enabled),
                source_id: source.clone(),
                original,
                exposed,
                error: None,
            });
        }
    }
    entries.sort_by(|a, b| a.exposed.uri_template.cmp(&b.exposed.uri_template));
    entries
}

fn apply_metadata(
    rule: &ResourceOverride,
    name: &mut String,
    title: &mut Option<String>,
    description: &mut Option<String>,
) {
    if let Some(value) = &rule.name {
        name.clone_from(value);
    }
    if rule.title.is_some() {
        title.clone_from(&rule.title);
    }
    if rule.description.is_some() {
        description.clone_from(&rule.description);
    }
}

pub(super) fn prompts(
    rules: &TransformPipeline,
    sources: Vec<(String, Vec<Prompt>)>,
) -> Vec<CatalogEntry<Prompt>> {
    let mut entries = Vec::new();
    let mut counts = HashMap::<String, usize>::new();
    let mut local_counts = HashMap::<(String, String), usize>::new();
    for (source, items) in sources {
        for original in items {
            let mut exposed = original.clone();
            let rule = rules
                .prompt_overrides
                .get(&source)
                .and_then(|entries| entries.get(&original.name));
            let error = rule
                .and_then(|rule| rule.apply(&mut exposed).err())
                .map(|error| error.to_string());
            let enabled = rule.is_none_or(|rule| rule.enabled) && error.is_none();
            if enabled {
                *counts.entry(exposed.name.clone()).or_default() += 1;
                *local_counts
                    .entry((source.clone(), exposed.name.clone()))
                    .or_default() += 1;
            }
            entries.push(CatalogEntry {
                source_id: source.clone(),
                original,
                exposed,
                enabled,
                error,
            });
        }
    }
    for entry in &mut entries {
        if local_counts
            .get(&(entry.source_id.clone(), entry.exposed.name.clone()))
            .copied()
            .unwrap_or_default()
            > 1
        {
            entry.enabled = false;
            entry.error = Some("Two prompts from this source have the same exposed name.".into());
        } else if counts.get(&entry.exposed.name).copied().unwrap_or_default() > 1 {
            entry.exposed.name = format!("{}:{}", entry.source_id, entry.exposed.name);
        }
    }
    // Upstream names may themselves contain prefixes. Never route an ambiguous exposed name.
    let mut seen = HashSet::new();
    let mut ambiguous = HashSet::new();
    for entry in entries.iter().filter(|entry| entry.enabled) {
        if !seen.insert(entry.exposed.name.clone()) {
            ambiguous.insert(entry.exposed.name.clone());
        }
    }
    for entry in &mut entries {
        if ambiguous.contains(&entry.exposed.name) {
            entry.enabled = false;
            entry.error = Some("Ambiguous exposed prompt name.".into());
        }
    }
    entries
}

pub(super) struct PromptRoute {
    pub source: String,
    pub original_name: String,
    pub rules: PromptOverride,
}

pub(super) fn prompt_route(
    rules: &TransformPipeline,
    entries: Vec<CatalogEntry<Prompt>>,
    name: &str,
) -> anyhow::Result<PromptRoute> {
    let candidates: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            entry.enabled
                && (entry.exposed.name == name
                    || format!(
                        "{}:{}",
                        entry.source_id,
                        rules
                            .prompt_overrides
                            .get(&entry.source_id)
                            .and_then(|entries| entries.get(&entry.original.name))
                            .and_then(|rule| rule.rename.as_ref())
                            .unwrap_or(&entry.original.name)
                    ) == name)
        })
        .collect();
    anyhow::ensure!(
        candidates.len() == 1,
        "Unknown, disabled, or ambiguous prompt: {name}"
    );
    let entry = candidates.into_iter().next().expect("one candidate");
    let overrides = rules
        .prompt_overrides
        .get(&entry.source_id)
        .and_then(|entries| entries.get(&entry.original.name))
        .cloned()
        .unwrap_or_default();
    Ok(PromptRoute {
        source: entry.source_id,
        original_name: entry.original.name,
        rules: overrides,
    })
}

pub(super) async fn policy(
    state: &super::McpState,
    profile_id: &str,
) -> anyhow::Result<TransformPipeline> {
    Ok(state
        .store
        .get_profile(profile_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Profile is unavailable"))?
        .transforms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn aliases_cannot_shadow_other_prompts_from_the_same_source() {
        let rules: TransformPipeline = serde_json::from_value(
            json!({"promptOverrides":{"one":{"first":{"rename":"second"}}}}),
        )
        .unwrap();
        let entries = prompts(
            &rules,
            vec![(
                "one".into(),
                vec![
                    Prompt::new("first", None::<String>, None),
                    Prompt::new("second", None::<String>, None),
                ],
            )],
        );
        assert!(
            entries
                .iter()
                .all(|entry| !entry.enabled && entry.error.is_some())
        );
        assert!(prompt_route(&rules, entries, "one:second").is_err());
    }

    #[test]
    fn resource_metadata_never_changes_identity_and_disabled_template_is_explained() {
        let rules: TransformPipeline = serde_json::from_value(json!({"resourceOverrides":{"one":{"docs:///guide":{"name":"Handbook","title":"Team","description":"Reference"}}},"resourceTemplateOverrides":{"one":{"docs:///{id}":{"enabled":false}}}})).unwrap();
        let entries = resources(
            &rules,
            vec![("one".into(), vec![Resource::new("docs:///guide", "guide")])],
        );
        let entry = &entries[0];
        assert_eq!(entry.original.name, "guide");
        assert_eq!(entry.exposed.uri, entry.original.uri);
        assert_eq!(entry.exposed.name, "Handbook");
        assert_eq!(entry.exposed.title.as_deref(), Some("Team"));
        assert!(!entry.enabled);
        assert!(entry.error.as_deref().unwrap().contains("template"));
    }
}
