use crate::{TOOL_REF_META_KEY, config};
use anyhow::{Context as _, bail};
use rmcp::model::Tool;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCatalog {
    pub fetched_at: u64,
    pub tools: Vec<Tool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Detail {
    Brief,
    #[default]
    Detailed,
    Full,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub tool_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<ParameterSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<Tool>,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParameterSummary {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub required: bool,
}

impl CachedCatalog {
    #[must_use]
    pub fn fresh(tools: Vec<Tool>) -> Self {
        Self {
            fetched_at: now_epoch_secs(),
            tools,
        }
    }

    #[must_use]
    pub fn is_fresh(&self) -> bool {
        now_epoch_secs().saturating_sub(self.fetched_at) < CACHE_TTL.as_secs()
    }

    #[must_use]
    pub fn find(&self, reference: &str) -> Option<&Tool> {
        self.tools
            .iter()
            .find(|tool| stable_ref(tool) == reference || tool.name == reference)
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn search(
        &self,
        query: &str,
        detail: Detail,
        limit: usize,
    ) -> anyhow::Result<Vec<SearchResult>> {
        let terms = tokenize(query);
        if terms.is_empty() {
            bail!("search query must not be empty");
        }
        let documents: Vec<Vec<String>> = self.tools.iter().map(index_terms).collect();
        let average_length = documents.iter().map(Vec::len).sum::<usize>().max(1) as f64
            / documents.len().max(1) as f64;
        let mut document_frequency: HashMap<&str, usize> = HashMap::new();
        for document in &documents {
            let unique: HashSet<&str> = document.iter().map(String::as_str).collect();
            for term in unique {
                *document_frequency.entry(term).or_default() += 1;
            }
        }

        let query_lower = query.to_ascii_lowercase();
        let mut scored = Vec::new();
        for (tool, document) in self.tools.iter().zip(documents.iter()) {
            let mut frequencies: HashMap<&str, usize> = HashMap::new();
            for term in document {
                *frequencies.entry(term).or_default() += 1;
            }
            let mut score = 0.0;
            for term in &terms {
                let tf = *frequencies.get(term.as_str()).unwrap_or(&0) as f64;
                if tf == 0.0 {
                    continue;
                }
                let df = *document_frequency.get(term.as_str()).unwrap_or(&0) as f64;
                let idf = ((self.tools.len() as f64 - df + 0.5) / (df + 0.5) + 1.0).ln();
                let length_norm =
                    1.2 * (1.0 - 0.75 + 0.75 * document.len() as f64 / average_length);
                score += idf * (tf * 2.2) / (tf + length_norm);
            }
            let reference = stable_ref(tool);
            if reference.eq_ignore_ascii_case(&query_lower) {
                score += 100.0;
            } else if tool.name.eq_ignore_ascii_case(&query_lower) {
                score += 75.0;
            } else if reference.to_ascii_lowercase().contains(&query_lower)
                || tool.name.to_ascii_lowercase().contains(&query_lower)
            {
                score += 15.0;
            }
            if score > 0.0 {
                scored.push(render_result(tool, detail, score));
            }
        }
        scored.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.tool_ref.cmp(&right.tool_ref))
        });
        scored.truncate(limit);
        Ok(scored)
    }
}

pub fn stable_ref(tool: &Tool) -> String {
    tool.meta
        .as_ref()
        .and_then(|meta| meta.0.get(TOOL_REF_META_KEY))
        .and_then(serde_json::Value::as_str)
        .filter(|reference| is_valid_stable_ref(reference))
        .unwrap_or(tool.name.as_ref())
        .to_string()
}

#[must_use]
pub fn is_valid_stable_ref(reference: &str) -> bool {
    reference
        .split_once(':')
        .is_some_and(|(source, name)| !source.is_empty() && !name.is_empty())
}

fn render_result(tool: &Tool, detail: Detail, score: f64) -> SearchResult {
    SearchResult {
        tool_ref: stable_ref(tool),
        name: tool.name.to_string(),
        title: tool.title.clone(),
        description: (detail != Detail::Brief)
            .then(|| tool.description.as_deref().map(str::to_string))
            .flatten(),
        parameters: (detail == Detail::Detailed).then(|| parameter_summaries(tool)),
        tool: (detail == Detail::Full).then(|| tool.clone()),
        score,
    }
}

fn parameter_summaries(tool: &Tool) -> Vec<ParameterSummary> {
    let required: HashSet<&str> = tool
        .input_schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    tool.input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .map(|(name, schema)| ParameterSummary {
            name: name.clone(),
            kind: schema
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("any")
                .to_string(),
            required: required.contains(name.as_str()),
        })
        .collect()
}

fn index_terms(tool: &Tool) -> Vec<String> {
    let mut text = format!(
        "{} {} {} {}",
        stable_ref(tool),
        tool.name,
        tool.title.as_deref().unwrap_or_default(),
        tool.description.as_deref().unwrap_or_default()
    );
    if let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
    {
        for name in properties.keys() {
            text.push(' ');
            text.push_str(name);
        }
    }
    tokenize(&text)
}

fn tokenize(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[must_use]
pub fn cache_path(base: &Path, context: &str) -> PathBuf {
    let digest = Sha256::digest(context.as_bytes());
    base.join(format!("{}.json", hex::encode(digest)))
}

pub fn load_cache(base: &Path, context: &str) -> anyhow::Result<Option<CachedCatalog>> {
    let path = cache_path(base, context);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&raw)
        .map(Some)
        .with_context(|| format!("invalid catalog cache {}", path.display()))
}

pub fn save_cache(base: &Path, context: &str, catalog: &CachedCatalog) -> anyhow::Result<()> {
    config::create_private_dir(base)?;
    let raw = serde_json::to_vec(catalog).context("failed to serialize catalog cache")?;
    config::write_private_file(&cache_path(base, context), &raw)
}

pub fn remove_cache(base: &Path, context: &str) -> anyhow::Result<()> {
    let path = cache_path(base, context);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn tool(name: &str, reference: Option<&str>, description: &str) -> Tool {
        let mut tool = Tool::new(
            name.to_string(),
            description.to_string(),
            Arc::new(serde_json::Map::from_iter([
                ("type".into(), serde_json::json!("object")),
                (
                    "properties".into(),
                    serde_json::json!({"unread": {"type": "boolean"}}),
                ),
            ])),
        );
        if let Some(reference) = reference {
            tool.meta = Some(rmcp::model::MetaObject(serde_json::Map::from_iter([(
                TOOL_REF_META_KEY.into(),
                serde_json::json!(reference),
            )])));
        }
        tool
    }

    #[test]
    fn stable_ref_uses_trusted_metadata_and_falls_back() {
        assert_eq!(
            stable_ref(&tool("exposed", Some("telegram:messages"), "")),
            "telegram:messages"
        );
        assert_eq!(
            stable_ref(&tool("old_gateway_name", None, "")),
            "old_gateway_name"
        );
    }

    #[test]
    fn bm25_search_boosts_exact_refs_and_semantics() {
        let catalog = CachedCatalog::fresh(vec![
            tool(
                "messages",
                Some("telegram:get_messages"),
                "Find unread Telegram messages",
            ),
            tool("send", Some("whatsapp:send"), "Send a WhatsApp message"),
        ]);
        let semantic = catalog
            .search("unread telegram", Detail::Detailed, 10)
            .unwrap();
        assert_eq!(semantic[0].tool_ref, "telegram:get_messages");
        let exact = catalog.search("whatsapp:send", Detail::Brief, 10).unwrap();
        assert_eq!(exact[0].tool_ref, "whatsapp:send");
    }

    #[test]
    fn cache_paths_do_not_include_context_names() {
        let path = cache_path(Path::new("/cache"), "../../escape");
        assert_eq!(path.parent(), Some(Path::new("/cache")));
    }

    #[cfg(unix)]
    #[test]
    fn cache_is_written_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        save_cache(temp.path(), "work", &CachedCatalog::fresh(Vec::new())).unwrap();
        let mode = fs::metadata(cache_path(temp.path(), "work"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
