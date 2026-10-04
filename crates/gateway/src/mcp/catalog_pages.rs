//! Shared bounds and cursor handling for client and management catalog reads.
use rmcp::model::ServerResult;
use std::{collections::HashSet, future::Future};

const MAX_PAGES: usize = 64;
const MAX_ITEMS: usize = 100_000;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct CatalogLimit(pub &'static str);

pub(super) async fn collect<T, F, Fut, E>(mut fetch: F, extract: E) -> anyhow::Result<Vec<T>>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = anyhow::Result<ServerResult>>,
    E: Fn(ServerResult) -> Option<(Vec<T>, Option<String>)>,
{
    let mut cursor = None;
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for _ in 0..MAX_PAGES {
        let result = fetch(cursor).await?;
        let (page, next) =
            extract(result).ok_or_else(|| anyhow::anyhow!("Unexpected catalog response"))?;
        items.extend(page);
        if items.len() > MAX_ITEMS {
            return Err(CatalogLimit("upstream catalog exceeds item limit").into());
        }
        let Some(next) = next else {
            return Ok(items);
        };
        if !seen.insert(next.clone()) {
            return Err(CatalogLimit("upstream repeated a catalog cursor").into());
        }
        cursor = Some(next);
    }
    Err(CatalogLimit("upstream catalog exceeds page limit").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ListToolsResult;

    #[tokio::test]
    async fn rejects_repeated_cursors_and_catalogs_that_never_end() {
        for repeat in [true, false] {
            let error = collect(
                |cursor: Option<String>| async move {
                    let number = cursor
                        .and_then(|value| value.parse::<u32>().ok())
                        .unwrap_or(0);
                    Ok(ServerResult::ListToolsResult(ListToolsResult {
                        next_cursor: Some(if repeat {
                            "1".into()
                        } else {
                            (number + 1).to_string()
                        }),
                        ..Default::default()
                    }))
                },
                |result| match result {
                    ServerResult::ListToolsResult(r) => Some((r.tools, r.next_cursor)),
                    _ => None,
                },
            )
            .await
            .unwrap_err();
            assert!(error.is::<CatalogLimit>());
            assert!(
                error
                    .to_string()
                    .contains(if repeat { "repeated" } else { "page limit" })
            );
        }
    }

    #[tokio::test]
    async fn rejects_oversized_catalogs() {
        let error = collect(
            |_| async { Ok(ServerResult::ListToolsResult(ListToolsResult::default())) },
            |_| Some((vec![(); MAX_ITEMS + 1], None)),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("item limit"));
    }
}
