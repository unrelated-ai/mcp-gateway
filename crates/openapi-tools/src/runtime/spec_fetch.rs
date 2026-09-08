use super::{
    AuthConfig, Client, OpenApiToolSource, OpenApiToolsError, RedirectPolicy, Result, Url,
};
use unrelated_http_tools::safety::{redact_url, sanitize_reqwest_error};

impl OpenApiToolSource {
    /// Fetch the configured root document with source authentication. Redirects are handled
    /// explicitly so custom headers and query credentials cannot cross origins.
    pub(super) async fn fetch_spec(&self, mut url: Url) -> Result<reqwest::Response> {
        const MAX_REDIRECTS: usize = 10;
        let location = redact_url(&url);
        let fetch_error = |message| OpenApiToolsError::OpenApiSpecFetch {
            url: location.clone(),
            message,
        };
        let authenticated = !matches!(self.config.auth, None | Some(AuthConfig::None))
            || !url.username().is_empty()
            || url.password().is_some();
        let origin = url.origin();
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| fetch_error(sanitize_reqwest_error(&e)))?;

        for redirects in 0..=MAX_REDIRECTS {
            self.safety
                .check_url(&url)
                .await
                .map_err(|e| fetch_error(e.to_string()))?;
            if let Some(AuthConfig::Query { name, value }) = &self.config.auth {
                // Replace an existing auth parameter, including one retained by a redirect.
                let mut pairs: Vec<(String, String)> = url
                    .query_pairs()
                    .filter(|(key, _)| key != name)
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect();
                pairs.push((name.clone(), value.clone()));
                url.query_pairs_mut().clear().extend_pairs(pairs);
            }
            let response = self
                .apply_auth(client.get(url.clone()))
                .send()
                .await
                .map_err(|e| fetch_error(sanitize_reqwest_error(&e)))?;
            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }
            if !matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Err(fetch_error(format!("HTTP {status}")));
            }
            if matches!(self.safety.redirects, RedirectPolicy::None) {
                return Err(fetch_error(format!(
                    "HTTP {status}: redirects are disabled"
                )));
            }
            if redirects == MAX_REDIRECTS {
                return Err(fetch_error("too many redirects".to_string()));
            }
            let next = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| url.join(value).ok())
                .ok_or_else(|| fetch_error(format!("HTTP {status}: invalid redirect location")))?;
            if authenticated && next.origin() != origin {
                return Err(fetch_error(
                    "authenticated spec fetch cannot redirect to a different origin; configure the final spec URL explicitly".to_string(),
                ));
            }
            url = next;
        }
        unreachable!("redirect limit checked before following the last redirect")
    }
}
