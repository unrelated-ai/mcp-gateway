use std::collections::HashSet;

/// Parse a boolean-like env var.
///
/// Truthy values (case-insensitive): `1`, `true`, `yes`, `y`, `on`.
#[must_use]
pub fn flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "y" | "on"
    )
}

/// Read an env var and split by comma into a non-empty lowercase set.
#[must_use]
pub fn csv_set_lower(name: &str) -> Option<HashSet<String>> {
    let raw = std::env::var(name).ok()?;
    let set: HashSet<String> = raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    (!set.is_empty()).then_some(set)
}

/// Parse a positive (`> 0`) u64 env var.
#[must_use]
pub fn positive_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
}

/// Expand `${VAR}` occurrences in a string using environment variables.
///
/// Returns an error if a referenced env var is missing.
///
/// # Errors
///
/// Returns `Err(...)` when a referenced environment variable is not set.
pub fn expand_env_string(s: &str) -> Result<String, String> {
    let mut result = s.to_string();
    let mut start = 0usize;

    while let Some(dollar_pos) = result[start..].find("${") {
        let abs_pos = start + dollar_pos;
        if let Some(end_pos) = result[abs_pos..].find('}') {
            let var_name = &result[abs_pos + 2..abs_pos + end_pos];
            let var_value = std::env::var(var_name).map_err(|_| {
                format!("Environment variable '{var_name}' not found (referenced in config)")
            })?;
            result = format!(
                "{}{}{}",
                &result[..abs_pos],
                var_value,
                &result[abs_pos + end_pos + 1..]
            );
            start = abs_pos + var_value.len();
        } else {
            start = abs_pos + 2;
        }
    }

    Ok(result)
}

pub mod serde_helpers {
    use super::expand_env_string;
    use serde::{Deserialize, Deserializer};

    /// Deserialize `Option<u64>` that may reference `${ENV}` inside a string.
    ///
    /// Supported JSON forms: `null`, number, or string.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a number/string, when env expansion fails, or when
    /// parsing the expanded string as `u64` fails.
    pub fn deserialize_option_u64_env<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as DeError;

        let value = Option::<serde_json::Value>::deserialize(deserializer)?;
        match value {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Number(n)) => n
                .as_u64()
                .map(Some)
                .ok_or_else(|| D::Error::custom("expected unsigned integer")),
            Some(serde_json::Value::String(s)) => {
                let expanded = expand_env_string(&s).map_err(D::Error::custom)?;
                let expanded = expanded.trim();
                let n = expanded.parse::<u64>().map_err(|e| {
                    D::Error::custom(format!("expected unsigned integer, got '{expanded}': {e}"))
                })?;
                Ok(Some(n))
            }
            Some(other) => Err(D::Error::custom(format!(
                "expected unsigned integer or string, got {other}"
            ))),
        }
    }

    /// Deserialize `Option<bool>` that may reference `${ENV}` inside a string.
    ///
    /// Supported JSON forms: `null`, boolean, or string.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a boolean/string, or when env expansion fails, or
    /// when the expanded string is not a supported boolean literal.
    pub fn deserialize_option_bool_env<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as DeError;

        let value = Option::<serde_json::Value>::deserialize(deserializer)?;
        match value {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
            Some(serde_json::Value::String(s)) => {
                let expanded = expand_env_string(&s).map_err(D::Error::custom)?;
                let expanded = expanded.trim().to_lowercase();
                match expanded.as_str() {
                    "true" | "1" | "yes" | "y" | "on" => Ok(Some(true)),
                    "false" | "0" | "no" | "n" | "off" => Ok(Some(false)),
                    _ => Err(D::Error::custom(format!(
                        "expected boolean, got '{expanded}'"
                    ))),
                }
            }
            Some(other) => Err(D::Error::custom(format!(
                "expected boolean or string, got {other}"
            ))),
        }
    }
}
