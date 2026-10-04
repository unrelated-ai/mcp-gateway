//! HTTP contracts shared without coupling clients to the Gateway runtime.
pub mod audit;
pub mod error;
pub mod routes;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// A router template with a compile-time parameter count.
#[derive(Clone, Copy, Debug)]
pub struct Route<const N: usize> {
    template: &'static str,
}

#[derive(Debug, thiserror::Error)]
#[error("route parameters must not be empty or dot segments")]
pub struct InvalidPathParameter;

impl<const N: usize> Route<N> {
    const fn new(template: &'static str) -> Self {
        let bytes = template.as_bytes();
        let mut count = 0;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'{' {
                count += 1;
            }
            i += 1;
        }
        assert!(count == N, "route parameter count mismatch");
        Self { template }
    }

    /// Axum route pattern, also used to name routes in audit records.
    #[must_use]
    pub const fn template(self) -> &'static str {
        self.template
    }

    /// Encode each identifier as one path segment, preserving reserved characters.
    ///
    /// # Errors
    /// Rejects empty and dot segments, which URL parsers otherwise normalize.
    pub fn bind(self, parameters: [&str; N]) -> Result<String, InvalidPathParameter> {
        let mut path = String::with_capacity(self.template.len());
        let mut remaining = self.template;
        for value in parameters {
            if matches!(value, "" | "." | "..") {
                return Err(InvalidPathParameter);
            }
            let (prefix, placeholder) = remaining.split_once('{').ok_or(InvalidPathParameter)?;
            let (_, suffix) = placeholder.split_once('}').ok_or(InvalidPathParameter)?;
            path.push_str(prefix);
            path.extend(utf8_percent_encode(value, PATH_SEGMENT));
            remaining = suffix;
        }
        path.push_str(remaining);
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_cannot_change_route_structure_or_query() {
        let path = routes::admin::SECRET.bind(["a/b", "café ?#%\\"]).unwrap();
        assert_eq!(
            path,
            "/admin/v1/tenants/a%2Fb/secrets/caf%C3%A9%20%3F%23%25%5C"
        );
        let url = url::Url::parse("https://gateway.example")
            .unwrap()
            .join(&path)
            .unwrap();
        assert_eq!(url.path(), path);
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
        for invalid in ["", ".", ".."] {
            assert!(routes::admin::TENANT.bind([invalid]).is_err());
        }
        assert_eq!(
            routes::admin::TENANT.bind(["%2e%2e"]).unwrap(),
            "/admin/v1/tenants/%252e%252e"
        );
    }
}
