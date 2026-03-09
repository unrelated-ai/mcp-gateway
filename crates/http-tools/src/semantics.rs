//! HTTP semantics helpers.
//!
//! The main use-case today is generating MCP `ToolAnnotations` for HTTP-backed tools based on
//! RFC 9110-style method semantics.

use reqwest::Method;
use rmcp::model::ToolAnnotations;

/// Generate MCP tool annotations based on HTTP method semantics.
///
/// Notes:
/// - `openWorldHint` is always set to `true` for HTTP tools (they interact with an external system).
/// - For unknown/extension methods, we only set `openWorldHint` and leave the other hints unset.
#[must_use]
pub fn annotations_for_method(method: &Method) -> ToolAnnotations {
    let open_world_hint = Some(true);

    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return ToolAnnotations::from_raw(
            None,
            Some(true),
            Some(false),
            Some(true),
            open_world_hint,
        );
    }

    if method == Method::POST {
        return ToolAnnotations::from_raw(
            None,
            Some(false),
            Some(false),
            Some(false),
            open_world_hint,
        );
    }

    if method == Method::PUT {
        return ToolAnnotations::from_raw(
            None,
            Some(false),
            Some(true),
            Some(true),
            open_world_hint,
        );
    }

    if method == Method::PATCH {
        return ToolAnnotations::from_raw(
            None,
            Some(false),
            Some(true),
            // PATCH may or may not be idempotent; do not guess.
            None,
            open_world_hint,
        );
    }

    if method == Method::DELETE {
        return ToolAnnotations::from_raw(
            None,
            Some(false),
            Some(true),
            Some(true),
            open_world_hint,
        );
    }

    ToolAnnotations::from_raw(None, None, None, None, open_world_hint)
}

#[cfg(test)]
mod tests {
    use super::annotations_for_method;
    use reqwest::Method;

    #[test]
    fn annotations_set_open_world_for_all_methods() {
        for m in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ] {
            let a = annotations_for_method(&m);
            assert_eq!(a.open_world_hint, Some(true));
        }

        let custom: Method = "PROPFIND".parse().expect("valid method token");
        let a = annotations_for_method(&custom);
        assert_eq!(a.open_world_hint, Some(true));
    }

    #[test]
    fn annotations_get_is_readonly_and_idempotent() {
        let a = annotations_for_method(&Method::GET);
        assert_eq!(a.read_only_hint, Some(true));
        assert_eq!(a.destructive_hint, Some(false));
        assert_eq!(a.idempotent_hint, Some(true));
    }

    #[test]
    fn annotations_patch_leaves_idempotence_unknown() {
        let a = annotations_for_method(&Method::PATCH);
        assert_eq!(a.read_only_hint, Some(false));
        assert_eq!(a.destructive_hint, Some(true));
        assert_eq!(a.idempotent_hint, None);
    }

    #[test]
    fn annotations_unknown_method_only_sets_open_world() {
        let custom: Method = "PROPFIND".parse().expect("valid method token");
        let a = annotations_for_method(&custom);
        assert_eq!(a.read_only_hint, None);
        assert_eq!(a.destructive_hint, None);
        assert_eq!(a.idempotent_hint, None);
        assert_eq!(a.open_world_hint, Some(true));
    }
}
