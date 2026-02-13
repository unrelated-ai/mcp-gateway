//! Small helper functions for Serde derives.
//!
//! Serde attributes like `#[serde(default = "...")]` require a function path (not a literal),
//! which is why we centralize common defaults here.

/// Default a boolean field to `true`.
///
/// Used with `#[serde(default = "crate::serde_helpers::default_true")]`.
pub(crate) const fn default_true() -> bool {
    true
}
