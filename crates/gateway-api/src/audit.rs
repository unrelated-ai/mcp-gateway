//! Audit settings and inheritance shared by management APIs and the audit writer.
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    Off,
    Summary,
    #[default]
    Metadata,
    Payload,
}

impl std::str::FromStr for AuditLevel {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "summary" => Ok(Self::Summary),
            "metadata" => Ok(Self::Metadata),
            "payload" => Ok(Self::Payload),
            _ => Err("invalid audit level (allowed: off|summary|metadata|payload)"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "std::collections::BTreeMap<String, Option<AuditLevel>>")]
pub struct ProfileAuditSettings {
    /// Missing or null inherits the tenant default. Retention stays tenant-wide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<AuditLevel>,
}

// Require an object: deriving struct deserialization alone also accepts positional arrays.
impl TryFrom<std::collections::BTreeMap<String, Option<AuditLevel>>> for ProfileAuditSettings {
    type Error = &'static str;

    fn try_from(
        mut fields: std::collections::BTreeMap<String, Option<AuditLevel>>,
    ) -> Result<Self, Self::Error> {
        let level = fields.remove("level").flatten();
        if !fields.is_empty() {
            return Err("unsupported profile audit setting (allowed: level)");
        }
        Ok(Self { level })
    }
}

impl ProfileAuditSettings {
    #[must_use]
    pub fn effective_level(self, tenant_enabled: bool, tenant_level: AuditLevel) -> AuditLevel {
        if !tenant_enabled || tenant_level == AuditLevel::Off {
            AuditLevel::Off
        } else {
            self.level.unwrap_or(tenant_level)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantAuditDefaults {
    pub enabled: bool,
    pub default_level: AuditLevel,
    pub retention_days: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileAuditSettingsResponse {
    pub audit_settings: ProfileAuditSettings,
    pub revision: i64,
    pub tenant_settings: TenantAuditDefaults,
    pub effective_level: AuditLevel,
    /// Previously stored arbitrary JSON does not become an active policy.
    pub has_unrecognized_settings: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn overrides_inherit_and_cannot_bypass_the_tenant_master_switch() {
        let levels = [
            AuditLevel::Off,
            AuditLevel::Summary,
            AuditLevel::Metadata,
            AuditLevel::Payload,
        ];
        for tenant in levels {
            for setting in [
                None,
                Some(AuditLevel::Off),
                Some(AuditLevel::Summary),
                Some(AuditLevel::Metadata),
                Some(AuditLevel::Payload),
            ] {
                let profile = ProfileAuditSettings { level: setting };
                assert_eq!(profile.effective_level(false, tenant), AuditLevel::Off);
                let expected = if tenant == AuditLevel::Off {
                    AuditLevel::Off
                } else {
                    setting.unwrap_or(tenant)
                };
                assert_eq!(profile.effective_level(true, tenant), expected);
            }
        }
    }

    #[test]
    fn accepts_inheritance_and_rejects_unsupported_fields_or_levels() {
        for input in [json!({}), json!({"level":null})] {
            assert_eq!(
                serde_json::from_value::<ProfileAuditSettings>(input).unwrap(),
                ProfileAuditSettings::default()
            );
        }
        for input in [
            json!({"level":"verbose"}),
            json!({"retentionDays":7}),
            json!({"enabled":true}),
            json!([]),
        ] {
            assert!(serde_json::from_value::<ProfileAuditSettings>(input).is_err());
        }
    }
}
