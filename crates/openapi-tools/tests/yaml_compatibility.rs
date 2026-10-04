use serde_json::{Value, json};

#[test]
fn config_yaml_preserves_aliases_nulls_unicode_and_literal_secrets() {
    let yaml = r#"
defaults: &defaults
  timeout: 30
  enabled: true
  unset: null
  secret: "${secret:api-token}"
  path: "C:\\notes\\file"
copy: *defaults
strings: ["0123", "false", "café ☕", "${ENV_VAR}"]
multiline: |
  first line
  second line
"#;
    let defaults = json!({
        "timeout": 30,
        "enabled": true,
        "unset": null,
        "secret": "${secret:api-token}",
        "path": "C:\\notes\\file"
    });
    let expected = json!({
        "defaults": defaults,
        "copy": defaults,
        "strings": ["0123", "false", "café ☕", "${ENV_VAR}"],
        "multiline": "first line\nsecond line\n"
    });
    let parsed: Value = serde_saphyr::from_str(yaml).unwrap();
    assert_eq!(parsed, expected);
    let emitted = serde_saphyr::to_string(&parsed).unwrap();
    assert_eq!(serde_saphyr::from_str::<Value>(&emitted).unwrap(), expected);
    assert!(serde_saphyr::from_str::<Value>("key: first\nkey: second\n").is_err());
}

#[test]
fn checked_in_openapi_fixture_parses_as_yaml_and_json() {
    let spec: openapiv3::OpenAPI = serde_saphyr::from_str(include_str!(
        "../../../tests/fixtures/openapi-mini-spec.yaml"
    ))
    .unwrap();
    let json = serde_json::to_string(&spec).unwrap();
    let from_json: openapiv3::OpenAPI = serde_saphyr::from_str(&json).unwrap();
    assert_eq!(
        serde_json::to_value(spec).unwrap(),
        serde_json::to_value(from_json).unwrap()
    );
}
