//! Pure helpers shared by Orion's build script and its regression tests.

use serde_json::{Map, Value};

/// Overrides bundle resources while preserving every other Tauri CLI override.
///
/// `tauri-build` copies bundle resources even for a debug-only Cargo build.
/// Those files are intentionally absent from Git, so plain debug compilation
/// must not depend on them when the Tauri preparation hook has not run.
pub fn without_bundle_resources(existing: Option<&str>) -> Result<String, String> {
    let mut config = match existing {
        Some(existing) => serde_json::from_str::<Value>(existing)
            .map_err(|error| format!("invalid TAURI_CONFIG: {error}"))?,
        None => Value::Object(Map::new()),
    };
    let root = config
        .as_object_mut()
        .ok_or_else(|| "TAURI_CONFIG must be a JSON object".to_owned())?;
    let bundle = root
        .entry("bundle")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "TAURI_CONFIG.bundle must be a JSON object".to_owned())?;
    bundle.insert("resources".to_owned(), Value::Array(Vec::new()));

    serde_json::to_string(&config).map_err(|error| format!("serializing TAURI_CONFIG: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_override_removes_resources_and_preserves_cli_configuration() {
        let config = without_bundle_resources(Some(
            r#"{"productName":"Test Orion","bundle":{"active":false,"resources":{"missing":"x"}}}"#,
        ))
        .unwrap();
        let config: Value = serde_json::from_str(&config).unwrap();

        assert_eq!(config["productName"], "Test Orion");
        assert_eq!(config["bundle"]["active"], false);
        assert_eq!(config["bundle"]["resources"], Value::Array(Vec::new()));
    }

    #[test]
    fn debug_override_builds_an_object_when_no_cli_configuration_exists() {
        let config = without_bundle_resources(None).unwrap();
        let config: Value = serde_json::from_str(&config).unwrap();

        assert_eq!(config["bundle"]["resources"], Value::Array(Vec::new()));
    }
}
