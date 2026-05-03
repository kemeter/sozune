use std::path::Path;

use crate::config::AppConfig;

/// Parse a YAML config string into `AppConfig`, mapping serde errors to a
/// human-readable message that includes the file path, line, and column.
///
/// `path` is purely cosmetic (used in the error message).
pub fn parse_yaml(path: &Path, content: &str) -> anyhow::Result<AppConfig> {
    serde_yaml::from_str::<AppConfig>(content).map_err(|e| {
        let display = path.display();
        let location = e
            .location()
            .map(|l| format!("{}:{}:{}", display, l.line(), l.column()))
            .unwrap_or_else(|| format!("{display}"));
        anyhow::anyhow!("config error at {location}: {e}\n  → check the YAML syntax and the field names against the documentation")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn bad_yaml_includes_path_and_location() {
        let p = PathBuf::from("/etc/sozune/config.yaml");
        let bad = "providers:\n  docker:\n    enabled: oui\n";
        let err = parse_yaml(&p, bad).unwrap_err().to_string();
        assert!(err.contains("/etc/sozune/config.yaml"), "got: {err}");
        // serde_yaml reports the column where the bad value sits.
        assert!(err.contains("config error at"), "got: {err}");
    }

    #[test]
    fn syntax_error_reports_line() {
        let p = PathBuf::from("config.yaml");
        let bad = "providers:\n  docker:\n  - bad\n";
        let err = parse_yaml(&p, bad).unwrap_err().to_string();
        assert!(err.contains("config error at"), "got: {err}");
    }

    #[test]
    fn missing_field_error_is_friendly() {
        let p = PathBuf::from("config.yaml");
        let err = parse_yaml(&p, "{}").unwrap_err().to_string();
        assert!(err.contains("config error at"), "got: {err}");
    }
}
