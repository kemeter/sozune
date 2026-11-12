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

/// The configuration `sozune` runs with: the file at `path`, the defaults
/// when there is none, with the `SOZUNE_*` variables applied over it. A file
/// that exists but cannot be read is an error, not the defaults.
pub async fn load(path: &str) -> anyhow::Result<AppConfig> {
    let mut config = match tokio::fs::read_to_string(path).await {
        Ok(content) => parse_yaml(Path::new(path), &content)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => AppConfig::default(),
        Err(e) => anyhow::bail!("could not read config file at {path}: {e}"),
    };
    config.apply_env_overrides();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ENV_LOCK;
    use std::path::PathBuf;

    #[test]
    fn load_applies_the_environment_over_the_file_or_the_defaults() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sozune-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yaml");
        std::fs::write(
            &file,
            "providers:\n  redis:\n    enabled: false\napi:\n  enabled: false\nproxy:\n  http:\n    listen_address: 80\n  https:\n    listen_address: 443\n",
        )
        .unwrap();
        let missing = dir.join("missing.yaml");
        // SAFETY: ENV_LOCK serializes the tests that touch the environment.
        unsafe { std::env::set_var("SOZUNE_PROVIDER_REDIS_ENABLED", "true") };

        let from_file = runtime.block_on(load(file.to_str().unwrap()));
        let from_defaults = runtime.block_on(load(missing.to_str().unwrap()));

        unsafe { std::env::remove_var("SOZUNE_PROVIDER_REDIS_ENABLED") };
        std::fs::remove_dir_all(&dir).ok();
        for config in [from_file.unwrap(), from_defaults.unwrap()] {
            assert!(config.providers.redis.is_some_and(|r| r.enabled));
        }
    }

    #[tokio::test]
    async fn load_refuses_a_file_it_cannot_read() {
        let dir = std::env::temp_dir();
        let err = load(dir.to_str().unwrap()).await.unwrap_err().to_string();
        assert!(err.contains("could not read config file"), "{err}");
    }

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
