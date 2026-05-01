use clap::{Parser, Subcommand};

pub mod render;
pub mod report;
pub mod validate;

#[derive(Parser, Debug)]
#[command(
    name = "sozune",
    version,
    about = "Container-native HTTP/TCP/UDP proxy"
)]
pub struct Cli {
    /// Path to the configuration file. Overrides the CONFIG_PATH env var.
    #[arg(short, long, global = true, value_name = "PATH")]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Resolve the config path: CLI flag > env var > default.
pub fn resolve_config_path(cli_override: Option<&str>) -> String {
    if let Some(p) = cli_override {
        return p.to_string();
    }
    std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string())
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the proxy (default when no subcommand is given).
    Serve,
    /// Inspect what sozune would route from configured providers, with
    /// per-candidate diagnostics explaining any silent skip or fallback.
    Validate(validate::ValidateArgs),
}
