use clap::{Parser, Subcommand};

pub mod doctor;
pub mod explain;
pub mod render;
pub mod report;
pub mod route;
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
    /// Print a detailed explanation for a diagnostic code (e.g. E002, W009).
    Explain(explain::ExplainArgs),
    /// Diagnose the runtime environment: ports, providers, ACME directory,
    /// privileges. Use this before `sozune serve` to catch setup issues early.
    Doctor(doctor::DoctorArgs),
    /// Explain which route of the running instance serves a URL, and why the
    /// others do not.
    Route(route::RouteArgs),
}

/// `host:port` from a listen address, IPv6 hosts unbracketed.
pub(crate) fn parse_listen_address(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), port))
}

/// `host:port`, with IPv6 hosts bracketed so the pair parses back.
pub(crate) fn socket_address(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Base URL of the API on this machine for a listen address: an instance
/// bound to every interface is reached on loopback.
pub(crate) fn local_api_url(listen_address: &str) -> Option<String> {
    let (host, port) = parse_listen_address(listen_address)?;
    let host = match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_unspecified() && ip.is_ipv4() => "127.0.0.1".to_string(),
        Ok(ip) if ip.is_unspecified() => "::1".to_string(),
        _ => host,
    };
    Some(format!("http://{}", socket_address(&host, port)))
}
