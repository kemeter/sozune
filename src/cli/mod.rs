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
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the proxy (default when no subcommand is given).
    Serve,
    /// Inspect what sozune would route from configured providers, with
    /// per-candidate diagnostics explaining any silent skip or fallback.
    Validate(validate::ValidateArgs),
}
