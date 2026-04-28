use clap::{Args, ValueEnum};

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Filter to a single provider (e.g. docker, file).
    #[arg(long)]
    pub provider: Option<String>,

    /// Filter to a single candidate id.
    #[arg(long)]
    pub id: Option<String>,

    /// Show only candidates that would not be routed.
    #[arg(long)]
    pub only_skipped: bool,

    /// Minimum diagnostic severity to display.
    #[arg(long, value_enum, default_value_t = SeverityFilter::Warn)]
    pub severity: SeverityFilter,

    /// Render output as a table with diagnostics inline as sub-rows.
    #[arg(long, conflicts_with_all = ["summary", "flat", "json"])]
    pub table: bool,

    /// One-line-per-candidate dense summary (codes only).
    #[arg(long, conflicts_with_all = ["table", "flat", "json"])]
    pub summary: bool,

    /// Card per candidate with horizontal rules.
    #[arg(long, conflicts_with_all = ["table", "summary", "json"])]
    pub flat: bool,

    /// Machine-readable JSON output for CI / scripts.
    #[arg(long, conflicts_with_all = ["table", "summary", "flat"])]
    pub json: bool,

    /// Re-validate on provider events (Docker events, file changes).
    #[arg(long)]
    pub watch: bool,

    /// Print documentation for a diagnostic code (e.g. W009) and exit.
    #[arg(long, value_name = "CODE")]
    pub explain: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum SeverityFilter {
    Error,
    Warn,
    Info,
}

pub async fn run(_args: ValidateArgs) -> anyhow::Result<i32> {
    eprintln!("sozune validate is not yet implemented");
    Ok(2)
}
