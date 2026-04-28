use clap::{Args, ValueEnum};

use crate::cli::render;
use crate::cli::report::{CandidateReport, Status, ValidationReport};
use crate::config::AppConfig;
use crate::labels::diagnostic::Severity;
use crate::labels::source::LabelSource;
use crate::labels::{self, Candidate};
use crate::provider::docker::DockerProvider;

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
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum SeverityFilter {
    Error,
    Warn,
    Info,
}

impl SeverityFilter {
    fn to_severity(self) -> Severity {
        match self {
            SeverityFilter::Error => Severity::Error,
            SeverityFilter::Warn => Severity::Warn,
            SeverityFilter::Info => Severity::Info,
        }
    }
}

pub async fn run(args: ValidateArgs) -> anyhow::Result<i32> {
    let config = load_config().await?;
    let candidates = collect_candidates(&config, args.provider.as_deref()).await?;
    let mut report = build_report(candidates);

    if let Some(id) = &args.id {
        report
            .candidates
            .retain(|c| c.id == *id || c.display_name == *id);
    }
    if args.only_skipped {
        report.candidates.retain(|c| c.status == Status::Skipped);
    }

    let min_severity = args.severity.to_severity();
    let output = render::tree::render(&report, min_severity);
    print!("{output}");

    Ok(exit_code(&report))
}

async fn load_config() -> anyhow::Result<AppConfig> {
    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());

    if !tokio::fs::try_exists(&config_path).await.unwrap_or(false) {
        return Ok(AppConfig::default());
    }
    let content = tokio::fs::read_to_string(&config_path).await?;
    Ok(serde_yaml::from_str(&content)?)
}

async fn collect_candidates(
    config: &AppConfig,
    provider_filter: Option<&str>,
) -> anyhow::Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    let want = |name: &str| provider_filter.map_or(true, |p| p == name);

    if want("docker") {
        if let Some(docker_cfg) = &config.providers.docker {
            if docker_cfg.enabled {
                match DockerProvider::new(docker_cfg.clone()) {
                    Ok(provider) => match provider.collect().await {
                        Ok(mut cs) => candidates.append(&mut cs),
                        Err(e) => eprintln!("docker: failed to collect candidates: {e}"),
                    },
                    Err(e) => eprintln!("docker: failed to connect: {e}"),
                }
            }
        }
    }

    Ok(candidates)
}

fn build_report(candidates: Vec<Candidate>) -> ValidationReport {
    let candidates = candidates
        .into_iter()
        .map(|c| {
            let r = labels::parse(&c);
            CandidateReport::from_parse(&c, r.entrypoints, r.diagnostics)
        })
        .collect();
    ValidationReport { candidates }
}

fn exit_code(report: &ValidationReport) -> i32 {
    if report
        .candidates
        .iter()
        .any(|c| c.status == Status::Skipped)
    {
        1
    } else {
        0
    }
}
