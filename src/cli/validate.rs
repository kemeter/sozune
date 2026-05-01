use clap::{Args, ValueEnum};

use crate::cli::render;
use crate::cli::report::{CandidateReport, Status, ValidationReport};
use crate::config::AppConfig;
use crate::labels::diagnostic::Severity;
use crate::labels::source::LabelSource;
use crate::labels::{self, Candidate};
use crate::provider::docker::DockerProvider;
use crate::provider::nomad::NomadProvider;
use crate::provider::podman::PodmanProvider;

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

pub async fn run(args: ValidateArgs, config_path: &str) -> anyhow::Result<i32> {
    let config = load_config(config_path).await?;
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

async fn load_config(config_path: &str) -> anyhow::Result<AppConfig> {
    if !tokio::fs::try_exists(config_path).await.unwrap_or(false) {
        return Ok(AppConfig::default());
    }
    let content = tokio::fs::read_to_string(config_path).await?;
    Ok(serde_yaml::from_str(&content)?)
}

async fn collect_candidates(
    config: &AppConfig,
    provider_filter: Option<&str>,
) -> anyhow::Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    let want = |name: &str| provider_filter.is_none_or(|p| p == name);

    if want("docker")
        && let Some(docker_cfg) = &config.providers.docker
        && docker_cfg.enabled
    {
        match DockerProvider::new(docker_cfg.clone()) {
            Ok(provider) => match provider.collect().await {
                Ok(mut cs) => candidates.append(&mut cs),
                Err(e) => eprintln!("docker: failed to collect candidates: {e}"),
            },
            Err(e) => eprintln!("docker: failed to connect: {e}"),
        }
    }

    if want("podman")
        && let Some(podman_cfg) = &config.providers.podman
        && podman_cfg.enabled
    {
        match PodmanProvider::new(podman_cfg.clone()) {
            Ok(provider) => match provider.collect().await {
                Ok(mut cs) => candidates.append(&mut cs),
                Err(e) => eprintln!("podman: failed to collect candidates: {e}"),
            },
            Err(e) => eprintln!("podman: failed to connect: {e}"),
        }
    }

    if want("nomad")
        && let Some(nomad_cfg) = &config.providers.nomad
        && nomad_cfg.enabled
    {
        match NomadProvider::new(nomad_cfg.clone()) {
            Ok(provider) => match provider.collect().await {
                Ok(mut cs) => candidates.append(&mut cs),
                Err(e) => eprintln!("nomad: failed to collect candidates: {e}"),
            },
            Err(e) => eprintln!("nomad: failed to create provider: {e}"),
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
