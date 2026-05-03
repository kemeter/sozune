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

    apply_collection_lints(&mut report);

    if let Some(id) = &args.id {
        report
            .candidates
            .retain(|c| c.id == *id || c.display_name == *id);
    }
    if args.only_skipped {
        report.candidates.retain(|c| c.status == Status::Skipped);
    }

    let min_severity = args.severity.to_severity();

    if let Some(diag) = global_acme_lint(&config, &report) {
        println!("global");
        println!("├─ ⚠ {}", diag.message);
        if let Some(hint) = &diag.hint {
            println!("│      → {hint}");
        }
        println!();
    }

    let output = render::tree::render(&report, min_severity);
    print!("{output}");

    Ok(exit_code(&report))
}

/// Run cross-cutting lints (collisions) and attach the resulting diagnostics
/// to the candidates that own the offending routes.
fn apply_collection_lints(report: &mut ValidationReport) {
    let pairs: Vec<(&str, &crate::model::Entrypoint)> = report
        .candidates
        .iter()
        .flat_map(|c| {
            let id = c.id.as_str();
            c.entrypoints.values().map(move |ep| (id, ep))
        })
        .collect();

    let extra = crate::labels::lint::lint_collection(&pairs);

    for (cand_id, diag) in extra {
        if let Some(c) = report.candidates.iter_mut().find(|c| c.id == cand_id) {
            c.diagnostics.push(diag);
        }
    }
}

/// Detect ACME-enabled-but-no-TLS as a global warning.
fn global_acme_lint(
    config: &AppConfig,
    report: &ValidationReport,
) -> Option<crate::labels::diagnostic::Diagnostic> {
    let acme_on = config.acme.as_ref().is_some_and(|a| a.enabled);
    let all_eps: Vec<&crate::model::Entrypoint> = report
        .candidates
        .iter()
        .flat_map(|c| c.entrypoints.values())
        .collect();
    crate::labels::lint::lint_acme_without_tls(acme_on, &all_eps)
}

async fn load_config(config_path: &str) -> anyhow::Result<AppConfig> {
    if !tokio::fs::try_exists(config_path).await.unwrap_or(false) {
        return Ok(AppConfig::default());
    }
    let content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| anyhow::anyhow!("could not read config file at {config_path}: {e}"))?;
    crate::config_load::parse_yaml(std::path::Path::new(config_path), &content)
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
                Err(e) => eprintln!(
                    "docker: could not list containers: {e}\n  → check that the Docker daemon is running and that the socket is readable (try: `docker ps`)"
                ),
            },
            Err(e) => eprintln!(
                "docker: could not connect: {e}\n  → check the endpoint in providers.docker.endpoint (default: unix:///var/run/docker.sock) and that the user has access to it"
            ),
        }
    }

    if want("podman")
        && let Some(podman_cfg) = &config.providers.podman
        && podman_cfg.enabled
    {
        match PodmanProvider::new(podman_cfg.clone()) {
            Ok(provider) => match provider.collect().await {
                Ok(mut cs) => candidates.append(&mut cs),
                Err(e) => eprintln!(
                    "podman: could not list containers: {e}\n  → check that the Podman API socket is running (try: `systemctl --user start podman.socket`)"
                ),
            },
            Err(e) => eprintln!(
                "podman: could not connect: {e}\n  → check the endpoint in providers.podman.endpoint and that the API socket is enabled"
            ),
        }
    }

    if want("nomad")
        && let Some(nomad_cfg) = &config.providers.nomad
        && nomad_cfg.enabled
    {
        match NomadProvider::new(nomad_cfg.clone()) {
            Ok(provider) => match provider.collect().await {
                Ok(mut cs) => candidates.append(&mut cs),
                Err(e) => eprintln!(
                    "nomad: could not list services: {e}\n  → check the address in providers.nomad.address (default: http://127.0.0.1:4646) and that the agent is reachable"
                ),
            },
            Err(e) => eprintln!(
                "nomad: invalid configuration: {e}\n  → check providers.nomad.address and providers.nomad.token in the config file"
            ),
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
