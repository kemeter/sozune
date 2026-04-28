use super::candidate::Candidate;
use anyhow::Result;
use async_trait::async_trait;

/// Implemented by providers that discover routing configuration through
/// labels/tags/annotations (Docker, Nomad, Kubernetes). Providers that
/// produce already-parsed entrypoints (file, http) do not implement this
/// trait — they bypass the label parser entirely.
#[async_trait]
pub trait LabelSource: Send + Sync {
    fn provider_name(&self) -> &'static str;

    /// Produce one `Candidate` per discoverable unit (container, job, pod).
    async fn collect(&self) -> Result<Vec<Candidate>>;
}
