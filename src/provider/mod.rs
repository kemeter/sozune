use async_trait::async_trait;
use std::collections::BTreeMap;
use crate::model::Entrypoint;

#[async_trait]
pub trait Provider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>>;
    fn name(&self) -> &'static str;
}

pub mod docker;
pub mod config;
pub mod factory;