use crate::model::Entrypoint;
use async_trait::async_trait;
use std::collections::BTreeMap;

#[async_trait]
pub trait Provider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>>;
    fn name(&self) -> &'static str;
}

pub mod config;
pub mod docker;
pub mod factory;
