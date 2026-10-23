//! `status.loadBalancer` of the Ingresses Sōzune serves.
//!
//! Tools that wait on an Ingress — external-dns creating its DNS record, a
//! GitOps tool calling it healthy — read the address it is reachable at from
//! its status. Sōzune writes there the addresses `publish_addresses` lists,
//! or those of the Service `publish_service` names, kept up to date as that
//! Service's load balancer gets or changes its address.

use super::{KubernetesProvider, ingress_id};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::{Ingress, IngressLoadBalancerIngress};
use kube::api::{Patch, PatchParams};
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// The addresses to publish, from `publish_addresses`: an IP as `ip`,
/// anything else as `hostname`.
pub(super) fn addresses_from_config(addresses: &[String]) -> Vec<IngressLoadBalancerIngress> {
    addresses
        .iter()
        .map(|a| a.trim())
        .filter(|a| !a.is_empty())
        .map(|a| match a.parse::<IpAddr>() {
            Ok(_) => IngressLoadBalancerIngress {
                ip: Some(a.to_string()),
                ..Default::default()
            },
            Err(_) => IngressLoadBalancerIngress {
                hostname: Some(a.to_string()),
                ..Default::default()
            },
        })
        .collect()
}

/// The addresses a Service's load balancer was given.
pub(super) fn addresses_of_service(service: &Service) -> Vec<IngressLoadBalancerIngress> {
    service
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .into_iter()
        .flatten()
        .map(|i| IngressLoadBalancerIngress {
            ip: i.ip.clone(),
            hostname: i.hostname.clone(),
            ..Default::default()
        })
        .collect()
}

/// What an Ingress's status says it is reachable at.
fn published_on(ing: &Ingress) -> Vec<IngressLoadBalancerIngress> {
    ing.status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.clone())
        .unwrap_or_default()
}

/// How often status writes that failed are tried again.
const STATUS_RETRY: Duration = Duration::from_secs(30);

/// Write `addresses` to the status of the Ingress `namespace/name`. Returns
/// whether the API server took it.
async fn write_status(
    client: &Client,
    namespace: &str,
    name: &str,
    addresses: &[IngressLoadBalancerIngress],
) -> bool {
    let api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({ "status": { "loadBalancer": { "ingress": addresses } } });
    match api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => {
            debug!(
                "Ingress {}/{}: status.loadBalancer written",
                namespace, name
            );
            true
        }
        Err(e) => {
            warn!(
                "Ingress {}/{}: could not write status.loadBalancer, trying again shortly (does the RBAC allow ingresses/status?): {}",
                namespace, name, e
            );
            false
        }
    }
}

impl KubernetesProvider {
    /// The addresses to publish, or `None` when publishing is not set up,
    /// or waits for the published Service to be seen.
    fn published_addresses(&self) -> Option<Vec<IngressLoadBalancerIngress>> {
        self.published.read().ok()?.clone()
    }

    /// Queue the status of an Ingress Sōzune serves for writing, when it
    /// says something else than the published addresses. Written by
    /// [`Self::write_statuses`], off the Ingress watch loop.
    pub(super) fn queue_ingress_status(&self, ing: &Ingress) {
        let Some(addresses) = self.published_addresses() else {
            return;
        };
        let Some(ing_id) = ingress_id(ing) else {
            return;
        };
        if !self.serves_ingress(&ing_id) || published_on(ing) == addresses {
            return;
        }
        self.queue_status(ing_id);
    }

    fn queue_status(&self, ing_id: String) {
        if let Ok(mut pending) = self.status_pending.lock() {
            pending.insert(ing_id);
        }
        self.status_wake.notify_one();
    }

    /// Write the queued statuses, as they are queued and, for those whose
    /// write failed, again every [`STATUS_RETRY`]: nothing else would, for an
    /// Ingress that does not change.
    pub(super) async fn write_statuses(self: Arc<Self>, client: Client) {
        let mut tick = tokio::time::interval(STATUS_RETRY);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = self.status_wake.notified() => {}
            }
            let Some(addresses) = self.published_addresses() else {
                continue;
            };
            // Taken out before writing: an Ingress queued again meanwhile,
            // for a newer address, stays queued.
            let pending: Vec<String> = self
                .status_pending
                .lock()
                .map(|mut p| p.drain().collect())
                .unwrap_or_default();
            for ing_id in pending {
                if !self.serves_ingress(&ing_id) {
                    continue;
                }
                let Some((namespace, name)) = ing_id.split_once('/') else {
                    continue;
                };
                if !write_status(&client, namespace, name, &addresses).await
                    && let Ok(mut p) = self.status_pending.lock()
                {
                    p.insert(ing_id);
                }
            }
        }
    }

    /// Whether Sōzune serves a route of the Ingress `namespace/name`.
    fn serves_ingress(&self, ing_id: &str) -> bool {
        self.ingress_keys
            .read()
            .is_ok_and(|owned| owned.get(ing_id).is_some_and(|keys| !keys.is_empty()))
    }

    /// Follow the address of the `publish_service` Service, and write it to
    /// every Ingress Sōzune serves when it changes.
    pub(super) async fn watch_published_service(self: Arc<Self>, client: Client) {
        let Some((namespace, name)) = self.config.publish_service.split_once('/') else {
            warn!(
                "providers.kubernetes.publish_service `{}` is not `namespace/name`: Ingress status is not written",
                self.config.publish_service
            );
            return;
        };
        let api: Api<Service> = Api::namespaced(client.clone(), namespace);
        let config = watcher::Config::default().fields(&format!("metadata.name={name}"));
        let mut stream = watcher::watcher(api, config).default_backoff().boxed();
        info!(
            "Publishing the address of Service {}/{} in Ingress status",
            namespace, name
        );

        // Whether the relist under way brought the Service back: one deleted
        // while the watch was down sends no `Delete`.
        let mut relisted = false;
        while let Some(event) = stream.next().await {
            let addresses = match event {
                Ok(Event::Apply(svc)) | Ok(Event::InitApply(svc)) => {
                    relisted = true;
                    addresses_of_service(&svc)
                }
                Ok(Event::Delete(_)) => Vec::new(),
                Ok(Event::Init) => {
                    relisted = false;
                    continue;
                }
                Ok(Event::InitDone) if relisted => continue,
                Ok(Event::InitDone) => Vec::new(),
                Err(e) => {
                    warn!(
                        "Could not watch Service {}/{} for Ingress status: {}",
                        namespace, name, e
                    );
                    continue;
                }
            };
            let changed = match self.published.write() {
                Ok(mut published) if published.as_ref() != Some(&addresses) => {
                    *published = Some(addresses.clone());
                    true
                }
                _ => false,
            };
            if changed {
                self.republish_all();
            }
        }
    }

    /// Queue the status of every Ingress Sōzune serves for writing.
    fn republish_all(&self) {
        let served: Vec<String> = self
            .ingress_keys
            .read()
            .map(|owned| owned.keys().cloned().collect())
            .unwrap_or_default();
        for ing_id in served {
            if self.serves_ingress(&ing_id) {
                self.queue_status(ing_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{LoadBalancerIngress, LoadBalancerStatus, ServiceStatus};

    /// The status of a served Ingress is queued when it says something
    /// else than the published addresses, and only then.
    #[test]
    fn a_served_ingress_with_another_status_is_queued() {
        use k8s_openapi::api::networking::v1::{IngressLoadBalancerStatus, IngressStatus};

        let config = crate::config::KubernetesConfig {
            enabled: true,
            publish_addresses: vec!["192.0.2.10".into()],
            ..Default::default()
        };
        let provider = KubernetesProvider::new(config).unwrap();
        let mut ing = Ingress::default();
        ing.metadata.namespace = Some("default".into());
        ing.metadata.name = Some("web".into());
        let queued = |provider: &KubernetesProvider| {
            provider
                .status_pending
                .lock()
                .unwrap()
                .contains("default/web")
        };

        // Not served: left alone.
        provider.queue_ingress_status(&ing);
        assert!(!queued(&provider));

        provider.ingress_keys.write().unwrap().insert(
            "default/web".into(),
            std::collections::HashSet::from(["ingress_default-web_r0p0".to_string()]),
        );
        ing.status = Some(IngressStatus {
            load_balancer: Some(IngressLoadBalancerStatus {
                ingress: Some(addresses_from_config(&["192.0.2.10".into()])),
            }),
        });
        provider.queue_ingress_status(&ing);
        assert!(!queued(&provider));

        ing.status = None;
        provider.queue_ingress_status(&ing);
        assert!(queued(&provider));
    }

    #[test]
    fn configured_addresses_split_ips_from_hostnames() {
        let addresses = addresses_from_config(&[
            "203.0.113.10".into(),
            "2001:db8::1".into(),
            "lb.example.com".into(),
            " ".into(),
        ]);
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0].ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(addresses[1].ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(addresses[2].hostname.as_deref(), Some("lb.example.com"));
    }

    #[test]
    fn a_service_publishes_its_load_balancer_addresses() {
        let mut service = Service::default();
        assert!(addresses_of_service(&service).is_empty());
        service.status = Some(ServiceStatus {
            load_balancer: Some(LoadBalancerStatus {
                ingress: Some(vec![
                    LoadBalancerIngress {
                        ip: Some("198.51.100.7".into()),
                        ..Default::default()
                    },
                    LoadBalancerIngress {
                        hostname: Some("abc.elb.example.com".into()),
                        ..Default::default()
                    },
                ]),
            }),
            ..Default::default()
        });
        let addresses = addresses_of_service(&service);
        assert_eq!(addresses[0].ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(
            addresses[1].hostname.as_deref(),
            Some("abc.elb.example.com")
        );
    }
}
