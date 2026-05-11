//! ACME-related Sōzu commands: register the loopback cluster that fronts
//! sōzune's HTTP-01 challenge responder, and push freshly-issued certificates
//! to the HTTPS worker.

use super::channel::send_to_worker;
use sozu_command_lib::{
    channel::Channel,
    proto::command::{
        AddBackend, AddCertificate, CertificateAndKey, Cluster, LoadBalancingAlgorithms,
        LoadBalancingParams, SocketAddress, TlsVersion, WorkerRequest, WorkerResponse,
        request::RequestType,
    },
};
use tracing::info;

pub(super) fn register_acme_challenge_cluster(
    command_channel: &mut Channel<WorkerRequest, WorkerResponse>,
    challenge_port: u16,
) -> anyhow::Result<()> {
    let cluster_id = "acme-challenge".to_string();

    let cluster = Cluster {
        cluster_id: cluster_id.clone(),
        sticky_session: false,
        https_redirect: false,
        proxy_protocol: None,
        load_balancing: LoadBalancingAlgorithms::RoundRobin as i32,
        load_metric: None,
        answer_503: None,
        http2: None,
        ..Default::default()
    };

    send_to_worker(
        command_channel,
        "add-cluster-acme-challenge".to_string(),
        RequestType::AddCluster(cluster),
    )?;

    let backend = AddBackend {
        cluster_id: cluster_id.clone(),
        backend_id: "acme-challenge-backend-0".to_string(),
        address: SocketAddress::new_v4(127, 0, 0, 1, challenge_port),
        load_balancing_parameters: Some(LoadBalancingParams { weight: 100 }),
        sticky_id: None,
        backup: None,
    };

    send_to_worker(
        command_channel,
        "add-backend-acme-challenge".to_string(),
        RequestType::AddBackend(backend),
    )?;

    info!(
        "ACME challenge cluster registered -> 127.0.0.1:{}",
        challenge_port
    );
    Ok(())
}

/// Send an AddCertificate command to the HTTPS worker.
pub(super) fn add_certificate(
    command_channel_https: &mut Channel<WorkerRequest, WorkerResponse>,
    https_port: u16,
    cert_pem: &str,
    chain: &[String],
    key_pem: &str,
    names: &[String],
) -> anyhow::Result<()> {
    let cert = AddCertificate {
        address: SocketAddress::new_v4(0, 0, 0, 0, https_port),
        certificate: CertificateAndKey {
            certificate: cert_pem.to_string(),
            certificate_chain: chain.to_vec(),
            key: key_pem.to_string(),
            versions: vec![TlsVersion::TlsV12 as i32, TlsVersion::TlsV13 as i32],
            names: names.to_vec(),
        },
        expired_at: None,
    };

    send_to_worker(
        command_channel_https,
        format!(
            "add-cert-{}",
            names.first().map(|s| s.as_str()).unwrap_or("unknown")
        ),
        RequestType::AddCertificate(cert),
    )?;

    info!("Certificate added for {:?}", names);
    Ok(())
}
