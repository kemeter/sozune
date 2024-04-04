extern crate sozu_lib as sozu;

#[macro_use]
extern crate sozu_command_lib;

use sozu_command_lib::{
    channel::Channel,
    config::ListenerBuilder,
    info,
    debug,
    logging::setup_logging,
    proto::command::{
        request::RequestType, AddBackend, Cluster, LoadBalancingAlgorithms, LoadBalancingParams,
        PathRule, RequestHttpFrontend, RulePosition, SocketAddress,
    }
};

use anyhow::Context;
use std::thread;

mod config {
    pub(crate) mod config;
}

mod providers {
    pub(crate) mod docker;
    pub(crate) mod entrypoint;
}

mod api {
    pub(crate) mod server;
}

mod proxy {
    pub(crate) mod sozu;
}

use crate::providers::entrypoint::Entrypoint;
use std::collections::HashMap;
use std::sync::{Mutex, Arc};
use sozu::http::testing::start_http_worker;
use sozu::https::testing::start_https_worker;
use sozu_command_lib::proto::command::{WorkerRequest, WorkerResponse};

fn main() {
    env_logger::init();
    let config = config::config::load_config();

    info!("starting up sozu proxy");

    let http_listener = ListenerBuilder::new_http(SocketAddress::new_v4(127, 0, 0, 1, 80))
        .to_http(None)
        .expect("Could not create HTTP listener");

    let https_listener =
        ListenerBuilder::new_https(SocketAddress::new_v4(127, 0, 0, 1, 8443))
            .to_tls(None)
            .expect("Could not create HTTPS listener");

    let (mut command_channel, proxy_channel): (
        Channel<WorkerRequest, WorkerResponse>,
        Channel<WorkerResponse, WorkerRequest>,
    ) = Channel::generate(1000, 10000).unwrap();

    let storage:HashMap<String, Entrypoint> = HashMap::new();
    let storage_arc = Arc::new(Mutex::new(storage));
    let docker_storage = storage_arc.clone();
    let api_storage = storage_arc.clone();

    let config_provider = config.clone();

    let provider = thread::spawn(move || {
        if config_provider.docker.enabled {
            crate::providers::docker::provide(config_provider, &mut command_channel, docker_storage);
        }
    });

    let api = thread::spawn(move || {
        crate::api::server::start(config.clone(), api_storage);
    });

    let jg = thread::spawn(move || {
        let max_buffers = 500;
        let buffer_size = 16384;

        start_http_worker(
            http_listener,
            proxy_channel,
            max_buffers,
            buffer_size,
        ).expect("The worker could not be started, or shut down");
    });

    let (mut command_channel2, proxy_channel2): (
        Channel<WorkerRequest, WorkerResponse>,
        Channel<WorkerResponse, WorkerRequest>,
    ) = Channel::generate(1000, 10000).unwrap();

    let jq2 = thread::spawn(move || {
        let max_buffers = 500;
        let buffer_size = 16384;
        start_https_worker(
            https_listener,
            proxy_channel2,
            max_buffers,
            buffer_size,
        )
    });

    debug!("listening for events");

    provider.join().unwrap();
    api.join().unwrap();
    jg.join().unwrap();
}
