extern crate sozu_lib as sozu;
#[macro_use] extern crate sozu_command_lib as sozu_command;

use std::thread;
use log::{info, debug};
use sozu_command::channel::Channel;

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

fn main() {
    env_logger::init();

    info!("starting up sozu proxy");

    let config = sozu_command::proxy::HttpListener {
        front: "0.0.0.0:80".parse().expect("could not parse address"),
        ..Default::default()
    };
    let (mut command, channel) = Channel::generate(1000, 10000).expect("should create a channel");
    let storage:HashMap<String, Entrypoint> = HashMap::new();

    let storage_arc = Arc::new(Mutex::new(storage));
    let docker_storage = storage_arc.clone();
    let api_storage = storage_arc.clone();

    let provider = thread::spawn(move || {
        crate::providers::docker::provide(&mut command, docker_storage);
    });

    let api = thread::spawn(move || {
        let server_address = "127.0.0.1:8080";
        crate::api::server::start(server_address, api_storage);
    });

    let jg = thread::spawn(move || {
        let max_buffers = 500;
        let buffer_size = 16384;
        sozu::http::start(config, channel, max_buffers, buffer_size);
    });

    debug!("listening for events");

    provider.join().unwrap();
    api.join().unwrap();
    jg.join().unwrap();
}
