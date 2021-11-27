extern crate sozu_lib as sozu;
#[macro_use] extern crate sozu_command_lib as sozu_command;

use std::io::stdout;
use sozu_command::logging::{Logger,LoggerBackend};
use std::env;
use std::thread;

use sozu_command::channel::Channel;
use sozu_command::proxy::HttpFront;

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

fn main() {
    env_logger::init();

    if env::var("RUST_LOG").is_ok() {
        Logger::init("".to_string(), &env::var("RUST_LOG").expect("could not get the RUST_LOG env var"), LoggerBackend::Stdout(stdout()), None);
    } else {
        Logger::init("".to_string(), "info", LoggerBackend::Stdout(stdout()), None);
    }

    let connection = sqlite::open("sozune.db").unwrap();
    match connection
        .execute("CREATE TABLE entrypoints (id TEXT, ip TEXT, name TEXT, hostname TEXT, port TEXT);") {
        Ok(file) => {
            info!("Create table");
        },
        Err(error) => {
            // info!("Unable to create tables {:?}", error);
        }
    }

    info!("starting up sozu proxy");

    let config = sozu_command::proxy::HttpListener {
        front: "0.0.0.0:80".parse().expect("could not parse address"),
        ..Default::default()
    };

    let (mut command, channel) = Channel::generate(1000, 10000).expect("should create a channel");

    let provider = thread::spawn(move || {
        crate::providers::docker::provide(&mut command);
    });

    let api = thread::spawn(move || {
        let mut storage: Vec<Entrypoint> = vec![];
        let server_address = "127.0.0.1:8080";
        crate::api::server::start(server_address, storage);
    });


    let jg = thread::spawn(move || {
        let max_buffers = 500;
        let buffer_size = 16384;
        sozu::http::start(config, channel, max_buffers, buffer_size);
    });

    println!("listening for events");

    provider.join().unwrap();
    api.join().unwrap();
    jg.join();
}
