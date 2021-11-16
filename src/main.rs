#[macro_use] extern crate sozu_command_lib as sozu_command;
use std::io::stdout;
use sozu_command::logging::{Logger,LoggerBackend};
use std::env;
use std::thread;

mod providers {
    pub(crate) mod docker;
    pub(crate) mod entrypoint;
}

mod api {
    pub(crate) mod server;
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
        .execute("CREATE TABLE entrypoints (id TEXT, ip TEXT, name TEXT, hostname TEXT);") {
        Ok(file) => {
            info!("Create table");
        },
        Err(error) => {
            // info!("Unable to create tables {:?}", error);
        }
    }

    let provider = thread::spawn(move || {
        let mut storage: Vec<Entrypoint> = vec![];
        crate::providers::docker::provide(&mut storage);
    });

    let api = thread::spawn(move || {
        let mut storage: Vec<Entrypoint> = vec![];
        let server_address = "127.0.0.1:8080";
        crate::api::server::start(server_address, storage);
    });

    provider.join().unwrap();
    api.join().unwrap();
}
