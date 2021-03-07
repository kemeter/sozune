#![allow(unused_variables,unused_must_use)]
extern crate sozu_lib as sozu;
#[macro_use] extern crate sozu_command_lib as sozu_command;
extern crate time;

use std::env;
use std::thread;
use std::io::stdout;
use sozu_command::proxy;
use sozu_command::channel::Channel;
use sozu_command::proxy::LoadBalancingParams;
use sozu_command::logging::{Logger,LoggerBackend};
use shiplift::Docker;

#[tokio::main]
async fn main() {
    env_logger::init();
    let docker = Docker::new();

    // start sozu proxy
    if env::var("RUST_LOG").is_ok() {
        Logger::init("".to_string(), &env::var("RUST_LOG").expect("could not get the RUST_LOG env var"), LoggerBackend::Stdout(stdout()), None);
    } else {
        Logger::init("".to_string(), "info", LoggerBackend::Stdout(stdout()), None);
    }

    info!("starting up sozu proxy");
    let config = proxy::HttpListener {
        front: "0.0.0.0:80".parse().expect("could not parse address"),
        ..Default::default()
    };

    let (mut command, channel) = Channel::generate(1000, 10000).expect("should create a channel");
    let jg = thread::spawn(move || {
        let max_buffers = 500;
        let buffer_size = 16384;
        sozu::http::start(config, channel, max_buffers, buffer_size);
    });

    match docker.containers().list(&Default::default()).await {
        Ok(containers) => {
            for container in containers {
                for (key, value) in container.labels.into_iter() {
                    if key == "sozune.host" {
                        let host = value;
                        match docker.containers().get(&container.id).inspect().await {
                            Ok(container) => {
                                let mut ip_address = container.network_settings.ip_address;
                                if "" == ip_address {
                                    for (_, value) in container.network_settings.networks {
                                        ip_address = value.ip_address
                                    }
                                }
                                let  container_name = container.name.replace("/", "");

                                info!("Registrer container {}. Host : {} ", container.id, host);
                                let http_front = proxy::HttpFront {
                                    app_id:     String::from(&container_name),
                                    address:    "0.0.0.0:80".parse().unwrap(),
                                    hostname:   String::from(host),
                                    path_begin: String::from("/"),
                                };
                                let http_backend = proxy::Backend {
                                    app_id:                    String::from(&container_name),
                                    backend_id:                String::from("test-0"),
                                    address:                   String::from(format!("{}:80", &ip_address)).parse().unwrap(),
                                    load_balancing_parameters: Some(LoadBalancingParams::default()),
                                    sticky_id:                 None,
                                    backup:                    None,
                                };

                                command.write_message(&proxy::ProxyRequest {
                                    id:    String::from("ID_ABCD"),
                                    order: proxy::ProxyRequestData::AddHttpFront(http_front)
                                });

                                command.write_message(&proxy::ProxyRequest {
                                    id:    String::from("ID_EFGH"),
                                    order: proxy::ProxyRequestData::AddBackend(http_backend)
                                });

                            }
                            Err(e) => eprintln!("Error: {}", e),
                        }
                    }
                }
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }

    let _ = jg.join();
}
