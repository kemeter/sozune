#![allow(unused_variables,unused_must_use)]
extern crate sozu_lib as sozu;
#[macro_use] extern crate sozu_command_lib as sozu_command;
extern crate time;

use std::env;
use std::thread;
use std::io::stdout;
use sozu_command::proxy;
use sozu_command::proxy::ProxyRequest;
use sozu_command::proxy::ProxyResponse;
use sozu_command::proxy::HttpFront;
use sozu_command::proxy::Backend;
use sozu_command::channel::Channel;
use sozu_command::proxy::LoadBalancingParams;


use sozu_command::logging::{Logger,LoggerBackend};
use shiplift::Docker;
use shiplift::rep::NetworkSettings;
use shiplift::rep::Container;

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

    let (command, channel) = Channel::generate(1000, 10000).expect("should create a channel");

    let jg = thread::spawn(move || {
        let max_buffers = 500;
        let buffer_size = 16384;
        sozu::http::start(config, channel, max_buffers, buffer_size);
    });

    match docker.containers().list(&Default::default()).await {
        Ok(containers) => {
            for container in containers {
                register_container(docker.clone(), &mut command, container).await
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }

    let _ = jg.join();
}

fn get_ip_address(network: &NetworkSettings) -> String {
    let mut ip_address = &network.ip_address;
    if "" == ip_address {
        for (_, value) in &network.networks {
            ip_address = &value.ip_address;
        }
    }

    return ip_address.to_string();
}

async fn register_container(docker: Docker, &mut command: Channel<ProxyRequest, ProxyResponse>, container: Container ) {
    for (key, value) in container.labels.into_iter() {
        if key == "sozune.host" {
            let host = value;
            match docker.containers().get(&container.id).inspect().await {
                Ok(container) => {
                    let ip_address  = get_ip_address(&container.network_settings);
                    let  container_name = container.name.replace("/", "");
                    let ip_address  = get_ip_address(&container.network_settings);
                    let container_name = container.name.replace("/", "");

                    let http_front = HttpFront {
                        app_id:     container_name.to_string(),
                        address:    "0.0.0.0:80".parse().unwrap(),
                        hostname:   host.to_string(),
                        path_begin: String::from("/"),
                    };

                    let http_backend = Backend {
                        app_id:                    container_name.to_string(),
                        backend_id:                String::from(format!("{}-backend", container_name.to_string())),
                        address:                   String::from(format!("{}:80", ip_address)).parse().unwrap(),
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

                    info!("Register container {}. Host : {} ", container.id, host);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }
}


