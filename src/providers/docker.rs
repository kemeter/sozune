use crate::providers::entrypoint::Entrypoint;
use crate::proxy::sozu;
use futures::StreamExt;
use shiplift::Docker;

use shiplift::rep::NetworkSettings;
use shiplift::rep::ContainerDetails;
use sozu_command::proxy::ProxyResponse;
use sozu_command::proxy::ProxyRequest;
use sozu_command::channel::Channel;
use std::collections::HashMap;

use std::sync::{Mutex, Arc};
use log::{info, debug};
use std::env;

use crate::config::config::Config;

#[tokio::main]
pub(crate) async fn provide(
    configuration: Config,
    command: &mut Channel<ProxyRequest,
    ProxyResponse>,
    storage: Arc<Mutex<HashMap<String, Entrypoint>>>
) {
    info!("Start docker provider");

    env::set_var("DOCKER_HOST", configuration.docker.endpoint.clone());
    let docker = Docker::new();

    match docker.containers().list(&Default::default()).await {
        Ok(containers) => {
            for container in containers {
                match docker.containers().get(&container.id).inspect().await {
                    Ok(container) => {
                        if container.state.status == "running" {
                            register_container(command, &storage, container).await
                        }
                    },
                    Err(e) => debug!("Error get container: {}", e),
                }
            }
        },
        Err(e) => debug!("Error list container: {}", e),
    }
        
    while let Some(event_result) = docker.events(&Default::default()).next().await {
        match event_result {
            Ok(event) => {
                debug!("Container event {:?}", event.action);
                if "container" == event.typ {
                    match docker.containers().get(&event.actor.id).inspect().await {
                        Ok(container) => {

                            debug!("Container event {:?}", event.action);

                            if "start" == event.action {
                                register_container(command, &storage, container.clone()).await
                            }

                            if "die" == event.action  {
                                remove_container(command, &storage, container).await
                            }

                        }
                        Err(e) => debug!("Error events get container: {}", e),
                    }

                }

            },
            Err(e) => debug!("Error watch docker event: {}", e),
        }
    }
}

fn get_ip_address(network: &NetworkSettings, network_label: String) -> String {
    let mut ip_address = &network.ip_address;

    if "" == ip_address {
        for (_label, value) in &network.networks {
            if network_label.eq(&network_label) {
                ip_address = &value.ip_address;
            }

            debug!("container ip {}", ip_address);
        }
    }

    return ip_address.to_string();
}

fn get_host(labels: Option<HashMap<String, String>>) -> String {
    for labels in labels.into_iter() {
        for (label, value) in labels {
            if label == "sozune.host" {
                return value;
            }
        }
    }

    return String::from("");
}

fn get_network(labels: Option<HashMap<String, String>>) -> String {
    for labels in labels.into_iter() {
        for (label, value) in labels {
            if label == "sozune.docker.network" {
                return value;
            }
        }
    }

    return String::from("");
}

fn get_port(labels: Option<HashMap<String, String>>) -> String {
    for labels in labels.into_iter() {
        for (label, value) in labels {
            if label == "sozune.port" {
                return value;
            }
        }
    }

    return String::from("80");
}

fn get_path(labels: Option<HashMap<String, String>>) -> String {
    for labels in labels.into_iter() {
        for (label, value) in labels {
            if label == "sozune.path" {
                return value;
            }
        }
    }

    return String::from("/");
}

async fn register_container(command: &mut Channel<ProxyRequest, ProxyResponse>, storage: &Arc<Mutex<HashMap<String, Entrypoint>>>, container: ContainerDetails ) {
    debug!("test container {:?}", container.id);
    let host = get_host(container.config.labels.clone());

    if host != "" {
        let network = get_network(container.config.labels.clone());
        let ip_address = get_ip_address(&container.network_settings, network);
        let port = get_port(container.config.labels.clone());
        let path = get_path(container.config.labels);
        let container_name = container.name.replace("/", "");

        let mut guard = storage.lock().unwrap();

        if guard.contains_key(&host) {
            let mut entrypoint = guard.get(&host).clone().unwrap().clone();
            entrypoint.backends.push(ip_address);

            guard.insert(host.to_string(), entrypoint.clone());

            info!("update container {:?}", entrypoint);

            sozu::register_front(command, entrypoint.clone());

        } else {
            let entrypoint = Entrypoint {
                id: container.id.to_string(),
                name: container_name,
                hostname: host.to_string(),
                port: port.to_string(),
                path: path,
                backends: vec![ip_address.to_string()],
            };

            guard.insert(host, entrypoint.clone());

            sozu::register_front(command, entrypoint.clone());

            info!("Register container {}. Host : {} ", container.id.to_string(), entrypoint.hostname);
        };

    } else {
        info!("Host not found for container {}  ", container.id.clone());
    }
}

async fn remove_container(command: &mut Channel<ProxyRequest, ProxyResponse>, storage: &Arc<Mutex<HashMap<String, Entrypoint>>>, container: ContainerDetails ) {
    let host = get_host(container.config.labels.clone());

    if "" != host {
        info!("Remove container {}. Host : {} ", container.id, host);

        let mut guard = storage.lock().unwrap();

        let container_name = container.name.replace("/", "");
        let ip_address = get_ip_address(&container.network_settings, String::from(""));
        let port = get_port(container.config.labels.clone());
        let path = get_path(container.config.labels);
        let entrypoint = Entrypoint {
            id: container.id.clone(),
            backends: vec![ip_address.clone()],
            name: container_name,
            hostname: host.clone(),
            path: path.clone(),
            port: port.clone()
        };

        guard.remove(&*host);
        sozu::remove_front(command, entrypoint);

        debug!("container ip {}", ip_address);
    }
}
