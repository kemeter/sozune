use crate::providers::entrypoint::Entrypoint;
use crate::proxy::sozu;
use futures::StreamExt;
use bollard::container::{Config, CreateContainerOptions, InspectContainerOptions, LogsOptions, StartContainerOptions};
use bollard::Docker;
use bollard::models::ContainerSummary;
use bollard::models::NetworkSettings;

use sozu_command::proxy::ProxyResponse;
use sozu_command::proxy::ProxyRequest;
use sozu_command::channel::Channel;
use std::collections::HashMap;

use std::sync::{Mutex, Arc};
use log::{info, debug};
use std::env;
use std::collections::hash_map::Iter;

use bollard::container::ListContainersOptions;

use crate::config::config::{Config as SozuneConfig};

#[tokio::main]
pub(crate) async fn provide(
    configuration: SozuneConfig,
    command: &mut Channel<ProxyRequest,
    ProxyResponse>,
    storage: Arc<Mutex<HashMap<String, Entrypoint>>>
) {
    info!("Start docker provider");

    env::set_var("DOCKER_HOST", configuration.docker.endpoint.clone());
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let mut list_container_filters = HashMap::new();
    list_container_filters.insert("status", vec!["running"]);

    let containers = &docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters: list_container_filters,
            ..Default::default()
        }))
        .await;

    for con in containers.iter() {
        for container in con.iter() {
            let labels = &container.labels.as_ref().unwrap();

            register_container(command, &storage, container.clone()).await;
        }
    }

    //
    // while let Some(event_result) = docker.events(&Default::default()).next().await {
    //     match event_result {
    //         Ok(event) => {
    //             info!("Container event {:?}", event.action);
    //             if "container" == event.typ {
    //                 match docker.containers().get(&event.actor.id).inspect().await {
    //                     Ok(container) => {
    //
    //                         debug!("Container event {:?}", event.action);
    //
    //                         if "start" == event.action {
    //                             register_container(command, &storage, container.clone()).await
    //                         }
    //
    //                         if "die" == event.action  {
    //                             remove_container(command, &storage, container).await
    //                         }
    //
    //                     }
    //                     Err(e) => debug!("Error events get container: {}", e),
    //                 }
    //
    //             }
    //
    //         },
    //         Err(e) => debug!("Error watch docker event: {}", e),
    //     }
    // }
}

// fn get_ip_address(network: &NetworkSettings, network_label: String) -> String {
//     dbg!(network.clone());
//     let mut ip_address = &network.ip_address;
//
//     if "" == ip_address {
//         for (_label, value) in &network.networks {
//             if network_label.eq(&network_label) {
//                 ip_address = &value.ip_address;
//             }
//
//             debug!("container ip {}", ip_address);
//         }
//     }
//
//     return ip_address.to_string();
// }
//
//             debug!("container ip {}", ip_address);
//         }
//     }
//
//     return ip_address.to_string();
// }

fn get_host(labels: Iter<String, String>) -> String {
    for (label, value) in labels {
        if label == "sozune.host" {
            return value.to_string();
        }
    }

    return String::from("");
}

fn get_network(labels: Iter<String, String>) -> String {
    for (label, value) in labels {
        if label == "sozune.docker.network" {
            return value.to_string();
        }
    }

    return String::from("");
}

fn get_port(labels: Iter<String, String>) -> String {
    for (label, value) in labels {
        if label == "sozune.port" {
            return value.to_string();
        }
    }

    return String::from("80");
}

fn get_path(labels: Iter<String, String>) -> String {
    for (label, value) in labels {
        if label == "sozune.path" {
            return value.to_string();
        }
    }

    return String::from("/");
}


async fn register_container(command: &mut Channel<ProxyRequest, ProxyResponse>, storage: &Arc<Mutex<HashMap<String, Entrypoint>>>, container: ContainerSummary ) {
    debug!("test container {:?}", container.id);
    let labels = &container.labels.as_ref().unwrap();
    let host = get_host(labels.into_iter());
    if host != "" {
        let network = get_network(labels.into_iter());
        // let ip_address = get_ip_address(&container.network_settings, network);
        let port = get_port(labels.into_iter());
        let path = get_path(labels.into_iter());
        let container_name = container.names.as_ref().unwrap()[0].replace("/", "");

    //
    //     let mut guard = storage.lock().unwrap();
    //
    //     if guard.contains_key(&host) {
    //         let mut entrypoint = guard.get(&host).clone().unwrap().clone();
    //         entrypoint.backends.push(ip_address);
    //
    //         guard.insert(host.to_string(), entrypoint.clone());
    //
    //         info!("update container {:?}", entrypoint);
    //
    //         sozu::register_front(command, entrypoint.clone());
    //
    //     } else {
    //         let entrypoint = Entrypoint {
    //             id: container.id.to_string(),
    //             name: container_name,
    //             hostname: host.to_string(),
    //             port: port.to_string(),
    //             path: path,
    //             backends: vec![ip_address.to_string()],
    //         };
    //
    //         guard.insert(host, entrypoint.clone());
    //
    //         sozu::register_front(command, entrypoint.clone());
    //
    //         info!("Register container {}. Host : {} ", container.id.to_string(), entrypoint.hostname);
    //     };
    //
    } else {
        info!("Host not found for container {}  ", container.id.unwrap());
    }
}
//
// async fn remove_container(command: &mut Channel<ProxyRequest, ProxyResponse>, storage: &Arc<Mutex<HashMap<String, Entrypoint>>>, container: ContainerDetails ) {
//     let host = get_host(container.config.labels.clone());
//     info!("process remove");
//
//     if "" != host {
//         dbg!(container.clone());
//         info!("Remove container {}. Host : {} ", container.id, host);
//
//         let mut guard = storage.lock().unwrap();
//         let ip_address = get_ip_address(&container.network_settings, String::from("bridge"));
//
//         let mut entrypoint = guard.get(&*host).unwrap().clone();
//         dbg!(entrypoint.clone());
//
//         let ip: &str = &ip_address;
//
//         let index = entrypoint.backends.iter().position(|r| r == ip);
//         dbg!(index);
//         // entrypoint.backends.remove(index);
//
//         // sozu::remove_front(command, entrypoint);
//
//         debug!("container ip {}", ip_address);
//     }
// }

//
// pub fn deserialize_labels(serialized: TypeName) -> HashMap<String, String> {
//     let deserialized: HashMap<String, String> = serde_json::from_str(&serialized).unwrap();
//     deserialized
// }