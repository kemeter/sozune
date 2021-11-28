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
use sqlite::Connection;
use sqlite::Value;

#[tokio::main]
pub(crate) async fn provide(command: &mut Channel<ProxyRequest, ProxyResponse>) {
    info!("Start docker provider");

    let mut storage: Vec<Entrypoint>  = vec![];
    let docker = Docker::new();
    let connection = sqlite::open("sozune.db").unwrap();

    match docker.containers().list(&Default::default()).await {
        Ok(containers) => {
            for container in containers {
                match docker.containers().get(&container.id).inspect().await {
                    Ok(container) => {
                        register_container(command, container).await
                    },
                    Err(e) => eprintln!("Error get container: {}", e),
                }
            }
        },
        Err(e) => eprintln!("Error list container: {}", e),
    }
        
    while let Some(event_result) = docker.events(&Default::default()).next().await {
        match event_result {
            Ok(event) => {
                info!("Container event {:?}", event.action);
                if "container" == event.typ {

                    match docker.containers().get(&event.actor.id).inspect().await {
                        Ok(container) => {

                            info!("Container event {:?}", event.action);

                            if "start" == event.action {
                                register_container(command, container.clone()).await
                            }

                            if "die" == event.action  {
                                remove_container(command, container).await
                            }

                        }
                        Err(e) => eprintln!("Error events get container: {}", e),
                    }

                }

            },
            Err(e) => eprintln!("Error watch docker event: {}", e),
        }
    }
}

fn get_ip_address(network: &NetworkSettings, network_label: String) -> String {
    let mut ip_address = &network.ip_address;

    if "" == ip_address {
        for (label, value) in &network.networks {
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

fn get_frontend_protocol(labels: Option<HashMap<String, String>>) -> String {
    for labels in labels.into_iter() {
        for (label, value) in labels {
            if label == "sozune.frontend.protocol" {
                return value;
            }
        }
    }

    return String::from("http");
}

async fn register_container(command: &mut Channel<ProxyRequest, ProxyResponse>, container: ContainerDetails ) {
    println!("register container");
    let host = get_host(container.config.labels.clone());
    let connection = Connection::open("sozune.db").expect("Could not test: DB not created");

    if host != "" {
        let network = get_network(container.config.labels.clone());
        let ip_address = get_ip_address(&container.network_settings, network);
        let port = get_port(container.config.labels.clone());
        let protocol = get_frontend_protocol(container.config.labels.clone());
        let container_name = container.name.replace("/", "");

        let entrypoint = Entrypoint {
            id: container.id.clone(),
            ip: ip_address,
            name: container_name,
            hostname: host.clone(),
            port: port.clone(),
            protocol: protocol.clone()
        };

        let mut cursor = connection
            .prepare("SELECT * FROM entrypoints WHERE hostname = ? ")
            .unwrap()
            .into_cursor();

        cursor.bind(&[Value::String(entrypoint.id.clone())]).unwrap();
        cursor.bind(&[Value::String(host.clone())]).unwrap();

        let row = cursor.next().unwrap();

        if None == row {

            let mut statement = connection
                .prepare(
                    "
                INSERT INTO entrypoints (id, ip, name, hostname, port, protocol)
                VALUES (?, ?, ?, ?, ?, ?);
            ",
                )
                .unwrap();

            statement.bind(1, string_to_static_str(entrypoint.id.clone().to_string())).unwrap();
            statement.bind(2, string_to_static_str(entrypoint.ip.clone().to_string())).unwrap();
            statement.bind(3, string_to_static_str(entrypoint.name.clone().to_string())).unwrap();
            statement.bind(4, string_to_static_str(entrypoint.hostname.clone().to_string())).unwrap();
            statement.bind(5, string_to_static_str(entrypoint.port.clone().to_string())).unwrap();
            statement.next();
        }

        // storage.push(entrypoint.clone());
        sozu::register_front(command, entrypoint.clone());

        info!("Register container {}. Host : {} ", container.id.clone(), entrypoint.hostname);
    } else {
        info!("container {} Host not found ", container.id.clone());
    }
}

async fn remove_container(command: &mut Channel<ProxyRequest, ProxyResponse>, container: ContainerDetails ) {
    let host = get_host(container.config.labels.clone());

    if "" != host {
        info!("Remove container {}. Host : {} ", container.id, host);

        let container_name = container.name.replace("/", "");
        let ip_address = get_ip_address(&container.network_settings, String::from(""));
        let port = get_port(container.config.labels.clone());
        let protocol = get_frontend_protocol(container.config.labels);
        let entrypoint = Entrypoint {
            id: container.id.clone(),
            ip: ip_address.clone(),
            name: container_name,
            hostname: host.clone(),
            port: port.clone(),
            protocol: protocol.clone()
        };

        sozu::remove_front(command, entrypoint);

        debug!("container ip {}", ip_address);
    }
}

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
