use crate::providers::entrypoint::Entrypoint;

use sozu_command_lib::{
    channel::Channel,
    proto::command::{
        request::RequestType, AddBackend, LoadBalancingParams,
        PathRule, RequestHttpFrontend, SocketAddress,
        WorkerResponse, WorkerRequest,
    },
};

pub fn register_front(command: &mut Channel<WorkerRequest, WorkerResponse>, entrypoint: Entrypoint) {

    let http_front = RequestHttpFrontend {
        cluster_id: Some("cluster_1".to_string()),
        address: SocketAddress::new_v4(127, 0, 0, 1, 80),
        hostname: entrypoint.hostname.to_string(),
        path: PathRule::prefix(entrypoint.path),
        ..Default::default()
    };

    let _ = command.write_message(&WorkerRequest {
        id:    entrypoint.id.to_string(),
        content: RequestType::AddHttpFrontend(http_front).into()
    });
    
    for ip in entrypoint.backends {
        let socket_address = parse_ip(entrypoint.port.clone(), &ip);

        let http_backend = AddBackend {
            cluster_id: String::from("cluster_1"),
            backend_id: String::from(format!("{}-backend", entrypoint.name.to_string())),
            address:  socket_address,
            load_balancing_parameters: Some(LoadBalancingParams::default()),
            sticky_id: None,
            backup: None,
        };

        let _ = command.write_message(&WorkerRequest {
            id: String::from("ID_EFGH"),
            content: RequestType::AddBackend(http_backend).into()
        });
    }
}

fn parse_ip(port: String, ip: &str) -> SocketAddress {

    let ip_segments: Vec<u8> = ip
        .split('.')
        .map(|s| s.parse::<u8>().expect("Parse error"))
        .collect();

    return SocketAddress::new_v4(
        ip_segments[0],
        ip_segments[1],
        ip_segments[2],
        ip_segments[3],
        port.parse().unwrap()
    );
}

pub fn remove_front(command: &mut Channel<WorkerRequest, WorkerResponse>, entrypoint: Entrypoint) {

    let socket_address = parse_ip(entrypoint.port, "0.0.0.0");
    let http_front = RequestHttpFrontend {
        address: socket_address,
        hostname: entrypoint.hostname.to_string(),
        path: PathRule::prefix(entrypoint.path),
        ..Default::default()
    };

    let _ = command.write_message(&WorkerRequest {
        id:    String::from("ID_ABCD"),
        content: RequestType::RemoveHttpFrontend(http_front).into()
    });
}