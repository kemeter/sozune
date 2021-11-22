use crate::providers::entrypoint::Entrypoint;

use sozu_command::proxy::Backend;
use sozu_command::channel::Channel;
use sozu_command::proxy::ProxyResponse;
use sozu_command::proxy::ProxyRequest;
use sozu_command::proxy::LoadBalancingParams;
use sozu_command::proxy;
use sozu_command::proxy::HttpFront;

pub fn register_front(command: &mut Channel<ProxyRequest, ProxyResponse>, entrypoint: Entrypoint) {

    let http_front = HttpFront {
        app_id:     entrypoint.name.to_string(),
        address:    "0.0.0.0:80".parse().unwrap(),
        hostname:   entrypoint.hostname.to_string(),
        path_begin: String::from("/"),
    };

    let http_backend = Backend {
        app_id:                    entrypoint.name.to_string(),
        backend_id:                String::from(format!("{}-backend", entrypoint.name.to_string())),
        address:                   String::from(format!("{}:80", entrypoint.ip)).parse().unwrap(),
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

pub fn remove_front(command: &mut Channel<ProxyRequest, ProxyResponse>, entrypoint: Entrypoint) {

    let http_front = HttpFront {
        app_id:     entrypoint.name.to_string(),
        address:    "0.0.0.0:80".parse().unwrap(),
        hostname:   entrypoint.hostname.to_string(),
        path_begin: String::from("/"),
    };

    command.write_message(&proxy::ProxyRequest {
        id:    String::from("ID_ABCD"),
        order: proxy::ProxyRequestData::RemoveHttpFront(http_front)
    });
}