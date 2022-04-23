use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use warp::Filter;
use std::net::IpAddr;

use crate::config::config::Config;
use crate::providers::entrypoint::Entrypoint;

#[tokio::main]
pub(crate) async fn start(configuration: Config, storage: Arc<Mutex<HashMap<String, Entrypoint>>>)
{
    let list = warp::get()
        .and(warp::path("entrypoints"))
        .map(move || {
            let entrypoints = storage.lock().unwrap().clone();

            warp::reply::json(&entrypoints)
        });

    let routes = list;

    println!("Starting api server {} on port {}", configuration.api.address, configuration.api.port);
    let address: IpAddr = configuration.api.address.parse().unwrap();

    warp::serve(routes).run((address, configuration.api.port)).await;
}
