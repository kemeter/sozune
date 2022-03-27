use crate::providers::entrypoint::Entrypoint;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;

use warp::Filter;

#[tokio::main]
pub(crate) async fn start(server_address: &str, storage: Arc<Mutex<HashMap<String, Entrypoint>>>)
{
    let list = warp::get()
        .and(warp::path("entrypoints"))
        .map(move || {
            let entrypoints = storage.lock().unwrap().clone();

            warp::reply::json(&entrypoints)
        });

    let routes = list;

    warp::serve(routes).run(([0,0,0,0], 3030)).await;
}
