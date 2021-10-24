use crate::providers::entrypoint::Entrypoint;
use serde::{Serialize, Deserialize};

use warp::Filter;
use warp::http::StatusCode;

#[tokio::main]
pub(crate) async fn start(server_address: &str, storage: Vec<Entrypoint>)
{
    let list = warp::get()
        .and(warp::path("entrypoints"))
        .map(move || {
            warp::reply::json(&storage)
        });

    let routes = list;

    warp::serve(routes).run(([0,0,0,0], 3030)).await;
}
