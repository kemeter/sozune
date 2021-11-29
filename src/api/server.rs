use crate::providers::entrypoint::Entrypoint;
use serde::{Serialize, Deserialize};

use warp::Filter;
use warp::http::StatusCode;
use sqlite::Connection;

#[tokio::main]
pub(crate) async fn start(server_address: &str, storage: Vec<Entrypoint>)
{
    let list = warp::get()
        .and(warp::path("entrypoints"))
        .map(move || {
            let connection = Connection::open("sozune.db").expect("Could not test: DB not created");

            let mut cursor = connection
                .prepare("SELECT * FROM entrypoints")
                .unwrap()
                .into_cursor();

            let mut entrypoints: Vec<Entrypoint> = Vec::new();

            while let Some(row) = cursor.next().unwrap() {
                let entrypoint = Entrypoint{
                    id: row[0].as_string().unwrap().to_string(),
                    ip: row[1].as_string().unwrap().to_string(),
                    name: row[2].as_string().unwrap().to_string(),
                    hostname: row[3].as_string().unwrap().to_string(),
                    port: row[4].as_string().unwrap().to_string(),
                    protocol: row[5].as_string().unwrap().to_string(),
                };

                entrypoints.push(entrypoint)
            }

            warp::reply::json(&entrypoints)
        });

    let routes = list;

    warp::serve(routes).run(([0,0,0,0], 3030)).await;
}
