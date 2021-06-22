use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

#[macro_use] extern crate sozu_command_lib as sozu_command;

mod providers {
    pub(crate) mod docker;
    pub(crate) mod entrypoint;
}

mod api {
    pub(crate) mod entrypoint;
}

use crate::providers::entrypoint::Entrypoint;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new( move || {

        let mut storage: Vec<Entrypoint>  = vec![];
        crate::providers::docker::provide(&mut storage);

        //let mut storage = vec![];
        //storage.push(entrypoint);

        App::new()
            .data(storage)
            .service(crate::api::entrypoint::list)
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}