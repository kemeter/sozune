use actix_web::*;
use crate::providers::entrypoint::Entrypoint;
use std::collections::HashMap;


#[get("/entrypoints")]
// pub async fn list(storage: web::Data<HashMap<String, Entrypoint>>) -> HttpResponse {
pub async fn list(storage: web::Data<Vec<Entrypoint>>) -> HttpResponse {

    let mut vec = Vec::new();

    for value in storage.iter() {
        vec.push(value);
    }

    HttpResponse::Ok().json(vec)
}
