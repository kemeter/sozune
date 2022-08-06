use serde::{Serialize, Deserialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Entrypoint {
    pub id: String,
    pub backends: Vec<String>,
    pub name: String,
    pub hostname: String,
    pub port: String,
    pub path: String,
}
