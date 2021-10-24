use serde::{Serialize, Deserialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Entrypoint {
    pub id: String,
    pub ip: String,
    pub name: String,
    pub hostname: String
}
