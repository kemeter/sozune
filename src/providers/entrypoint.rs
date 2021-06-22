use serde::{Serialize, Deserialize}; 

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entrypoint {
    pub id: String,
    pub ip: String,
    pub name: String,
    pub hostname: String
}
