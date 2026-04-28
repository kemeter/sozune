use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub provider: &'static str,
    pub id: String,
    pub display_name: String,
    pub labels: HashMap<String, String>,
    pub networks: Vec<NetworkInfo>,
    pub enabled_default: bool,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub name: String,
    pub ip: Option<String>,
}
