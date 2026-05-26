use std::collections::HashMap;

/// Parse `<prefix>plugins=name1,name2` into an ordered list of plugin names to
/// run as middleware. Names reference plugins declared in the static config's
/// `plugins` map; resolution (and the warning for unknown names) happens when
/// the route is built, so no validation is done here. Empty tokens are dropped,
/// order is preserved, duplicates are removed.
pub fn parse_plugins(labels: &HashMap<String, String>, prefix: &str) -> Vec<String> {
    let key = format!("{prefix}plugins");
    let raw = match labels.get(&key) {
        Some(v) => v.trim(),
        None => return Vec::new(),
    };

    let mut out: Vec<String> = Vec::new();
    for token in raw.split(',') {
        let name = token.trim();
        if name.is_empty() {
            continue;
        }
        let name = name.to_string();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn absent_label_yields_empty() {
        assert!(parse_plugins(&labels(&[]), "sozune.").is_empty());
    }

    #[test]
    fn parses_ordered_unique_list() {
        let l = labels(&[("sozune.plugins", "crowdsec, geoblock ,crowdsec")]);
        assert_eq!(parse_plugins(&l, "sozune."), vec!["crowdsec", "geoblock"]);
    }

    #[test]
    fn empty_tokens_dropped() {
        let l = labels(&[("sozune.plugins", " , ,foo, ")]);
        assert_eq!(parse_plugins(&l, "sozune."), vec!["foo"]);
    }
}
