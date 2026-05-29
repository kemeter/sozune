//! Parser for the `<prefix>ipAllowList` label.
//!
//! The label value is a comma-separated list of IPs or CIDR ranges, e.g.
//!
//! ```text
//! sozune.http.api.ipAllowList = 10.0.0.0/8, 192.168.1.5, 2001:db8::/32
//! ```
//!
//! Only the textual split happens here. Entries are validated when the
//! middleware compiles them so an unparseable entry is logged and dropped
//! rather than rejected at parse time. Empty tokens are dropped, ordering
//! is preserved, duplicates are removed (a duplicate gives the operator no
//! extra coverage but bloats the per-request linear walk).

use std::collections::HashMap;

pub fn parse_ip_allow_list(labels: &HashMap<String, String>, prefix: &str) -> Vec<String> {
    let key = format!("{prefix}ipAllowList");
    let Some(raw) = labels.get(&key) else {
        return Vec::new();
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<String> = Vec::new();
    for token in raw.split(',') {
        let entry = token.trim();
        if entry.is_empty() {
            continue;
        }
        if !out.iter().any(|e| e == entry) {
            out.push(entry.to_string());
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
        assert!(parse_ip_allow_list(&labels(&[]), "sozune.").is_empty());
    }

    #[test]
    fn empty_value_yields_empty() {
        let l = labels(&[("sozune.ipAllowList", "")]);
        assert!(parse_ip_allow_list(&l, "sozune.").is_empty());
    }

    #[test]
    fn whitespace_only_value_yields_empty() {
        let l = labels(&[("sozune.ipAllowList", "  ,  , ")]);
        assert!(parse_ip_allow_list(&l, "sozune.").is_empty());
    }

    #[test]
    fn parses_ordered_unique_list() {
        let l = labels(&[("sozune.ipAllowList", "10.0.0.0/8, 192.168.1.5 ,10.0.0.0/8")]);
        assert_eq!(
            parse_ip_allow_list(&l, "sozune."),
            vec!["10.0.0.0/8", "192.168.1.5"]
        );
    }

    #[test]
    fn preserves_ipv6_and_cidr_mix() {
        let l = labels(&[(
            "sozune.ipAllowList",
            "2001:db8::/32, 10.0.0.5, 203.0.113.0/24",
        )]);
        assert_eq!(
            parse_ip_allow_list(&l, "sozune."),
            vec!["2001:db8::/32", "10.0.0.5", "203.0.113.0/24"]
        );
    }

    #[test]
    fn empty_tokens_dropped() {
        let l = labels(&[("sozune.ipAllowList", " , ,10.0.0.1, ")]);
        assert_eq!(parse_ip_allow_list(&l, "sozune."), vec!["10.0.0.1"]);
    }
}
