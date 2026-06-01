use std::collections::HashMap;

use crate::model::MatchCondition;

/// Parse `<prefix>matchHeaders=key:value,key2:value2` into match conditions.
/// An entry without `:` (or with an empty value) matches on key presence
/// alone. Empty tokens are dropped; order is preserved.
pub fn parse_match_headers(labels: &HashMap<String, String>, prefix: &str) -> Vec<MatchCondition> {
    parse_conditions(labels, &format!("{prefix}matchHeaders"))
}

/// Parse `<prefix>matchQuery=key:value,...` into match conditions. Same shape
/// as [`parse_match_headers`].
pub fn parse_match_query(labels: &HashMap<String, String>, prefix: &str) -> Vec<MatchCondition> {
    parse_conditions(labels, &format!("{prefix}matchQuery"))
}

/// Parse `<prefix>matchClientIP=cidr,cidr2,...` into a list of raw IP/CIDR
/// strings. Validation (and dropping of invalid entries) happens later, in
/// the matching layer, which shares the allow-list's CIDR parser. Empty
/// tokens are dropped; order is preserved.
pub fn parse_match_client_ip(labels: &HashMap<String, String>, prefix: &str) -> Vec<String> {
    let raw = match labels.get(&format!("{prefix}matchClientIP")) {
        Some(v) => v.trim(),
        None => return Vec::new(),
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_conditions(labels: &HashMap<String, String>, key: &str) -> Vec<MatchCondition> {
    let raw = match labels.get(key) {
        Some(v) => v.trim(),
        None => return Vec::new(),
    };

    let mut out: Vec<MatchCondition> = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (k, v) = match token.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (token, ""),
        };
        if k.is_empty() {
            continue;
        }
        let cond = MatchCondition {
            key: k.to_string(),
            value: v.to_string(),
        };
        if !out.contains(&cond) {
            out.push(cond);
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
    fn absent_yields_empty() {
        assert!(parse_match_headers(&labels(&[]), "sozune.").is_empty());
        assert!(parse_match_query(&labels(&[]), "sozune.").is_empty());
    }

    #[test]
    fn parses_key_value_pairs() {
        let l = labels(&[("sozune.matchHeaders", "X-Env:prod, X-Region:eu")]);
        let got = parse_match_headers(&l, "sozune.");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].key, "X-Env");
        assert_eq!(got[0].value, "prod");
        assert_eq!(got[1].key, "X-Region");
        assert_eq!(got[1].value, "eu");
    }

    #[test]
    fn key_only_means_presence() {
        let l = labels(&[("sozune.matchQuery", "beta")]);
        let got = parse_match_query(&l, "sozune.");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, "beta");
        assert_eq!(got[0].value, "");
    }

    #[test]
    fn empty_tokens_dropped_and_deduped() {
        let l = labels(&[("sozune.matchHeaders", " , X-A:1 ,X-A:1, ")]);
        let got = parse_match_headers(&l, "sozune.");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, "X-A");
    }

    #[test]
    fn value_may_contain_no_extra_colon_split() {
        // Only the first colon splits key/value.
        let l = labels(&[("sozune.matchHeaders", "X-Time:12:30")]);
        let got = parse_match_headers(&l, "sozune.");
        assert_eq!(got[0].key, "X-Time");
        assert_eq!(got[0].value, "12:30");
    }

    #[test]
    fn client_ip_absent_yields_empty() {
        assert!(parse_match_client_ip(&labels(&[]), "sozune.").is_empty());
    }

    #[test]
    fn client_ip_parses_list_preserving_order() {
        let l = labels(&[(
            "sozune.matchClientIP",
            "10.0.0.0/8, 192.168.1.5 ,2001:db8::/32",
        )]);
        let got = parse_match_client_ip(&l, "sozune.");
        assert_eq!(got, vec!["10.0.0.0/8", "192.168.1.5", "2001:db8::/32"]);
    }

    #[test]
    fn client_ip_drops_empty_tokens() {
        let l = labels(&[("sozune.matchClientIP", " , 10.0.0.1 , ")]);
        let got = parse_match_client_ip(&l, "sozune.");
        assert_eq!(got, vec!["10.0.0.1"]);
    }
}
