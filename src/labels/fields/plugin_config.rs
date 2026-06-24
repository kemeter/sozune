use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Maximum nesting depth for a dotted plugin-config key (`plugins.a.b.c…`).
/// Keys come from tenant-controlled labels, so the recursion that builds the
/// nested object must be bounded; without a cap a single pathological key with
/// thousands of segments could overflow the parsing thread's stack at reload.
/// 16 is far beyond any real plugin config.
const MAX_PLUGIN_CONFIG_DEPTH: usize = 16;

/// Parse `plugins.<name>.<key>=<value>` labels into a per-plugin JSON config,
/// keyed by plugin name. This is how a route configures a WASM plugin
/// differently from the plugin's global config — e.g. an Umami `websiteId` or
/// a CrowdSec `lapi_key` that only applies to one entrypoint.
///
/// `<key>` may itself be dotted (`plugins.umami.tracking.mode=spa`), which nests
/// into the plugin's JSON object (`{"tracking": {"mode": "spa"}}`). Each leaf
/// value is parsed as JSON when it is valid JSON (so `true`, `42`, `["a","b"]`
/// keep their type), falling back to a plain string otherwise.
///
/// Note this only collects the *config* sub-keys; the ordered list of plugins to
/// run still comes from the bare `plugins=a,b,c` label (see [`super::plugins`]).
/// A `<name>` here that is not also in that list is parsed but never used.
pub fn parse_plugin_config(
    labels: &std::collections::HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, Value> {
    let config_prefix = format!("{prefix}plugins.");
    let mut out: BTreeMap<String, Value> = BTreeMap::new();

    // Deterministic order so nested merges are reproducible.
    let mut keys: Vec<&String> = labels.keys().collect();
    keys.sort();

    for key in keys {
        let Some(remainder) = key.strip_prefix(&config_prefix) else {
            continue;
        };
        // The bare `plugins=a,b,c` list label shares the `plugins` stem but not
        // the `plugins.` config prefix, so it never reaches here; anything that
        // does is meant to be plugin config.

        // remainder is `<name>.<key...>`; split off the plugin name.
        let Some((plugin_name, path)) = remainder.split_once('.') else {
            // `plugins.<name>` with no sub-key is meaningless as config; warn so
            // the operator knows the label was ignored rather than applied.
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W026InvalidPluginConfig,
                    format!("plugin config '{remainder}' has no sub-key, ignored"),
                )
                .with_label(key)
                .with_hint("use `plugins.<name>.<key>=<value>` (e.g. plugins.umami.websiteId=...)"),
            );
            continue;
        };
        if plugin_name.is_empty() || path.is_empty() {
            continue;
        }

        // Bound the nesting driven by the (tenant-controlled) key so a deeply
        // dotted label cannot overflow the stack at reload.
        if path.split('.').count() > MAX_PLUGIN_CONFIG_DEPTH {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W026InvalidPluginConfig,
                    format!(
                        "plugin config key '{path}' nests deeper than {MAX_PLUGIN_CONFIG_DEPTH}, ignored"
                    ),
                )
                .with_label(key)
                .with_hint("flatten the config; plugin config does not need deep nesting"),
            );
            continue;
        }

        let leaf = parse_value(&labels[key]);
        let entry = out
            .entry(plugin_name.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(obj) = entry {
            insert_nested(obj, path, leaf);
        }
    }

    out
}

/// Parse a label value as JSON, falling back to a plain string. This keeps
/// `true`/`42`/`["a","b"]` typed while leaving `crowdsec:8080` a string.
fn parse_value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

/// Insert `value` into `obj` at the dotted `path`, creating intermediate
/// objects as needed. A segment that collides with a non-object value is
/// overwritten with a fresh object so later keys still apply.
fn insert_nested(obj: &mut Map<String, Value>, path: &str, value: Value) {
    match path.split_once('.') {
        None => {
            obj.insert(path.to_string(), value);
        }
        Some((head, tail)) => {
            let child = obj
                .entry(head.to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if !child.is_object() {
                *child = Value::Object(Map::new());
            }
            if let Value::Object(child_obj) = child {
                insert_nested(child_obj, tail, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn labels(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Parse with a throwaway diagnostics sink, for tests that only assert the
    /// parsed config.
    fn parse(l: &std::collections::HashMap<String, String>) -> BTreeMap<String, Value> {
        let mut diags = Vec::new();
        parse_plugin_config(l, "sozune.http.web.", &mut diags)
    }

    #[test]
    fn absent_yields_empty() {
        assert!(parse(&labels(&[])).is_empty());
    }

    #[test]
    fn single_plugin_single_key() {
        let l = labels(&[("sozune.http.web.plugins.umami.websiteId", "abc-123")]);
        assert_eq!(parse(&l)["umami"], json!({ "websiteId": "abc-123" }));
    }

    #[test]
    fn multiple_keys_same_plugin() {
        let l = labels(&[
            (
                "sozune.http.web.plugins.crowdsec.lapi_host",
                "crowdsec:8080",
            ),
            ("sozune.http.web.plugins.crowdsec.lapi_key", "secret"),
        ]);
        assert_eq!(
            parse(&l)["crowdsec"],
            json!({ "lapi_host": "crowdsec:8080", "lapi_key": "secret" })
        );
    }

    #[test]
    fn separate_plugins_are_separate_keys() {
        let l = labels(&[
            ("sozune.http.web.plugins.umami.websiteId", "w1"),
            ("sozune.http.web.plugins.crowdsec.lapi_key", "k1"),
        ]);
        let out = parse(&l);
        assert_eq!(out.len(), 2);
        assert_eq!(out["umami"], json!({ "websiteId": "w1" }));
        assert_eq!(out["crowdsec"], json!({ "lapi_key": "k1" }));
    }

    #[test]
    fn typed_values_are_preserved() {
        let l = labels(&[
            ("sozune.http.web.plugins.p.enabled", "true"),
            ("sozune.http.web.plugins.p.count", "42"),
            ("sozune.http.web.plugins.p.host", "host:1"),
        ]);
        assert_eq!(
            parse(&l)["p"],
            json!({ "enabled": true, "count": 42, "host": "host:1" })
        );
    }

    #[test]
    fn nested_keys_build_objects() {
        let l = labels(&[("sozune.http.web.plugins.umami.tracking.mode", "spa")]);
        assert_eq!(parse(&l)["umami"], json!({ "tracking": { "mode": "spa" } }));
    }

    #[test]
    fn deeper_key_overwrites_leaf_collision() {
        // Keys are processed in sorted order, so `p.a` (a leaf) is set before
        // `p.a.b`; the leaf is overwritten with an object so the later key
        // still applies. The discarded leaf is the documented trade-off.
        let l = labels(&[
            ("sozune.http.web.plugins.p.a", "leaf"),
            ("sozune.http.web.plugins.p.a.b", "deep"),
        ]);
        assert_eq!(parse(&l)["p"], json!({ "a": { "b": "deep" } }));
    }

    #[test]
    fn json_array_and_object_values_are_preserved() {
        let l = labels(&[
            ("sozune.http.web.plugins.p.list", "[\"a\",\"b\"]"),
            ("sozune.http.web.plugins.p.obj", "{\"k\":1}"),
        ]);
        assert_eq!(
            parse(&l)["p"],
            json!({ "list": ["a", "b"], "obj": { "k": 1 } })
        );
    }

    #[test]
    fn bare_plugin_name_without_subkey_is_ignored_and_warns() {
        // `plugins.umami` with no sub-key is ignored, but now surfaces a W026 so
        // the operator knows; the bare `plugins=umami` list label does not (it
        // lacks the `plugins.` config prefix).
        let l = labels(&[
            ("sozune.http.web.plugins.umami", "x"),
            ("sozune.http.web.plugins", "umami"),
        ]);
        let mut diags = Vec::new();
        let out = parse_plugin_config(&l, "sozune.http.web.", &mut diags);
        assert!(out.is_empty());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W026InvalidPluginConfig);
    }

    #[test]
    fn over_deep_key_is_dropped_and_warns() {
        // A key nested past the depth cap must be dropped (no stack blow-up) and
        // surface a W026 rather than silently building a huge tree.
        let deep = format!("a{}", ".a".repeat(MAX_PLUGIN_CONFIG_DEPTH + 2));
        let key = format!("sozune.http.web.plugins.p.{deep}");
        let l = labels(&[(key.as_str(), "v")]);
        let mut diags = Vec::new();
        let out = parse_plugin_config(&l, "sozune.http.web.", &mut diags);
        assert!(out.is_empty());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W026InvalidPluginConfig);
    }
}
