//! Named middlewares: a set of route options, defined once and referenced
//! by name from routes (`sozune.http.<route>.middlewares=a,b`), as Traefik's
//! middlewares and its `chain` are.
//!
//! A middleware is defined on the workload itself
//! (`sozune.middlewares.<name>.<option>=<value>`), or in static config
//! (`middlewares:`), which every label provider shares. Its options are the
//! route labels without their `sozune.<protocol>.<route>.` prefix:
//! `headers.response.X-Frame-Options`, `ratelimit.average`… A route that
//! references it gets them before its labels are read, so every option
//! works the same there. The route's own labels win; in the list, a later
//! middleware wins over an earlier one. `chain=a,b` in a definition brings
//! in other middlewares, its own options winning over theirs.

use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, RwLock};

/// A middleware's options, by name.
pub type Definitions = BTreeMap<String, BTreeMap<String, String>>;

/// The middlewares of static config, shared by every workload.
static SHARED: LazyLock<RwLock<Definitions>> = LazyLock::new(Default::default);

const NAMESPACE: &str = "sozune.middlewares.";
const CHAIN: &str = "chain";
/// How deep chains may nest.
const MAX_DEPTH: usize = 16;

/// Set the middlewares of static config.
pub fn set_shared(definitions: Definitions) {
    if let Ok(mut shared) = SHARED.write() {
        *shared = definitions;
    }
}

/// Whether `key` defines a middleware on a workload.
pub fn is_definition(key: &str) -> bool {
    key.strip_prefix(NAMESPACE)
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(name, option)| !name.is_empty() && !option.is_empty())
}

/// Whether `option` is one a middleware may set: a route option, or
/// `chain`.
pub fn is_option(option: &str) -> bool {
    option == CHAIN || crate::labels::catalog::is_route_option(option)
}

/// The middlewares `labels` define.
fn local(labels: &HashMap<String, String>) -> Definitions {
    let mut definitions = Definitions::new();
    for (key, value) in labels {
        if let Some((name, option)) = key
            .strip_prefix(NAMESPACE)
            .and_then(|rest| rest.split_once('.'))
        {
            definitions
                .entry(name.to_string())
                .or_default()
                .insert(option.to_string(), value.clone());
        }
    }
    definitions
}

fn names(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
}

fn invalid(label: &str, value: &str, message: String, hint: &str) -> Diagnostic {
    Diagnostic::new(DiagnosticCode::W038InvalidMiddleware, message)
        .with_label(label)
        .with_value(value)
        .with_hint(hint)
}

/// What resolves the middlewares of one workload.
struct Resolver<'a> {
    local: &'a Definitions,
    shared: &'a Definitions,
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl Resolver<'_> {
    /// The options of middleware `name`, its chain's first, into `out`.
    /// `stack` holds the middlewares being resolved, to tell a cycle;
    /// `label` is where `name` was referenced.
    fn resolve(
        &mut self,
        name: &str,
        label: &str,
        stack: &mut Vec<String>,
        out: &mut BTreeMap<String, String>,
    ) {
        if stack.iter().any(|n| n == name) || stack.len() >= MAX_DEPTH {
            stack.push(name.to_string());
            let cycle = stack.join(" -> ");
            stack.pop();
            self.diagnostics.push(invalid(
                label,
                name,
                format!("middleware '{name}' refers back to itself ({cycle}), not applied again"),
                "break the cycle in the chain options",
            ));
            return;
        }
        let Some(definition) = self.local.get(name).or_else(|| self.shared.get(name)) else {
            self.diagnostics.push(invalid(
                label,
                name,
                format!("no middleware named '{name}', ignored"),
                "define it with sozune.middlewares.<name>.<option> labels on this workload, or under middlewares: in static config",
            ));
            return;
        };
        stack.push(name.to_string());
        let definition_label = format!("{NAMESPACE}{name}.{CHAIN}");
        if let Some(chain) = definition.get(CHAIN) {
            for child in names(chain) {
                self.resolve(&child, &definition_label, stack, out);
            }
        }
        for (option, value) in definition {
            if option == CHAIN {
                continue;
            }
            if is_option(option) {
                out.insert(option.clone(), value.clone());
            } else {
                self.diagnostics.push(invalid(
                    &format!("{NAMESPACE}{name}.{option}"),
                    value,
                    format!("middleware '{name}' sets '{option}', which is no route option, ignored"),
                    "a middleware's options are route labels without their sozune.<protocol>.<route>. prefix",
                ));
            }
        }
        stack.pop();
    }
}

/// `labels`, with the options of the middlewares each route references
/// added, where the route does not set them itself.
pub fn expand(
    labels: &HashMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> HashMap<String, String> {
    if !labels.keys().any(|key| is_reference(key)) {
        return labels.clone();
    }
    let shared = SHARED.read().map(|s| s.clone()).unwrap_or_default();
    expand_with(labels, &shared, diagnostics)
}

/// Whether `key` is a route's list of middlewares.
fn is_reference(key: &str) -> bool {
    key.ends_with(".middlewares") && !key.starts_with(NAMESPACE)
}

/// [`expand`], with `shared` as static config's middlewares.
fn expand_with(
    labels: &HashMap<String, String>,
    shared: &Definitions,
    diagnostics: &mut Vec<Diagnostic>,
) -> HashMap<String, String> {
    let local = local(labels);
    let mut expanded = labels.clone();
    let mut resolver = Resolver {
        local: &local,
        shared,
        diagnostics,
    };
    let mut references: Vec<(&String, &String)> =
        labels.iter().filter(|(key, _)| is_reference(key)).collect();
    references.sort();
    for (key, value) in references {
        let prefix = key.trim_end_matches("middlewares");
        let mut options = BTreeMap::new();
        for name in names(value) {
            resolver.resolve(&name, key, &mut Vec::new(), &mut options);
        }
        for (option, value) in options {
            expanded.entry(format!("{prefix}{option}")).or_insert(value);
        }
    }
    expanded
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

    fn expand_with(
        shared: &Definitions,
        pairs: &[(&str, &str)],
    ) -> (HashMap<String, String>, Vec<Diagnostic>) {
        let mut diagnostics = Vec::new();
        // The shared ones given here, not the process-wide registry, which
        // other tests may set.
        let expanded = super::expand_with(&labels(pairs), shared, &mut diagnostics);
        (expanded, diagnostics)
    }

    fn shared(defs: &[(&str, &[(&str, &str)])]) -> Definitions {
        defs.iter()
            .map(|(name, options)| {
                (
                    name.to_string(),
                    options
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn a_route_gets_the_options_of_its_middlewares() {
        let shared = shared(&[(
            "secure",
            &[
                ("headers.response.X-Frame-Options", "DENY"),
                ("compress", "true"),
            ],
        )]);
        let (labels, diagnostics) = expand_with(
            &shared,
            &[
                ("sozune.http.web.host", "a.example.com"),
                ("sozune.http.web.middlewares", "secure"),
            ],
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            labels["sozune.http.web.headers.response.X-Frame-Options"],
            "DENY"
        );
        assert_eq!(labels["sozune.http.web.compress"], "true");
    }

    /// The route's own labels win; a later middleware wins over an earlier
    /// one; a definition on the workload wins over static config's.
    #[test]
    fn what_wins() {
        let shared = shared(&[
            (
                "a",
                &[("ratelimit.average", "10"), ("ratelimit.burst", "1")],
            ),
            ("b", &[("ratelimit.average", "20")]),
            ("local", &[("compress", "false")]),
        ]);
        let (labels, _) = expand_with(
            &shared,
            &[
                ("sozune.http.web.middlewares", "a, b, local"),
                ("sozune.http.web.ratelimit.burst", "5"),
                ("sozune.middlewares.local.compress", "true"),
            ],
        );
        assert_eq!(labels["sozune.http.web.ratelimit.average"], "20");
        assert_eq!(labels["sozune.http.web.ratelimit.burst"], "5");
        assert_eq!(labels["sozune.http.web.compress"], "true");
    }

    /// A chain brings in other middlewares, its own options winning.
    #[test]
    fn a_chain_brings_in_other_middlewares() {
        let (labels, diagnostics) = expand_with(
            &Definitions::new(),
            &[
                ("sozune.http.web.middlewares", "all"),
                ("sozune.middlewares.all.chain", "headers,limits"),
                ("sozune.middlewares.all.ratelimit.average", "50"),
                ("sozune.middlewares.headers.headers.X-Env", "prod"),
                ("sozune.middlewares.limits.ratelimit.average", "10"),
                ("sozune.middlewares.limits.ratelimit.burst", "2"),
            ],
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(labels["sozune.http.web.headers.X-Env"], "prod");
        assert_eq!(labels["sozune.http.web.ratelimit.average"], "50");
        assert_eq!(labels["sozune.http.web.ratelimit.burst"], "2");
        assert!(!labels.contains_key("sozune.http.web.chain"));
    }

    #[test]
    fn an_unknown_middleware_or_a_cycle_is_reported() {
        let (_, diagnostics) = expand_with(
            &Definitions::new(),
            &[("sozune.http.web.middlewares", "nothing")],
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, DiagnosticCode::W038InvalidMiddleware);

        let (labels, diagnostics) = expand_with(
            &Definitions::new(),
            &[
                ("sozune.http.web.middlewares", "a"),
                ("sozune.middlewares.a.chain", "b"),
                ("sozune.middlewares.a.compress", "true"),
                ("sozune.middlewares.b.chain", "a"),
            ],
        );
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert!(diagnostics[0].message.contains("a -> b -> a"));
        // What the cycle does not hold still applies.
        assert_eq!(labels["sozune.http.web.compress"], "true");
    }

    #[test]
    fn an_option_that_is_no_route_option_is_reported() {
        let (labels, diagnostics) = expand_with(
            &Definitions::new(),
            &[
                ("sozune.http.web.middlewares", "m"),
                ("sozune.middlewares.m.compres", "true"),
            ],
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(!labels.contains_key("sozune.http.web.compres"));
    }

    #[test]
    fn definitions_are_told_apart() {
        assert!(is_definition("sozune.middlewares.secure.compress"));
        assert!(!is_definition("sozune.middlewares.secure"));
        assert!(!is_definition("sozune.http.web.middlewares"));
        assert!(is_option("chain"));
        assert!(is_option("headers.response.X-Frame-Options"));
        assert!(!is_option("compres"));
    }
}
