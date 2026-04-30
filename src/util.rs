//! Small cross-module helpers (fuzzy matching, debug-mode flag).

pub mod fuzzy {
    /// Find the closest match in `haystack` for `needle`. Returns `None` if
    /// nothing is close enough. Substring containment in either direction is
    /// treated as distance 1 so cases like `timeout` → `backendTimeout` work
    /// even though raw Levenshtein distance is large.
    pub fn closest_match<'a>(
        needle: &str,
        haystack: &'a [&'a str],
        max_distance: usize,
    ) -> Option<&'a str> {
        let needle_lower = needle.to_lowercase();
        let mut best: Option<(&str, usize)> = None;
        for &candidate in haystack {
            let candidate_lower = candidate.to_lowercase();
            let d = if candidate_lower.contains(&needle_lower)
                || needle_lower.contains(&candidate_lower)
            {
                1
            } else {
                levenshtein(&needle_lower, &candidate_lower)
            };
            if d <= max_distance && best.is_none_or(|(_, bd)| d < bd) {
                best = Some((candidate, d));
            }
        }
        best.map(|(s, _)| s)
    }

    pub fn levenshtein(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let (n, m) = (a.len(), b.len());
        if n == 0 {
            return m;
        }
        if m == 0 {
            return n;
        }
        let mut prev: Vec<usize> = (0..=m).collect();
        let mut curr = vec![0usize; m + 1];
        for i in 1..=n {
            curr[0] = i;
            for j in 1..=m {
                let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
                curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
            }
            std::mem::swap(&mut prev, &mut curr);
        }
        prev[m]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn levenshtein_basics() {
            assert_eq!(levenshtein("", ""), 0);
            assert_eq!(levenshtein("abc", ""), 3);
            assert_eq!(levenshtein("", "abc"), 3);
            assert_eq!(levenshtein("abc", "abc"), 0);
            assert_eq!(levenshtein("abc", "abd"), 1);
            assert_eq!(levenshtein("kitten", "sitting"), 3);
        }

        #[test]
        fn closest_uses_substring_for_long_candidates() {
            let opts = ["backendTimeout", "port"];
            assert_eq!(closest_match("timeout", &opts, 2), Some("backendTimeout"));
        }

        #[test]
        fn closest_returns_none_when_far_off() {
            let opts = ["port", "host"];
            assert!(closest_match("xyzzy", &opts, 2).is_none());
        }

        #[test]
        fn closest_picks_shortest_distance() {
            let opts = ["port", "host", "path"];
            assert_eq!(closest_match("prt", &opts, 2), Some("port"));
        }
    }
}

/// Returns `true` when `SOZUNE_DEBUG=true`. Used to gate verbose runtime
/// diagnostics that may leak configured hostnames or backend addresses.
pub fn debug_enabled() -> bool {
    std::env::var("SOZUNE_DEBUG")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}
