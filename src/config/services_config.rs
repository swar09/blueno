use serde::{Deserialize, Serialize};

use crate::config::serde_defaults::{default_false, default_true};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRuleConfig {
    pub path: String,
    pub upstream: String,
    #[serde(default = "default_true")]
    pub auth: bool,
    #[serde(default = "default_false")]
    pub rate_limit: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct ServicesConfig {
    #[serde(default)]
    pub default_upstream: Option<String>,
    #[serde(default)]
    pub routes: Vec<RouteRuleConfig>,
}

impl ServicesConfig {
    pub fn resolve_upstream(&self, path: &str) -> Option<&str> {
        let mut best: Option<(&str, usize)> = None;
        for route in &self.routes {
            let prefix = route.path.trim_end_matches('/');
            if path == prefix || path.starts_with(&format!("{prefix}/")) {
                let len = prefix.len();
                if best.as_ref().is_none_or(|(_, best_len)| len > *best_len) {
                    best = Some((&route.upstream, len));
                }
            }
        }
        if let Some((upstream, _)) = best {
            return Some(upstream);
        }
        self.default_upstream.as_deref()
    }
}
