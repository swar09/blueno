use serde::Deserialize;

use crate::config::forwarding_config::ForwardingConfig;
use crate::config::header_rule_config::HeaderRuleConfig;
use crate::config::serde_defaults::default_true;

pub const DEFAULT_ALLOWED_HEADERS: [&str; 11] = [
    "authorization",
    "content-type",
    "content-length",
    "accept",
    "accept-encoding",
    "user-agent",
    "host",
    "origin",
    "x-request-id",
    "access-control-request-method",
    "access-control-request-headers",
];

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeadersConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub filter: HeaderFilter,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: Vec<HeaderRuleConfig>,
    #[serde(default)]
    pub add: Vec<HeaderRuleConfig>,
    #[serde(default)]
    pub safety: HeaderSafetyConfig,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
}

impl Default for HeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            filter: HeaderFilter::default(),
            remove: Vec::new(),
            set: Vec::new(),
            add: Vec::new(),
            safety: HeaderSafetyConfig::default(),
            forwarding: ForwardingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(try_from = "RawHeaderFilter")]
#[non_exhaustive]
pub enum HeaderFilter {
    Allowlist { names: Vec<String> },
    Denylist { names: Vec<String> },
    Passthrough,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeaderFilter {
    mode: String,
    names: Option<Vec<String>>,
}

impl TryFrom<RawHeaderFilter> for HeaderFilter {
    type Error = String;

    fn try_from(raw: RawHeaderFilter) -> Result<Self, Self::Error> {
        match (raw.mode.as_str(), raw.names) {
            ("allowlist", Some(names)) => Ok(Self::Allowlist { names }),
            ("denylist", Some(names)) => Ok(Self::Denylist { names }),
            ("allowlist" | "denylist", None) => {
                Err(format!("filter mode '{}' requires 'names'", raw.mode))
            }
            ("passthrough", None) => Ok(Self::Passthrough),
            ("passthrough", Some(_)) => {
                Err("filter mode 'passthrough' does not accept 'names'".to_string())
            }
            (other, _) => Err(format!(
                "unknown filter mode '{other}': expected allowlist, denylist or passthrough"
            )),
        }
    }
}

impl Default for HeaderFilter {
    fn default() -> Self {
        Self::Allowlist {
            names: DEFAULT_ALLOWED_HEADERS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderSafetyConfig {
    #[serde(default = "default_true")]
    pub strip_identity_headers: bool,
    #[serde(default = "default_true")]
    pub strip_hop_by_hop: bool,
}

impl Default for HeaderSafetyConfig {
    fn default() -> Self {
        Self {
            strip_identity_headers: true,
            strip_hop_by_hop: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiGatewayConfig;

    fn default_names() -> Vec<String> {
        DEFAULT_ALLOWED_HEADERS
            .iter()
            .map(|name| (*name).to_string())
            .collect()
    }

    #[test]
    fn default_is_allowlist_of_eleven_names() {
        let config = HeadersConfig::default();
        assert!(config.enabled);
        assert!(config.safety.strip_identity_headers);
        assert!(config.safety.strip_hop_by_hop);
        let HeaderFilter::Allowlist { names } = config.filter else {
            panic!("default filter is an allowlist");
        };
        assert_eq!(names.len(), 11);
        assert_eq!(names, default_names());
    }

    #[test]
    fn empty_table_uses_defaults() {
        let config: HeadersConfig = toml::from_str("").expect("empty table parses");
        assert_eq!(config, HeadersConfig::default());
    }

    #[test]
    fn explicit_allowlist_parses() {
        let config: HeadersConfig = toml::from_str(
            r#"
            enabled = false
            [filter]
            mode = "allowlist"
            names = ["x-a", "X-B"]
            [safety]
            strip_identity_headers = false
            strip_hop_by_hop = false
            "#,
        )
        .expect("valid config parses");
        assert!(!config.enabled);
        assert_eq!(
            config.filter,
            HeaderFilter::Allowlist {
                names: vec!["x-a".to_string(), "X-B".to_string()]
            }
        );
        assert!(!config.safety.strip_identity_headers);
        assert!(!config.safety.strip_hop_by_hop);
    }

    #[test]
    fn denylist_with_names_parses() {
        let config: HeadersConfig = toml::from_str(
            r#"
            [filter]
            mode = "denylist"
            names = ["cookie", "x-internal-*"]
            "#,
        )
        .expect("valid config parses");
        assert_eq!(
            config.filter,
            HeaderFilter::Denylist {
                names: vec!["cookie".to_string(), "x-internal-*".to_string()]
            }
        );
    }

    #[test]
    fn passthrough_parses() {
        let config: HeadersConfig = toml::from_str(
            r#"
            [filter]
            mode = "passthrough"
            "#,
        )
        .expect("valid config parses");
        assert_eq!(config.filter, HeaderFilter::Passthrough);
    }

    #[test]
    fn passthrough_with_names_fails() {
        let result = toml::from_str::<HeadersConfig>(
            r#"
            [filter]
            mode = "passthrough"
            names = ["cookie"]
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn denylist_without_names_fails() {
        let result = toml::from_str::<HeadersConfig>(
            r#"
            [filter]
            mode = "denylist"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn unknown_mode_fails() {
        let result = toml::from_str::<HeadersConfig>(
            r#"
            [filter]
            mode = "bogus"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn unknown_filter_field_fails() {
        let result = toml::from_str::<HeadersConfig>(
            r#"
            [filter]
            mode = "allowlist"
            names = []
            extra = 1
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn remove_set_and_add_parse() {
        let config: HeadersConfig = toml::from_str(
            r#"
            remove = ["x-powered-by", "x-debug-*"]

            [[set]]
            name = "x-real-ip"
            value = "{client_ip}"

            [[add]]
            name = "x-gateway"
            value = "blueno"
            "#,
        )
        .expect("valid config parses");
        assert_eq!(config.remove, vec!["x-powered-by", "x-debug-*"]);
        assert_eq!(
            config.set,
            vec![HeaderRuleConfig {
                name: "x-real-ip".to_string(),
                value: "{client_ip}".to_string()
            }]
        );
        assert_eq!(
            config.add,
            vec![HeaderRuleConfig {
                name: "x-gateway".to_string(),
                value: "blueno".to_string()
            }]
        );
    }

    #[test]
    fn unknown_field_in_rule_fails() {
        let result = toml::from_str::<HeadersConfig>(
            r#"
            [[set]]
            name = "x-a"
            value = "b"
            extra = 1
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rule_missing_value_fails() {
        let result = toml::from_str::<HeadersConfig>(
            r#"
            [[add]]
            name = "x-a"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn missing_headers_table_in_gateway_config_uses_defaults() {
        let config: ApiGatewayConfig = toml::from_str("").expect("empty config parses");
        assert_eq!(config.headers, HeadersConfig::default());
    }
}
