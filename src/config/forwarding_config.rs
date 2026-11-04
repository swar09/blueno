use serde::Deserialize;

use crate::config::serde_defaults::{default_false, default_true};
use crate::config::x_forwarded_for_mode::XForwardedForMode;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForwardingConfig {
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub x_forwarded_for: XForwardedForMode,
    #[serde(default = "default_true")]
    pub x_real_ip: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_proto: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_host: bool,
    #[serde(default = "default_false")]
    pub forwarded: bool,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            x_forwarded_for: XForwardedForMode::default(),
            x_real_ip: true,
            x_forwarded_proto: true,
            x_forwarded_host: true,
            forwarded: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeadersConfig;

    #[test]
    fn default_has_no_trusted_proxies() {
        let config: ForwardingConfig = toml::from_str("").expect("empty table parses");
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config, ForwardingConfig::default());
    }

    #[test]
    fn defaults_enable_standard_headers_only() {
        let config = ForwardingConfig::default();
        assert_eq!(config.x_forwarded_for, XForwardedForMode::Append);
        assert!(config.x_real_ip);
        assert!(config.x_forwarded_proto);
        assert!(config.x_forwarded_host);
        assert!(!config.forwarded);
    }

    #[test]
    fn each_x_forwarded_for_mode_parses() {
        for (text, mode) in [
            ("append", XForwardedForMode::Append),
            ("replace", XForwardedForMode::Replace),
            ("off", XForwardedForMode::Off),
        ] {
            let config: ForwardingConfig =
                toml::from_str(&format!("x_forwarded_for = \"{text}\"")).expect("mode parses");
            assert_eq!(config.x_forwarded_for, mode);
        }
    }

    #[test]
    fn unknown_x_forwarded_for_mode_is_rejected() {
        let result = toml::from_str::<ForwardingConfig>("x_forwarded_for = \"bogus\"");
        assert!(result.is_err());
    }

    #[test]
    fn toggles_parse() {
        let config: ForwardingConfig = toml::from_str(
            r#"
            x_real_ip = false
            x_forwarded_proto = false
            x_forwarded_host = false
            forwarded = true
            "#,
        )
        .expect("toggles parse");
        assert!(!config.x_real_ip);
        assert!(!config.x_forwarded_proto);
        assert!(!config.x_forwarded_host);
        assert!(config.forwarded);
    }

    #[test]
    fn trusted_proxies_list_parses() {
        let config: ForwardingConfig =
            toml::from_str(r#"trusted_proxies = ["10.0.0.0/8", "192.168.1.10"]"#)
                .expect("list parses");
        assert_eq!(
            config.trusted_proxies,
            vec!["10.0.0.0/8".to_string(), "192.168.1.10".to_string()]
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let result = toml::from_str::<ForwardingConfig>("bogus = 1");
        assert!(result.is_err());
    }

    #[test]
    fn nested_under_headers_table() {
        let config: HeadersConfig = toml::from_str(
            r#"
            [forwarding]
            trusted_proxies = ["::1"]
            "#,
        )
        .expect("nested table parses");
        assert_eq!(config.forwarding.trusted_proxies, vec!["::1".to_string()]);
    }
}
