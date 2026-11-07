use axum::http::{HeaderMap, HeaderName, HeaderValue};

use crate::config::{HeaderFilter, HeaderRuleConfig, HeaderSafetyConfig, HeadersConfig};
use crate::header_policy::client_ip_resolver::ClientIpResolver;
use crate::header_policy::forwarding_policy::ForwardingPolicy;
use crate::header_policy::header_name_pattern::HeaderNamePattern;
use crate::header_policy::header_policy_error::HeaderPolicyError;
use crate::header_policy::header_template::HeaderTemplate;
use crate::header_policy::render_error::RenderError;
use crate::header_policy::request_context::RequestContext;
use crate::header_policy::reserved_headers::{
    IDENTITY_HEADERS, is_hop_by_hop_header, is_identity_header,
};

#[derive(Debug, Clone)]
enum CompiledFilter {
    Allow(Vec<HeaderNamePattern>),
    Deny(Vec<HeaderNamePattern>),
    Passthrough,
}

impl CompiledFilter {
    fn compile(
        filter: &HeaderFilter,
        strip_identity_headers: bool,
    ) -> Result<Self, HeaderPolicyError> {
        match filter {
            HeaderFilter::Allowlist { names } => {
                let patterns = Self::parse_all(names)?;
                if strip_identity_headers {
                    for pattern in &patterns {
                        if Self::matches_identity_header(pattern) {
                            return Err(HeaderPolicyError::Reserved {
                                name: pattern.to_string(),
                                reason: "identity headers are set by the gateway and cannot be allowlisted",
                            });
                        }
                    }
                }
                Ok(Self::Allow(patterns))
            }
            HeaderFilter::Denylist { names } => Ok(Self::Deny(Self::parse_all(names)?)),
            HeaderFilter::Passthrough => Ok(Self::Passthrough),
        }
    }

    fn parse_all(names: &[String]) -> Result<Vec<HeaderNamePattern>, HeaderPolicyError> {
        names
            .iter()
            .map(|raw| HeaderNamePattern::parse(raw))
            .collect()
    }

    fn matches_identity_header(pattern: &HeaderNamePattern) -> bool {
        IDENTITY_HEADERS
            .iter()
            .any(|name| pattern.matches(&HeaderName::from_static(name)))
    }

    fn keeps(&self, name: &HeaderName) -> bool {
        match self {
            Self::Allow(patterns) => patterns.iter().any(|pattern| pattern.matches(name)),
            Self::Deny(patterns) => !patterns.iter().any(|pattern| pattern.matches(name)),
            Self::Passthrough => true,
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: HeaderName,
    template: HeaderTemplate,
}

impl CompiledRule {
    fn compile(
        config: &HeaderRuleConfig,
        safety: &HeaderSafetyConfig,
    ) -> Result<Self, HeaderPolicyError> {
        let HeaderNamePattern::Exact(name) = HeaderNamePattern::parse(&config.name)? else {
            return Err(HeaderPolicyError::InvalidPattern {
                pattern: config.name.clone(),
                reason: "set and add rules need an exact header name, not a wildcard",
            });
        };
        if safety.strip_identity_headers && is_identity_header(&name) {
            return Err(HeaderPolicyError::Reserved {
                name: name.to_string(),
                reason: "identity headers are set by the gateway and cannot be set or added",
            });
        }
        if safety.strip_hop_by_hop && is_hop_by_hop_header(&name) {
            return Err(HeaderPolicyError::Reserved {
                name: name.to_string(),
                reason: "hop-by-hop headers are stripped by the gateway and cannot be set or added",
            });
        }
        let template = HeaderTemplate::parse(name.as_str(), &config.value)?;
        Ok(Self { name, template })
    }

    fn compile_all(
        rules: &[HeaderRuleConfig],
        safety: &HeaderSafetyConfig,
    ) -> Result<Vec<Self>, HeaderPolicyError> {
        rules
            .iter()
            .map(|rule| Self::compile(rule, safety))
            .collect()
    }

    fn render(&self, context: &RequestContext) -> Option<HeaderValue> {
        match self.template.render(context) {
            Ok(value) => Some(value),
            Err(RenderError::Missing(variable)) => {
                tracing::debug!(header = %self.name, ?variable, "skipping header: template data unavailable");
                None
            }
            Err(RenderError::InvalidValue) => {
                tracing::warn!(header = %self.name, "skipping header: rendered value is not a valid header value");
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeaderPolicy {
    enabled: bool,
    filter: CompiledFilter,
    remove: Vec<HeaderNamePattern>,
    set: Vec<CompiledRule>,
    add: Vec<CompiledRule>,
    strip_identity_headers: bool,
    strip_hop_by_hop: bool,
    client_ip_resolver: ClientIpResolver,
    forwarding: ForwardingPolicy,
    needs_context: bool,
}

impl Default for HeaderPolicy {
    fn default() -> Self {
        Self::from_config(&HeadersConfig::default())
            .expect("default headers config is valid by construction")
    }
}

impl HeaderPolicy {
    pub fn from_config(config: &HeadersConfig) -> Result<Self, HeaderPolicyError> {
        let strip_identity_headers = config.safety.strip_identity_headers;
        let filter = CompiledFilter::compile(&config.filter, strip_identity_headers)?;

        if config.enabled && !strip_identity_headers {
            tracing::warn!(
                headers = ?IDENTITY_HEADERS,
                "strip_identity_headers is disabled: clients can forge identity headers on routes without auth, and passthrough or denylist filters forward them unchanged"
            );
        }

        let remove = CompiledFilter::parse_all(&config.remove)?;
        let set = CompiledRule::compile_all(&config.set, &config.safety)?;
        let add = CompiledRule::compile_all(&config.add, &config.safety)?;

        let client_ip_resolver = ClientIpResolver::new(&config.forwarding.trusted_proxies)?;

        let forwarding = ForwardingPolicy::from_config(&config.forwarding);
        let needs_context = config.enabled
            && (forwarding.is_active()
                || set
                    .iter()
                    .chain(&add)
                    .any(|rule| !rule.template.is_static()));

        Ok(Self {
            enabled: config.enabled,
            filter,
            remove,
            set,
            add,
            strip_identity_headers,
            strip_hop_by_hop: config.safety.strip_hop_by_hop,
            client_ip_resolver,
            forwarding,
            needs_context,
        })
    }

    pub fn client_ip_resolver(&self) -> &ClientIpResolver {
        &self.client_ip_resolver
    }

    pub fn needs_context(&self) -> bool {
        self.needs_context
    }

    pub fn strip_hop_by_hop(&self) -> bool {
        self.strip_hop_by_hop
    }

    pub fn apply(&self, headers: &mut HeaderMap, context: &RequestContext) {
        if !self.enabled {
            return;
        }
        let incoming = self.forwarding.capture(headers, context);
        if self.strip_identity_headers {
            for name in IDENTITY_HEADERS {
                headers.remove(name);
            }
        }
        self.apply_filter(headers);
        self.apply_remove(headers);
        self.forwarding.apply(headers, &incoming, context);
        for rule in &self.set {
            if let Some(value) = rule.render(context) {
                headers.insert(rule.name.clone(), value);
            }
        }
        for rule in &self.add {
            if let Some(value) = rule.render(context) {
                headers.append(rule.name.clone(), value);
            }
        }
    }

    fn apply_filter(&self, headers: &mut HeaderMap) {
        if matches!(self.filter, CompiledFilter::Passthrough) {
            return;
        }
        let disallowed: Vec<HeaderName> = headers
            .keys()
            .filter(|name| !self.filter.keeps(name))
            .cloned()
            .collect();
        for name in disallowed {
            headers.remove(name);
        }
    }

    fn apply_remove(&self, headers: &mut HeaderMap) {
        if self.remove.is_empty() {
            return;
        }
        let doomed: Vec<HeaderName> = headers
            .keys()
            .filter(|name| self.remove.iter().any(|pattern| pattern.matches(name)))
            .cloned()
            .collect();
        for name in doomed {
            headers.remove(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ForwardingConfig, HeaderSafetyConfig};
    use axum::http::HeaderValue;

    fn config_with(names: &[&str], strip_identity: bool) -> HeadersConfig {
        HeadersConfig {
            enabled: true,
            filter: HeaderFilter::Allowlist {
                names: names.iter().map(|name| (*name).to_string()).collect(),
            },
            safety: HeaderSafetyConfig {
                strip_identity_headers: strip_identity,
                strip_hop_by_hop: true,
            },
            forwarding: ForwardingConfig::default(),
            ..Default::default()
        }
    }

    fn headers_of(names: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for name in names {
            headers.insert(HeaderName::from_static(name), HeaderValue::from_static("v"));
        }
        headers
    }

    #[test]
    fn invalid_name_is_rejected() {
        let result = HeaderPolicy::from_config(&config_with(&["bad name"], true));
        assert!(matches!(result, Err(HeaderPolicyError::InvalidName { .. })));
    }

    #[test]
    fn identity_header_in_allowlist_is_reserved_when_stripping() {
        let result = HeaderPolicy::from_config(&config_with(&["X-User-Id"], true));
        assert!(matches!(result, Err(HeaderPolicyError::Reserved { .. })));
    }

    #[test]
    fn identity_header_in_allowlist_is_ok_when_not_stripping() {
        let result = HeaderPolicy::from_config(&config_with(&["x-user-id"], false));
        assert!(result.is_ok());
    }

    #[test]
    fn apply_keeps_only_allowlisted_headers() {
        let policy = HeaderPolicy::from_config(&config_with(&["accept"], true)).expect("valid");
        let mut headers = headers_of(&["accept", "x-evil"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("accept"));
    }

    #[test]
    fn apply_is_case_insensitive_for_config_names() {
        let policy =
            HeaderPolicy::from_config(&config_with(&["Content-Type"], true)).expect("valid");
        let mut headers = headers_of(&["content-type", "x-evil"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert!(headers.contains_key("content-type"));
        assert!(!headers.contains_key("x-evil"));
    }

    #[test]
    fn apply_removes_identity_headers() {
        let policy = HeaderPolicy::from_config(&config_with(&["x-user-id", "accept"], false))
            .expect("valid");
        let mut headers = headers_of(&["x-user-id", "accept"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert!(headers.contains_key("x-user-id"));

        let strict = HeaderPolicy::default();
        let mut headers = headers_of(&["x-user-id", "x-user-role", "x-token-id", "accept"]);
        strict.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("accept"));
    }

    fn config_with_filter(filter: HeaderFilter, strip_identity: bool) -> HeadersConfig {
        HeadersConfig {
            filter,
            ..config_with(&[], strip_identity)
        }
    }

    fn denylist(names: &[&str]) -> HeaderFilter {
        HeaderFilter::Denylist {
            names: names.iter().map(|name| (*name).to_string()).collect(),
        }
    }

    #[test]
    fn denylist_drops_only_listed_names() {
        let config = config_with_filter(denylist(&["cookie", "X-Internal-*"]), true);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["cookie", "x-internal-trace", "x-internalx", "x-custom"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert!(!headers.contains_key("cookie"));
        assert!(!headers.contains_key("x-internal-trace"));
        assert!(headers.contains_key("x-internalx"));
        assert!(headers.contains_key("x-custom"));
    }

    #[test]
    fn denylist_still_strips_identity_headers() {
        let config = config_with_filter(denylist(&["cookie"]), true);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["x-user-id", "x-user-role", "x-token-id", "x-custom"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("x-custom"));
    }

    #[test]
    fn passthrough_keeps_everything_except_identity_headers() {
        let config = config_with_filter(HeaderFilter::Passthrough, true);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["x-user-id", "x-token-id", "cookie", "x-custom"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("cookie"));
        assert!(headers.contains_key("x-custom"));
    }

    #[test]
    fn passthrough_without_identity_stripping_keeps_identity_headers() {
        let config = config_with_filter(HeaderFilter::Passthrough, false);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["x-user-id", "x-custom"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn allowlist_prefix_keeps_matching_headers() {
        let policy =
            HeaderPolicy::from_config(&config_with(&["x-app-*", "accept"], true)).expect("valid");
        let mut headers = headers_of(&["x-app-a", "x-app-b", "accept", "x-other"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 3);
        assert!(!headers.contains_key("x-other"));
    }

    #[test]
    fn allowlist_prefix_covering_identity_headers_is_reserved_when_stripping() {
        for pattern in ["x-user-*", "x-*", "x-token-*"] {
            let result = HeaderPolicy::from_config(&config_with(&[pattern], true));
            assert!(matches!(result, Err(HeaderPolicyError::Reserved { .. })));
        }
        let result = HeaderPolicy::from_config(&config_with(&["x-user-*"], false));
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_patterns_in_denylist_are_rejected() {
        let config = config_with_filter(denylist(&["x-*-id"]), true);
        let result = HeaderPolicy::from_config(&config);
        assert!(matches!(
            result,
            Err(HeaderPolicyError::InvalidPattern { .. })
        ));
    }

    #[test]
    fn disabled_policy_leaves_headers_untouched() {
        let mut config = config_with(&["accept"], true);
        config.enabled = false;
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["x-user-id", "x-evil", "accept"]);
        policy.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 3);
    }

    fn rule(name: &str, value: &str) -> HeaderRuleConfig {
        HeaderRuleConfig {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn passthrough_with(
        remove: &[&str],
        set: Vec<HeaderRuleConfig>,
        add: Vec<HeaderRuleConfig>,
    ) -> HeadersConfig {
        HeadersConfig {
            remove: remove.iter().map(|name| (*name).to_string()).collect(),
            set,
            add,
            ..config_with_filter(HeaderFilter::Passthrough, true)
        }
    }

    fn ip_context() -> RequestContext {
        RequestContext {
            client_ip: Some("127.0.0.1".parse().expect("valid ip")),
            scheme: "http".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn remove_drops_exact_and_prefix_matches() {
        let config = passthrough_with(&["X-Powered-By", "x-debug-*"], vec![], vec![]);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["x-powered-by", "x-debug-a", "x-debug-b", "x-keep"]);
        policy.apply(&mut headers, &ip_context());
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("x-keep"));
    }

    #[test]
    fn set_overwrites_existing_value() {
        let config = passthrough_with(&[], vec![rule("x-real-ip", "{client_ip}")], vec![]);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["x-real-ip"]);
        policy.apply(&mut headers, &ip_context());
        let values: Vec<&HeaderValue> = headers.get_all("x-real-ip").iter().collect();
        assert_eq!(values, vec![&HeaderValue::from_static("127.0.0.1")]);
    }

    #[test]
    fn add_appends_to_existing_value() {
        let config = passthrough_with(&[], vec![], vec![rule("x-tag", "gateway")]);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["x-tag"]);
        policy.apply(&mut headers, &ip_context());
        let values: Vec<&HeaderValue> = headers.get_all("x-tag").iter().collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1], &HeaderValue::from_static("gateway"));
    }

    #[test]
    fn set_and_add_survive_the_filter() {
        let config = HeadersConfig {
            set: vec![rule("x-set", "a")],
            add: vec![rule("x-add", "b")],
            ..config_with(&["accept"], true)
        };
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = headers_of(&["accept", "x-evil"]);
        policy.apply(&mut headers, &ip_context());
        assert!(headers.contains_key("x-set"));
        assert!(headers.contains_key("x-add"));
        assert!(!headers.contains_key("x-evil"));
    }

    #[test]
    fn identity_header_rules_are_reserved_when_stripping() {
        for config in [
            passthrough_with(&[], vec![rule("x-user-id", "a")], vec![]),
            passthrough_with(&[], vec![], vec![rule("X-User-Id", "a")]),
        ] {
            let result = HeaderPolicy::from_config(&config);
            assert!(matches!(result, Err(HeaderPolicyError::Reserved { .. })));
        }
    }

    #[test]
    fn identity_header_rules_are_ok_when_not_stripping() {
        let config = HeadersConfig {
            set: vec![rule("x-user-id", "a")],
            add: vec![rule("x-user-id", "b")],
            ..config_with_filter(HeaderFilter::Passthrough, false)
        };
        assert!(HeaderPolicy::from_config(&config).is_ok());
    }

    #[test]
    fn hop_by_hop_rule_is_reserved_when_stripping() {
        let config = passthrough_with(&[], vec![rule("transfer-encoding", "chunked")], vec![]);
        let result = HeaderPolicy::from_config(&config);
        assert!(matches!(result, Err(HeaderPolicyError::Reserved { .. })));
    }

    #[test]
    fn hop_by_hop_rule_is_ok_when_not_stripping() {
        let mut config = passthrough_with(&[], vec![rule("transfer-encoding", "chunked")], vec![]);
        config.safety.strip_hop_by_hop = false;
        assert!(HeaderPolicy::from_config(&config).is_ok());
    }

    #[test]
    fn wildcard_rule_name_is_rejected() {
        let config = passthrough_with(&[], vec![rule("x-*", "a")], vec![]);
        let result = HeaderPolicy::from_config(&config);
        assert!(matches!(
            result,
            Err(HeaderPolicyError::InvalidPattern { .. })
        ));
    }

    #[test]
    fn bad_template_is_rejected_at_startup() {
        let config = passthrough_with(&[], vec![rule("x-a", "{bogus}")], vec![]);
        let result = HeaderPolicy::from_config(&config);
        assert!(matches!(
            result,
            Err(HeaderPolicyError::UnknownVariable { .. })
        ));
    }

    #[test]
    fn invalid_rendered_value_is_skipped() {
        let config = passthrough_with(
            &[],
            vec![rule("x-host", "{host}"), rule("x-ok", "fine")],
            vec![],
        );
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let context = RequestContext {
            host: Some("bad\nhost".to_string()),
            ..ip_context()
        };
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &context);
        assert!(!headers.contains_key("x-host"));
        assert!(headers.contains_key("x-ok"));
    }

    #[test]
    fn missing_context_data_skips_header() {
        let config = passthrough_with(&[], vec![rule("x-real-ip", "{client_ip}")], vec![]);
        let policy = HeaderPolicy::from_config(&config).expect("valid");
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &RequestContext::default());
        assert!(headers.is_empty());
    }

    #[test]
    fn default_policy_exposes_hop_by_hop_flag() {
        assert!(HeaderPolicy::default().strip_hop_by_hop());
    }
}
