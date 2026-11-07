use std::net::IpAddr;

use axum::http::header::FORWARDED;
use axum::http::{HeaderMap, HeaderName, HeaderValue};

use crate::config::{ForwardingConfig, XForwardedForMode};
use crate::header_policy::incoming_forwarding::IncomingForwarding;
use crate::header_policy::request_context::RequestContext;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

#[derive(Debug, Clone)]
pub(crate) struct ForwardingPolicy {
    x_forwarded_for: XForwardedForMode,
    x_real_ip: bool,
    x_forwarded_proto: bool,
    x_forwarded_host: bool,
    forwarded: bool,
}

impl ForwardingPolicy {
    pub(crate) fn from_config(config: &ForwardingConfig) -> Self {
        Self {
            x_forwarded_for: config.x_forwarded_for,
            x_real_ip: config.x_real_ip,
            x_forwarded_proto: config.x_forwarded_proto,
            x_forwarded_host: config.x_forwarded_host,
            forwarded: config.forwarded,
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.x_forwarded_for != XForwardedForMode::Off
            || self.x_real_ip
            || self.x_forwarded_proto
            || self.x_forwarded_host
            || self.forwarded
    }

    pub(crate) fn capture(
        &self,
        headers: &HeaderMap,
        context: &RequestContext,
    ) -> IncomingForwarding {
        if context.peer_ip.is_none() || !context.peer_trusted {
            return IncomingForwarding::default();
        }
        IncomingForwarding {
            chain: (self.x_forwarded_for == XForwardedForMode::Append)
                .then(|| Self::joined(headers, &X_FORWARDED_FOR))
                .flatten(),
            proto: self
                .x_forwarded_proto
                .then(|| Self::first(headers, &X_FORWARDED_PROTO))
                .flatten(),
            host: self
                .x_forwarded_host
                .then(|| Self::first(headers, &X_FORWARDED_HOST))
                .flatten(),
            forwarded: self
                .forwarded
                .then(|| Self::joined(headers, &FORWARDED))
                .flatten(),
        }
    }

    pub(crate) fn apply(
        &self,
        headers: &mut HeaderMap,
        incoming: &IncomingForwarding,
        context: &RequestContext,
    ) {
        let Some(peer) = context.peer_ip else {
            return;
        };
        self.apply_x_forwarded_for(headers, incoming, context, peer);
        if self.x_real_ip
            && let Some(client) = context.client_ip
        {
            Self::put(headers, X_REAL_IP, &client.to_string());
        }
        if self.x_forwarded_proto {
            let proto = incoming.proto.as_deref().unwrap_or(&context.scheme);
            Self::put(headers, X_FORWARDED_PROTO, proto);
        }
        if self.x_forwarded_host {
            let host = incoming.host.as_deref().or(context.host.as_deref());
            match host {
                Some(host) => Self::put(headers, X_FORWARDED_HOST, host),
                None => {
                    headers.remove(X_FORWARDED_HOST);
                }
            }
        }
        if self.forwarded {
            let element = Self::forwarded_element(peer, context);
            let value = match incoming.forwarded.as_deref() {
                Some(chain) => format!("{chain}, {element}"),
                None => element,
            };
            Self::put(headers, FORWARDED, &value);
        }
    }

    fn apply_x_forwarded_for(
        &self,
        headers: &mut HeaderMap,
        incoming: &IncomingForwarding,
        context: &RequestContext,
        peer: IpAddr,
    ) {
        let value = match self.x_forwarded_for {
            XForwardedForMode::Off => return,
            XForwardedForMode::Replace if context.peer_trusted => {
                context.client_ip.unwrap_or(peer).to_string()
            }
            XForwardedForMode::Append => match incoming.chain.as_deref() {
                Some(chain) => format!("{chain}, {peer}"),
                None => peer.to_string(),
            },
            XForwardedForMode::Replace => peer.to_string(),
        };
        Self::put(headers, X_FORWARDED_FOR, &value);
    }

    fn forwarded_element(peer: IpAddr, context: &RequestContext) -> String {
        let node = match peer {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("\"[{ip}]\""),
        };
        let mut element = format!(
            "for={node};proto={}",
            Self::quote_if_needed(&context.scheme)
        );
        if let Some(host) = context.host.as_deref() {
            element.push_str(";host=");
            element.push_str(&Self::quote_if_needed(host));
        }
        element
    }

    fn quote_if_needed(text: &str) -> String {
        let is_token = !text.is_empty()
            && text
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(ch));
        if is_token {
            return text.to_string();
        }
        let mut quoted = String::with_capacity(text.len() + 2);
        quoted.push('"');
        for ch in text.chars() {
            if ch == '"' || ch == '\\' {
                quoted.push('\\');
            }
            quoted.push(ch);
        }
        quoted.push('"');
        quoted
    }

    fn joined(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
        let lines: Vec<&str> = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        if lines.is_empty() {
            None
        } else {
            Some(lines.join(", "))
        }
    }

    fn first(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
        headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::trim)
            .find(|value| !value.is_empty())
            .map(str::to_string)
    }

    fn put(headers: &mut HeaderMap, name: HeaderName, value: &str) {
        match HeaderValue::from_str(value) {
            Ok(value) => {
                headers.insert(name, value);
            }
            Err(_) => {
                tracing::warn!(header = %name, "skipping forwarding header: value is not a valid header value");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HeaderFilter, HeaderRuleConfig, HeadersConfig};
    use crate::header_policy::HeaderPolicy;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid ip")
    }

    fn policy_with(forwarding: ForwardingConfig) -> HeaderPolicy {
        let config = HeadersConfig {
            filter: HeaderFilter::Passthrough,
            forwarding,
            ..Default::default()
        };
        HeaderPolicy::from_config(&config).expect("valid config")
    }

    fn only(mode: XForwardedForMode) -> ForwardingConfig {
        ForwardingConfig {
            x_forwarded_for: mode,
            x_real_ip: false,
            x_forwarded_proto: false,
            x_forwarded_host: false,
            forwarded: false,
            ..Default::default()
        }
    }

    fn context(peer: &str, client: &str, trusted: bool) -> RequestContext {
        RequestContext {
            client_ip: Some(ip(client)),
            peer_ip: Some(ip(peer)),
            peer_trusted: trusted,
            scheme: "http".to_string(),
            host: Some("example.com".to_string()),
            method: "GET".to_string(),
            ..Default::default()
        }
    }

    fn headers_with(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_static(name),
                HeaderValue::from_str(value).expect("valid value"),
            );
        }
        headers
    }

    fn values(headers: &HeaderMap, name: &str) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().expect("ascii").to_string())
            .collect()
    }

    #[test]
    fn untrusted_peer_spoofed_chain_is_replaced_by_peer() {
        let policy = policy_with(only(XForwardedForMode::Append));
        let mut headers = headers_with(&[("x-forwarded-for", "1.2.3.4")]);
        policy.apply(&mut headers, &context("203.0.113.9", "203.0.113.9", false));
        assert_eq!(values(&headers, "x-forwarded-for"), vec!["203.0.113.9"]);
    }

    #[test]
    fn untrusted_peer_replace_mode_also_uses_peer_only() {
        let policy = policy_with(only(XForwardedForMode::Replace));
        let mut headers = headers_with(&[("x-forwarded-for", "1.2.3.4")]);
        policy.apply(&mut headers, &context("203.0.113.9", "203.0.113.9", false));
        assert_eq!(values(&headers, "x-forwarded-for"), vec!["203.0.113.9"]);
    }

    #[test]
    fn trusted_peer_appends_to_chain() {
        let policy = policy_with(only(XForwardedForMode::Append));
        let mut headers = headers_with(&[("x-forwarded-for", "198.51.100.1")]);
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(
            values(&headers, "x-forwarded-for"),
            vec!["198.51.100.1, 10.0.0.1"]
        );
    }

    #[test]
    fn trusted_peer_without_chain_gets_peer_only() {
        let policy = policy_with(only(XForwardedForMode::Append));
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &context("10.0.0.1", "10.0.0.1", true));
        assert_eq!(values(&headers, "x-forwarded-for"), vec!["10.0.0.1"]);
    }

    #[test]
    fn multiple_incoming_lines_are_combined() {
        let policy = policy_with(only(XForwardedForMode::Append));
        let mut headers = headers_with(&[
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-for", "10.0.0.2, 10.0.0.3"),
        ]);
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(
            values(&headers, "x-forwarded-for"),
            vec!["198.51.100.1, 10.0.0.2, 10.0.0.3, 10.0.0.1"]
        );
    }

    #[test]
    fn replace_mode_with_trusted_peer_sets_resolved_client() {
        let policy = policy_with(only(XForwardedForMode::Replace));
        let mut headers = headers_with(&[("x-forwarded-for", "198.51.100.1, 10.0.0.2")]);
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(values(&headers, "x-forwarded-for"), vec!["198.51.100.1"]);
    }

    #[test]
    fn off_mode_leaves_incoming_untouched() {
        let policy = policy_with(only(XForwardedForMode::Off));
        let mut headers = headers_with(&[("x-forwarded-for", "1.2.3.4")]);
        policy.apply(&mut headers, &context("203.0.113.9", "203.0.113.9", false));
        assert_eq!(values(&headers, "x-forwarded-for"), vec!["1.2.3.4"]);
    }

    #[test]
    fn x_real_ip_is_resolved_client_and_overwrites_spoof() {
        let policy = policy_with(ForwardingConfig {
            x_forwarded_for: XForwardedForMode::Off,
            x_forwarded_proto: false,
            x_forwarded_host: false,
            ..Default::default()
        });
        let mut headers = headers_with(&[("x-real-ip", "6.6.6.6")]);
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(values(&headers, "x-real-ip"), vec!["198.51.100.1"]);
    }

    #[test]
    fn proto_and_host_are_kept_from_trusted_peer() {
        let policy = policy_with(ForwardingConfig::default());
        let mut headers = headers_with(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "public.example"),
        ]);
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(values(&headers, "x-forwarded-proto"), vec!["https"]);
        assert_eq!(values(&headers, "x-forwarded-host"), vec!["public.example"]);
    }

    #[test]
    fn proto_and_host_are_replaced_for_untrusted_peer() {
        let policy = policy_with(ForwardingConfig::default());
        let mut headers = headers_with(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
        ]);
        policy.apply(&mut headers, &context("203.0.113.9", "203.0.113.9", false));
        assert_eq!(values(&headers, "x-forwarded-proto"), vec!["http"]);
        assert_eq!(values(&headers, "x-forwarded-host"), vec!["example.com"]);
    }

    #[test]
    fn trusted_peer_without_incoming_proto_uses_request_scheme() {
        let policy = policy_with(ForwardingConfig::default());
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(values(&headers, "x-forwarded-proto"), vec!["http"]);
        assert_eq!(values(&headers, "x-forwarded-host"), vec!["example.com"]);
    }

    fn forwarded_only() -> ForwardingConfig {
        ForwardingConfig {
            forwarded: true,
            ..only(XForwardedForMode::Off)
        }
    }

    #[test]
    fn forwarded_element_formats_ipv4_with_plain_host() {
        let policy = policy_with(forwarded_only());
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &context("203.0.113.9", "203.0.113.9", false));
        assert_eq!(
            values(&headers, "forwarded"),
            vec!["for=203.0.113.9;proto=http;host=example.com"]
        );
    }

    #[test]
    fn forwarded_element_quotes_ipv6() {
        let policy = policy_with(forwarded_only());
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &context("2001:db8::1", "2001:db8::1", false));
        assert_eq!(
            values(&headers, "forwarded"),
            vec!["for=\"[2001:db8::1]\";proto=http;host=example.com"]
        );
    }

    #[test]
    fn forwarded_element_quotes_host_with_port() {
        let policy = policy_with(forwarded_only());
        let mut headers = HeaderMap::new();
        let mut ctx = context("203.0.113.9", "203.0.113.9", false);
        ctx.host = Some("example.com:8080".to_string());
        policy.apply(&mut headers, &ctx);
        assert_eq!(
            values(&headers, "forwarded"),
            vec!["for=203.0.113.9;proto=http;host=\"example.com:8080\""]
        );
    }

    #[test]
    fn forwarded_appends_for_trusted_and_replaces_for_untrusted() {
        let policy = policy_with(forwarded_only());
        let incoming = "for=198.51.100.1;proto=https";

        let mut headers = headers_with(&[("forwarded", incoming)]);
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(
            values(&headers, "forwarded"),
            vec![format!(
                "{incoming}, for=10.0.0.1;proto=http;host=example.com"
            )]
        );

        let mut headers = headers_with(&[("forwarded", incoming)]);
        policy.apply(&mut headers, &context("203.0.113.9", "203.0.113.9", false));
        assert_eq!(
            values(&headers, "forwarded"),
            vec!["for=203.0.113.9;proto=http;host=example.com"]
        );
    }

    #[test]
    fn allowlist_still_yields_forwarding_headers_and_keeps_trusted_chain() {
        let config = HeadersConfig {
            filter: HeaderFilter::Allowlist {
                names: vec!["accept".to_string()],
            },
            ..Default::default()
        };
        let policy = HeaderPolicy::from_config(&config).expect("valid config");
        let mut headers = headers_with(&[("accept", "*/*"), ("x-forwarded-for", "198.51.100.1")]);
        policy.apply(&mut headers, &context("10.0.0.1", "198.51.100.1", true));
        assert_eq!(
            values(&headers, "x-forwarded-for"),
            vec!["198.51.100.1, 10.0.0.1"]
        );
        assert_eq!(values(&headers, "x-real-ip"), vec!["198.51.100.1"]);
    }

    #[test]
    fn user_set_rule_overrides_forwarding_value() {
        let config = HeadersConfig {
            set: vec![HeaderRuleConfig {
                name: "x-real-ip".to_string(),
                value: "custom".to_string(),
            }],
            ..Default::default()
        };
        let policy = HeaderPolicy::from_config(&config).expect("valid config");
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &context("10.0.0.1", "10.0.0.1", false));
        assert_eq!(values(&headers, "x-real-ip"), vec!["custom"]);
    }

    #[test]
    fn disabled_policy_adds_nothing() {
        let config = HeadersConfig {
            enabled: false,
            ..Default::default()
        };
        let policy = HeaderPolicy::from_config(&config).expect("valid config");
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &context("10.0.0.1", "10.0.0.1", false));
        assert!(headers.is_empty());
        assert!(!policy.needs_context());
    }

    #[test]
    fn missing_peer_adds_no_forwarding_headers() {
        let policy = policy_with(ForwardingConfig {
            forwarded: true,
            ..Default::default()
        });
        let mut headers = headers_with(&[("x-forwarded-for", "1.2.3.4")]);
        policy.apply(&mut headers, &RequestContext::default());
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn needs_context_only_when_forwarding_or_dynamic_rules() {
        let off = ForwardingConfig {
            x_forwarded_for: XForwardedForMode::Off,
            x_real_ip: false,
            x_forwarded_proto: false,
            x_forwarded_host: false,
            forwarded: false,
            ..Default::default()
        };
        assert!(!policy_with(off.clone()).needs_context());
        assert!(policy_with(ForwardingConfig::default()).needs_context());

        let rule = |value: &str| HeaderRuleConfig {
            name: "x-a".to_string(),
            value: value.to_string(),
        };
        let build = |value: &str| {
            HeaderPolicy::from_config(&HeadersConfig {
                forwarding: off.clone(),
                set: vec![rule(value)],
                ..Default::default()
            })
            .expect("valid config")
        };
        assert!(!build("static").needs_context());
        assert!(build("{client_ip}").needs_context());
    }
}
