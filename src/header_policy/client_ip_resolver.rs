use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

use crate::header_policy::header_policy_error::HeaderPolicyError;

#[derive(Debug, Clone, Default)]
pub struct ClientIpResolver {
    trusted: Vec<IpNet>,
}

impl ClientIpResolver {
    pub fn new(entries: &[String]) -> Result<Self, HeaderPolicyError> {
        let mut trusted = Vec::with_capacity(entries.len());
        for entry in entries {
            let trimmed = entry.trim();
            let net = match trimmed.parse::<IpNet>() {
                Ok(net) => net,
                Err(_) => trimmed.parse::<IpAddr>().map(IpNet::from).map_err(|_| {
                    HeaderPolicyError::InvalidTrustedProxy {
                        entry: entry.clone(),
                    }
                })?,
            };
            trusted.push(net);
        }
        Ok(Self { trusted })
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    pub fn resolve(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.is_trusted(peer) {
            return peer;
        }

        let mut hops: Vec<Option<IpAddr>> = Vec::new();
        for value in headers.get_all("x-forwarded-for") {
            match value.to_str() {
                Ok(text) => hops.extend(text.split(',').map(|part| {
                    part.trim()
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| ip.to_canonical())
                })),
                Err(_) => hops.push(None),
            }
        }

        let mut reached = peer;
        for hop in hops.iter().rev() {
            let Some(ip) = *hop else {
                return reached;
            };
            if !self.is_trusted(ip) {
                return ip;
            }
            reached = ip;
        }
        reached
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn resolver(entries: &[&str]) -> ClientIpResolver {
        let entries: Vec<String> = entries.iter().map(|entry| (*entry).to_string()).collect();
        ClientIpResolver::new(&entries).expect("valid entries")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid ip")
    }

    fn xff(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(
                "x-forwarded-for",
                HeaderValue::from_str(line).expect("valid header value"),
            );
        }
        headers
    }

    #[test]
    fn parses_single_ips_and_cidrs() {
        let resolver = resolver(&["10.0.0.1", "::1", "192.168.0.0/16", "fd00::/8"]);
        assert!(resolver.is_trusted(ip("10.0.0.1")));
        assert!(!resolver.is_trusted(ip("10.0.0.2")));
        assert!(resolver.is_trusted(ip("::1")));
        assert!(resolver.is_trusted(ip("192.168.5.5")));
        assert!(resolver.is_trusted(ip("fd12::1")));
        assert!(!resolver.is_trusted(ip("fe80::1")));
    }

    #[test]
    fn invalid_entries_are_rejected() {
        for entry in ["10.0.0.0/33", "nope"] {
            let result = ClientIpResolver::new(&[entry.to_string()]);
            assert!(matches!(
                result,
                Err(HeaderPolicyError::InvalidTrustedProxy { entry: ref e }) if e == entry
            ));
        }
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_for() {
        let resolver = resolver(&["10.0.0.0/8"]);
        let headers = xff(&["1.2.3.4"]);
        assert_eq!(resolver.resolve(ip("8.8.8.8"), &headers), ip("8.8.8.8"));
    }

    #[test]
    fn trusted_peer_returns_first_untrusted_from_right() {
        let resolver = resolver(&["10.0.0.0/8"]);
        let headers = xff(&["9.9.9.9, 1.2.3.4, 10.0.0.7"]);
        assert_eq!(resolver.resolve(ip("10.0.0.1"), &headers), ip("1.2.3.4"));
    }

    #[test]
    fn multiple_header_lines_are_combined_in_order() {
        let resolver = resolver(&["10.0.0.0/8"]);
        let headers = xff(&["1.2.3.4", "10.0.0.5, 10.0.0.6"]);
        assert_eq!(resolver.resolve(ip("10.0.0.1"), &headers), ip("1.2.3.4"));
    }

    #[test]
    fn all_trusted_returns_leftmost() {
        let resolver = resolver(&["10.0.0.0/8"]);
        let headers = xff(&["10.0.0.9, 10.0.0.8"]);
        assert_eq!(resolver.resolve(ip("10.0.0.1"), &headers), ip("10.0.0.9"));
    }

    #[test]
    fn absent_or_empty_header_returns_peer() {
        let resolver = resolver(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(ip("10.0.0.1"), &HeaderMap::new()),
            ip("10.0.0.1")
        );
        assert_eq!(
            resolver.resolve(ip("10.0.0.1"), &xff(&[""])),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn garbage_entry_stops_the_walk() {
        let resolver = resolver(&["10.0.0.0/8"]);
        let headers = xff(&["6.6.6.6, garbage, 10.0.0.7"]);
        assert_eq!(resolver.resolve(ip("10.0.0.1"), &headers), ip("10.0.0.7"));
        let headers = xff(&["6.6.6.6, 1.2.3.4:80"]);
        assert_eq!(resolver.resolve(ip("10.0.0.1"), &headers), ip("10.0.0.1"));
    }

    #[test]
    fn ipv6_client_is_resolved() {
        let resolver = resolver(&["10.0.0.0/8"]);
        let headers = xff(&["2001:db8::1, 10.0.0.7"]);
        assert_eq!(
            resolver.resolve(ip("10.0.0.1"), &headers),
            ip("2001:db8::1")
        );
    }

    #[test]
    fn ipv4_mapped_addresses_are_normalized() {
        let resolver = resolver(&["10.0.0.0/8"]);
        let headers = xff(&["1.2.3.4"]);
        assert_eq!(
            resolver.resolve(ip("::ffff:10.0.0.1"), &headers),
            ip("1.2.3.4")
        );
        let headers = xff(&["::ffff:1.2.3.4"]);
        assert_eq!(resolver.resolve(ip("10.0.0.1"), &headers), ip("1.2.3.4"));
    }
}
