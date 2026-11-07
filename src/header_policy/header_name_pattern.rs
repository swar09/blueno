use std::fmt;
use std::str::FromStr;

use axum::http::HeaderName;

use crate::header_policy::header_policy_error::HeaderPolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderNamePattern {
    Exact(HeaderName),
    Prefix(String),
}

impl HeaderNamePattern {
    pub fn parse(raw: &str) -> Result<Self, HeaderPolicyError> {
        let normalized = raw.trim().to_ascii_lowercase();
        let invalid = |reason: &'static str| HeaderPolicyError::InvalidPattern {
            pattern: raw.to_string(),
            reason,
        };
        match normalized.strip_suffix('*') {
            Some(prefix) => {
                if prefix.is_empty() {
                    return Err(invalid("wildcard needs a non-empty prefix"));
                }
                if prefix.contains('*') {
                    return Err(invalid("'*' is only allowed as the final character"));
                }
                if HeaderName::from_str(prefix).is_err() {
                    return Err(invalid("prefix contains invalid header name characters"));
                }
                Ok(Self::Prefix(prefix.to_string()))
            }
            None => {
                if normalized.contains('*') {
                    return Err(invalid("'*' is only allowed as the final character"));
                }
                HeaderName::from_str(&normalized)
                    .map(Self::Exact)
                    .map_err(|source| HeaderPolicyError::InvalidName {
                        name: raw.to_string(),
                        source,
                    })
            }
        }
    }

    #[must_use]
    pub fn matches(&self, name: &HeaderName) -> bool {
        match self {
            Self::Exact(exact) => exact == name,
            Self::Prefix(prefix) => name.as_str().starts_with(prefix.as_str()),
        }
    }
}

impl fmt::Display for HeaderNamePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => write!(f, "{name}"),
            Self::Prefix(prefix) => write!(f, "{prefix}*"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> HeaderName {
        HeaderName::from_str(text).expect("valid header name")
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let pattern = HeaderNamePattern::parse("X-Custom").expect("valid");
        assert!(pattern.matches(&name("x-custom")));
        assert!(!pattern.matches(&name("x-custom-2")));
    }

    #[test]
    fn prefix_matches_only_names_with_that_prefix() {
        let pattern = HeaderNamePattern::parse("X-Internal-*").expect("valid");
        assert_eq!(
            pattern,
            HeaderNamePattern::Prefix("x-internal-".to_string())
        );
        assert!(pattern.matches(&name("x-internal-trace")));
        assert!(!pattern.matches(&name("x-internalx")));
    }

    #[test]
    fn lone_star_is_rejected() {
        assert!(matches!(
            HeaderNamePattern::parse("*"),
            Err(HeaderPolicyError::InvalidPattern { .. })
        ));
    }

    #[test]
    fn star_in_the_middle_is_rejected() {
        for raw in ["x-*-id", "x-*-id*", "**", "*x"] {
            assert!(matches!(
                HeaderNamePattern::parse(raw),
                Err(HeaderPolicyError::InvalidPattern { .. })
            ));
        }
    }

    #[test]
    fn invalid_characters_are_rejected() {
        assert!(matches!(
            HeaderNamePattern::parse("bad name"),
            Err(HeaderPolicyError::InvalidName { .. })
        ));
        assert!(matches!(
            HeaderNamePattern::parse("bad name*"),
            Err(HeaderPolicyError::InvalidPattern { .. })
        ));
    }

    #[test]
    fn display_round_trips_config_form() {
        assert_eq!(
            HeaderNamePattern::parse("X-A-*")
                .expect("valid")
                .to_string(),
            "x-a-*"
        );
        assert_eq!(
            HeaderNamePattern::parse("X-A").expect("valid").to_string(),
            "x-a"
        );
    }
}
