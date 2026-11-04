use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

use crate::config::RequestBodyLimitError;

pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;

const UNLIMITED_LITERAL: &str = "unlimited";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyLimit {
    Bytes(u64),
    Unlimited,
}

impl Default for RequestBodyLimit {
    fn default() -> Self {
        Self::Bytes(DEFAULT_MAX_REQUEST_BODY_BYTES)
    }
}

impl FromStr for RequestBodyLimit {
    type Err = RequestBodyLimitError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed == UNLIMITED_LITERAL {
            return Ok(Self::Unlimited);
        }
        trimmed
            .parse::<u64>()
            .map(Self::Bytes)
            .map_err(|_| RequestBodyLimitError::Invalid {
                value: value.to_string(),
            })
    }
}

struct RequestBodyLimitVisitor;

impl Visitor<'_> for RequestBodyLimitVisitor {
    type Value = RequestBodyLimit;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a non-negative integer or the string \"unlimited\"")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(RequestBodyLimit::Bytes(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        u64::try_from(value)
            .map(RequestBodyLimit::Bytes)
            .map_err(|_| E::invalid_value(de::Unexpected::Signed(value), &self))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value == UNLIMITED_LITERAL {
            Ok(RequestBodyLimit::Unlimited)
        } else {
            Err(E::invalid_value(de::Unexpected::Str(value), &self))
        }
    }
}

impl<'de> Deserialize<'de> for RequestBodyLimit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RequestBodyLimitVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LimitsConfig;

    #[derive(Debug, Deserialize)]
    struct Holder {
        limit: RequestBodyLimit,
    }

    fn parse(toml_text: &str) -> Result<RequestBodyLimit, toml::de::Error> {
        toml::from_str::<Holder>(toml_text).map(|holder| holder.limit)
    }

    #[test]
    fn deserializes_integer() {
        assert_eq!(
            parse("limit = 2048").expect("parse"),
            RequestBodyLimit::Bytes(2048)
        );
    }

    #[test]
    fn deserializes_unlimited() {
        assert_eq!(
            parse("limit = \"unlimited\"").expect("parse"),
            RequestBodyLimit::Unlimited
        );
    }

    #[test]
    fn rejects_other_strings() {
        assert!(parse("limit = \"lots\"").is_err());
        assert!(parse("limit = \"Unlimited\"").is_err());
    }

    #[test]
    fn rejects_negative_numbers() {
        assert!(parse("limit = -1").is_err());
    }

    #[test]
    fn from_str_accepts_number_and_unlimited() {
        assert_eq!("512".parse(), Ok(RequestBodyLimit::Bytes(512)));
        assert_eq!("unlimited".parse(), Ok(RequestBodyLimit::Unlimited));
    }

    #[test]
    fn from_str_rejects_invalid_values() {
        assert!("lots".parse::<RequestBodyLimit>().is_err());
        assert!("-5".parse::<RequestBodyLimit>().is_err());
        assert!("".parse::<RequestBodyLimit>().is_err());
    }

    #[test]
    fn default_is_ten_mebibytes() {
        assert_eq!(
            RequestBodyLimit::default(),
            RequestBodyLimit::Bytes(10 * 1024 * 1024)
        );
    }

    #[test]
    fn legacy_key_still_loads_into_limits_config() {
        let config: LimitsConfig =
            toml::from_str("max_content_length_bytes = 4096").expect("parse");
        assert_eq!(config.max_request_body_bytes, RequestBodyLimit::Bytes(4096));
    }

    #[test]
    fn new_key_loads_into_limits_config() {
        let config: LimitsConfig =
            toml::from_str("max_request_body_bytes = \"unlimited\"").expect("parse");
        assert_eq!(config.max_request_body_bytes, RequestBodyLimit::Unlimited);
    }
}
