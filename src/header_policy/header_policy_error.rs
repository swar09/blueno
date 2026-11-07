use axum::http::header::InvalidHeaderName;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HeaderPolicyError {
    #[error("invalid header name '{name}': {source}")]
    InvalidName {
        name: String,
        #[source]
        source: InvalidHeaderName,
    },
    #[error("invalid header pattern '{pattern}': {reason}")]
    InvalidPattern {
        pattern: String,
        reason: &'static str,
    },
    #[error("invalid trusted proxy '{entry}': expected an IP address or CIDR")]
    InvalidTrustedProxy { entry: String },
    #[error("header '{name}' is reserved: {reason}")]
    Reserved { name: String, reason: &'static str },
    #[error("header '{name}' uses unknown template variable '{{{variable}}}'")]
    UnknownVariable { name: String, variable: String },
    #[error("header '{name}' has an invalid template: {reason}")]
    InvalidTemplate { name: String, reason: &'static str },
    #[error("header '{name}' has a value that is not a valid header value")]
    InvalidValue { name: String },
}
