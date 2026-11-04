use thiserror::Error;

use crate::config::{RequestBodyLimitError, SecretError};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to parse TOML from '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "'auth.secret' in '{path}' is no longer supported: provide the JWT secret via the JWT_SECRET or JWT_SECRET_FILE environment variable"
    )]
    SecretInConfigFile { path: String },
    #[error("Invalid value for environment variable {key}: {source}")]
    InvalidEnvValue {
        key: String,
        #[source]
        source: RequestBodyLimitError,
    },
    #[error(transparent)]
    Secret(#[from] SecretError),
}
