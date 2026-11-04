use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("both {var} and {var}_FILE are set; set only one")]
    BothSet { var: String },
    #[error("failed to read secret file '{path}': {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to load env file '{path}': {source}")]
    EnvFile {
        path: String,
        #[source]
        source: dotenvy::Error,
    },
}
