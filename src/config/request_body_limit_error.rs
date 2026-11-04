use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RequestBodyLimitError {
    #[error(
        "invalid request body limit '{value}': expected a non-negative integer or \"unlimited\""
    )]
    Invalid { value: String },
}
