use thiserror::Error;

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Internal error: {0}")]
    Internal(String),
}
