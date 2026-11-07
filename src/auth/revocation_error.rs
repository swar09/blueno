use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RevocationError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
}
