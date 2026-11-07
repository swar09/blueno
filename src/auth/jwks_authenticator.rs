use std::future::Future;
use std::pin::Pin;

use axum::http::StatusCode;
use jsonwebtoken::{DecodingKey, Validation, decode};

use crate::auth::{Authenticator, Claims, JwksStore};

pub fn is_valid_kid(kid: &str) -> bool {
    kid.len() == 32 && kid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub struct JwksAuthenticator {
    cache: JwksStore,
}

impl JwksAuthenticator {
    pub fn new(cache: JwksStore) -> Self {
        Self { cache }
    }

    pub fn cache(&self) -> &JwksStore {
        &self.cache
    }
}

impl Authenticator for JwksAuthenticator {
    fn verify<'a>(
        &'a self,
        token: &'a str,
        header: &'a jsonwebtoken::Header,
    ) -> Pin<Box<dyn Future<Output = Result<Claims, StatusCode>> + Send + 'a>> {
        Box::pin(async move {
            let Some(kid) = header.kid.as_deref().filter(|k| is_valid_kid(k)) else {
                return Err(StatusCode::UNAUTHORIZED);
            };

            let jwk = match self.cache.get_or_fetch_jwk(kid).await {
                Ok(j) => j,
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            };

            let decoding_key = match DecodingKey::from_jwk(&jwk) {
                Ok(k) => k,
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            };

            let mut validation = Validation::new(header.alg);
            validation.validate_nbf = true;
            validation.validate_aud = false;

            match decode::<Claims>(token, &decoding_key, &validation) {
                Ok(token_data) => Ok(token_data.claims),
                Err(_) => Err(StatusCode::UNAUTHORIZED),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_kid() {
        assert!(is_valid_kid("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_kid("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!is_valid_kid("short"));
        assert!(!is_valid_kid("0123456789abcdef0123456789abcdefg"));
    }
}
