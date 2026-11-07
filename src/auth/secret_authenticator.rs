use std::future::Future;
use std::pin::Pin;

use axum::http::StatusCode;
use jsonwebtoken::{DecodingKey, Validation, decode};

use crate::auth::{Authenticator, Claims};

pub struct SecretAuthenticator {
    secret: Vec<u8>,
}

impl SecretAuthenticator {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

impl Authenticator for SecretAuthenticator {
    fn verify<'a>(
        &'a self,
        token: &'a str,
        header: &'a jsonwebtoken::Header,
    ) -> Pin<Box<dyn Future<Output = Result<Claims, StatusCode>> + Send + 'a>> {
        Box::pin(async move {
            let decoding_key = DecodingKey::from_secret(&self.secret);
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
    use jsonwebtoken::{EncodingKey, Header, decode_header};
    use uuid::Uuid;

    use super::*;
    use crate::auth::{Audience, UserRole};

    #[tokio::test]
    async fn test_secret_authenticator_valid_and_invalid_token() {
        let secret = b"super-secret-key-1234567890123456";
        let authenticator = SecretAuthenticator::new(secret.to_vec());

        let claims = Claims {
            iss: "test".to_string(),
            sub: Uuid::new_v4(),
            iat: 100,
            nbf: 100,
            exp: 9999999999,
            aud: Audience("api".to_string()),
            role: UserRole("user".to_string()),
            jti: Uuid::new_v4(),
        };

        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let header = decode_header(&token).unwrap();
        let verified = authenticator.verify(&token, &header).await.unwrap();
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.role.as_str(), "user");

        let bad_token = "invalid.jwt.token";
        let bad_header = Header::default();
        let err = authenticator
            .verify(bad_token, &bad_header)
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }
}
