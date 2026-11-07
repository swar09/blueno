use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use reqwest::{Client as HttpClient, Url};

#[derive(Clone)]
pub struct JwksClient {
    pub client: HttpClient,
    jwks_endpoint: String,
}

impl JwksClient {
    pub fn new(jwks_endpoint: String) -> Result<Self, JwksClientError> {
        let parsed = Url::parse(&jwks_endpoint)
            .map_err(|_| JwksClientError::InvalidEndpoint(jwks_endpoint.clone()))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(JwksClientError::InvalidEndpoint(jwks_endpoint));
        }
        if parsed.host_str().is_none() {
            return Err(JwksClientError::InvalidEndpoint(jwks_endpoint));
        }

        let client = HttpClient::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
            .map_err(JwksClientError::ClientBuild)?;
        Ok(Self {
            client,
            jwks_endpoint,
        })
    }

    pub async fn fetch_jwks_from_endpoint(&self) -> Result<JwkSet, JwksClientError> {
        let res = self.client.get(&self.jwks_endpoint).send().await?;
        let jwkset: JwkSet = res.json().await?;
        Ok(jwkset)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwksClientError {
    #[error("invalid jwks endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("failed to build http client")]
    ClientBuild(#[source] reqwest::Error),
    #[error("failed to fetch jwks")]
    Fetch(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwks_client_valid_and_invalid_endpoints() {
        assert!(
            JwksClient::new("https://auth.example.com/.well-known/jwks.json".to_string()).is_ok()
        );
        assert!(JwksClient::new("http://localhost:8080/jwks".to_string()).is_ok());

        assert!(JwksClient::new("ftp://auth.example.com/jwks".to_string()).is_err());
        assert!(JwksClient::new("not-a-valid-url".to_string()).is_err());
    }
}
