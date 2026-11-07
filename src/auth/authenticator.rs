use std::future::Future;
use std::pin::Pin;

use axum::http::StatusCode;

use crate::auth::Claims;

pub trait Authenticator: Send + Sync {
    fn verify<'a>(
        &'a self,
        token: &'a str,
        header: &'a jsonwebtoken::Header,
    ) -> Pin<Box<dyn Future<Output = Result<Claims, StatusCode>> + Send + 'a>>;
}
