use std::pin::Pin;
use std::sync::Arc;

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use jsonwebtoken::decode_header;
use tower::Service;

use crate::auth::AuthState;
use crate::header_policy::{IDENTITY_TOKEN_ID, IDENTITY_USER_ID, IDENTITY_USER_ROLE};

#[derive(Clone)]
pub struct AuthLayer {
    state: Arc<AuthState>,
}

impl AuthLayer {
    pub fn new(state: Arc<AuthState>) -> Self {
        Self { state }
    }
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    state: Arc<AuthState>,
}

pub type BoxFut<E> = Pin<Box<dyn std::future::Future<Output = Result<Response, E>> + Send>>;

fn reject<E: Send + 'static>(status: StatusCode) -> BoxFut<E> {
    Box::pin(async move { Ok(status.into_response()) })
}

impl<S> Service<Request> for AuthService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFut<Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let Some(auth_header) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
        else {
            return reject(StatusCode::UNAUTHORIZED);
        };
        let Some(raw_token) = auth_header.strip_prefix("Bearer ") else {
            return reject(StatusCode::UNAUTHORIZED);
        };
        let token = raw_token.trim().to_owned();
        if token.is_empty() {
            return reject(StatusCode::UNAUTHORIZED);
        }

        let Ok(jwt_header) = decode_header(&token) else {
            return reject(StatusCode::UNAUTHORIZED);
        };

        let path = req.uri().path().to_string();
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let token_bytes = token.as_bytes();

            let claims = if let Some(claims) = state.jwt_cache.get(token_bytes) {
                claims
            } else {
                let claims = match state.authenticator.verify(&token, &jwt_header).await {
                    Ok(c) => c,
                    Err(status) => return Ok(status.into_response()),
                };

                match state.revocations.is_revoked(claims.jti).await {
                    Ok(false) => {}
                    Ok(true) => return Ok(StatusCode::UNAUTHORIZED.into_response()),
                    Err(e) => {
                        tracing::warn!(error = %e, "revocation check failed, rejecting token");
                        return Ok(StatusCode::UNAUTHORIZED.into_response());
                    }
                }

                state.jwt_cache.insert(token_bytes, claims.clone());
                claims
            };

            req.headers_mut().remove(AUTHORIZATION);

            if let Ok(val) = HeaderValue::from_str(&claims.sub.to_string()) {
                req.headers_mut()
                    .insert(HeaderName::from_static(IDENTITY_USER_ID), val);
            }
            if let Ok(val) = HeaderValue::from_str(claims.role.as_str()) {
                req.headers_mut()
                    .insert(HeaderName::from_static(IDENTITY_USER_ROLE), val);
            }
            if let Ok(val) = HeaderValue::from_str(&claims.jti.to_string()) {
                req.headers_mut()
                    .insert(HeaderName::from_static(IDENTITY_TOKEN_ID), val);
            }

            req.extensions_mut().insert(claims);
            let response = inner.call(req).await;

            if let Ok(ref res) = response
                && res.status().is_success()
                && path == state.logout_path
            {
                state.jwt_cache.evict(token_bytes);
            }

            response
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::convert::Infallible;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use jsonwebtoken::{EncodingKey, Header};
    use tower::{Layer, ServiceExt, service_fn};
    use uuid::Uuid;

    use super::*;
    use crate::auth::{Audience, Claims, RevocationCheck, RevocationError, UserRole};

    const SECRET: &[u8] = b"layer-test-secret-0123456789abcdef";

    #[derive(Default)]
    struct FakeRevocations {
        revoked: HashSet<Uuid>,
        fail: bool,
        calls: AtomicUsize,
    }

    impl RevocationCheck for FakeRevocations {
        fn is_revoked<'a>(
            &'a self,
            jti: Uuid,
        ) -> Pin<Box<dyn Future<Output = Result<bool, RevocationError>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.fail {
                    let err = redis::RedisError::from(std::io::Error::other("down"));
                    return Err(RevocationError::Redis(err));
                }
                Ok(self.revoked.contains(&jti))
            })
        }
    }

    fn token_for(jti: Uuid) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let claims = Claims {
            iss: "test".to_string(),
            sub: Uuid::new_v4(),
            iat: now,
            nbf: now,
            exp: now + 600,
            aud: Audience("api".to_string()),
            role: UserRole("user".to_string()),
            jti,
        };
        jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .expect("token encodes")
    }

    async fn call(state: &Arc<AuthState>, token: &str) -> StatusCode {
        let inner = service_fn(|_req: Request| async {
            Ok::<_, Infallible>(StatusCode::OK.into_response())
        });
        let service = AuthLayer::new(state.clone()).layer(inner);
        let request = Request::builder()
            .uri("/protected")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request builds");
        service.oneshot(request).await.expect("infallible").status()
    }

    fn state_with(fake: Arc<FakeRevocations>) -> Arc<AuthState> {
        Arc::new(AuthState::new_with_secret(SECRET.to_vec()).with_revocations(fake))
    }

    #[tokio::test]
    async fn revoked_token_is_rejected() {
        let jti = Uuid::new_v4();
        let fake = Arc::new(FakeRevocations {
            revoked: HashSet::from([jti]),
            ..Default::default()
        });
        let state = state_with(fake);
        assert_eq!(
            call(&state, &token_for(jti)).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn unrevoked_token_passes() {
        let fake = Arc::new(FakeRevocations::default());
        let state = state_with(fake.clone());
        assert_eq!(
            call(&state, &token_for(Uuid::new_v4())).await,
            StatusCode::OK
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn checker_error_fails_closed() {
        let fake = Arc::new(FakeRevocations {
            fail: true,
            ..Default::default()
        });
        let state = state_with(fake);
        assert_eq!(
            call(&state, &token_for(Uuid::new_v4())).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn cached_token_skips_revocation_check() {
        let fake = Arc::new(FakeRevocations::default());
        let state = state_with(fake.clone());
        let token = token_for(Uuid::new_v4());
        assert_eq!(call(&state, &token).await, StatusCode::OK);
        assert_eq!(call(&state, &token).await, StatusCode::OK);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn default_state_does_not_revoke() {
        let state = Arc::new(AuthState::new_with_secret(SECRET.to_vec()));
        assert_eq!(
            call(&state, &token_for(Uuid::new_v4())).await,
            StatusCode::OK
        );
    }
}
