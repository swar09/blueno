use axum::http::StatusCode;
use std::time::Duration;
use tower::Layer;
pub use tower_http::timeout::{Timeout, TimeoutLayer as HttpTimeoutLayer};

#[derive(Clone)]
pub struct TimeoutLayer {
    inner: HttpTimeoutLayer,
}

impl TimeoutLayer {
    pub fn new(timeout: Duration) -> Self {
        Self {
            inner: HttpTimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, timeout),
        }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        self.inner.layer(inner)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::body::Body;
    use axum::http::Request;
    use axum::response::{IntoResponse, Response};
    use tower::{ServiceExt, service_fn};

    use super::*;

    #[tokio::test]
    async fn slow_inner_service_gets_gateway_timeout() {
        let slow = service_fn(|_request: Request<Body>| async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok::<Response, Infallible>("late".into_response())
        });
        let response = TimeoutLayer::new(Duration::from_millis(20))
            .layer(slow)
            .oneshot(Request::new(Body::empty()))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn fast_inner_service_passes() {
        let fast = service_fn(|_request: Request<Body>| async {
            Ok::<Response, Infallible>("ok".into_response())
        });
        let response = TimeoutLayer::new(Duration::from_secs(5))
            .layer(fast)
            .oneshot(Request::new(Body::empty()))
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
