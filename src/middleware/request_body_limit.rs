use axum::body::Body;
use axum::http::Request;
use tower::Layer;
use tower::util::MapRequest;
use tower_http::body::Limited;
use tower_http::limit::{RequestBodyLimit, RequestBodyLimitLayer as HttpRequestBodyLimitLayer};

use crate::config::RequestBodyLimit as RequestBodyLimitConfig;

pub type LimitedBodyMapper = fn(Request<Limited<Body>>) -> Request<Body>;

fn into_axum_body(request: Request<Limited<Body>>) -> Request<Body> {
    request.map(Body::new)
}

#[derive(Debug, Clone, Copy)]
pub struct RequestBodyLimitLayer {
    max_bytes: usize,
}

impl RequestBodyLimitLayer {
    pub fn new(limit: RequestBodyLimitConfig) -> Self {
        let max_bytes = match limit {
            RequestBodyLimitConfig::Bytes(bytes) => usize::try_from(bytes).unwrap_or(usize::MAX),
            RequestBodyLimitConfig::Unlimited => usize::MAX,
        };
        Self { max_bytes }
    }
}

impl<S> Layer<S> for RequestBodyLimitLayer {
    type Service = RequestBodyLimit<MapRequest<S, LimitedBodyMapper>>;

    fn layer(&self, inner: S) -> Self::Service {
        let mapped = MapRequest::new(inner, into_axum_body as LimitedBodyMapper);
        HttpRequestBodyLimitLayer::new(self.max_bytes).layer(mapped)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use axum::body::Bytes;
    use axum::http::{StatusCode, header::CONTENT_LENGTH};
    use axum::response::{IntoResponse, Response};
    use http_body::{Body as HttpBody, Frame};
    use http_body_util::BodyExt;
    use tower::{ServiceExt, service_fn};

    use super::*;

    struct ChunkedBody {
        chunks: VecDeque<Bytes>,
    }

    impl HttpBody for ChunkedBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.chunks.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    fn chunked(chunks: usize, chunk_size: usize) -> Body {
        Body::new(ChunkedBody {
            chunks: (0..chunks)
                .map(|_| Bytes::from(vec![0u8; chunk_size]))
                .collect(),
        })
    }

    async fn run(
        limit: RequestBodyLimitConfig,
        request: Request<Body>,
        calls: Arc<AtomicUsize>,
    ) -> Response<Body> {
        let service = service_fn(move |request: Request<Body>| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let response = match request.into_body().collect().await {
                    Ok(collected) => collected.to_bytes().len().to_string().into_response(),
                    Err(_) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
                };
                Ok::<_, Infallible>(response)
            }
        });
        RequestBodyLimitLayer::new(limit)
            .layer(service)
            .oneshot(request)
            .await
            .expect("infallible")
            .map(Body::new)
    }

    fn request_with(body: Body) -> Request<Body> {
        Request::builder().body(body).expect("request")
    }

    #[tokio::test]
    async fn body_under_limit_passes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let request = request_with(Body::from(vec![0u8; 10]));
        let response = run(RequestBodyLimitConfig::Bytes(16), request, calls.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn declared_content_length_over_limit_is_rejected_without_calling_inner() {
        let calls = Arc::new(AtomicUsize::new(0));
        let request = Request::builder()
            .header(CONTENT_LENGTH, "100")
            .body(Body::from(vec![0u8; 100]))
            .expect("request");
        let response = run(RequestBodyLimitConfig::Bytes(16), request, calls.clone()).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn streamed_body_over_limit_is_rejected_when_read() {
        let calls = Arc::new(AtomicUsize::new(0));
        let request = request_with(chunked(4, 8));
        let response = run(RequestBodyLimitConfig::Bytes(16), request, calls.clone()).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unlimited_lets_large_body_through() {
        let calls = Arc::new(AtomicUsize::new(0));
        let request = request_with(chunked(64, 16 * 1024));
        let response = run(RequestBodyLimitConfig::Unlimited, request, calls).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
