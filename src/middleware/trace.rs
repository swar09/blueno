use std::pin::Pin;

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    response::Response,
};
use tower::Service;
use tower_http::request_id::{MakeRequestId, RequestId as HttpHeaderRequestId};
use tracing::{Instrument, info_span};
use uuid::Uuid;

pub static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId(pub Uuid);

#[derive(Clone, Copy, Debug, Default)]
pub struct MakeRequestUuid7;

impl MakeRequestId for MakeRequestUuid7 {
    fn make_request_id<B>(
        &mut self,
        _request: &axum::http::Request<B>,
    ) -> Option<HttpHeaderRequestId> {
        let id = Uuid::now_v7();
        let val = HeaderValue::from_str(&id.to_string()).ok()?;
        Some(HttpHeaderRequestId::new(val))
    }
}

#[derive(Clone, Default)]
pub struct TraceLayer;

impl<S> tower::Layer<S> for TraceLayer {
    type Service = TraceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceService { inner }
    }
}

#[derive(Clone)]
pub struct TraceService<S> {
    inner: S,
}

type BoxFut<E> = Pin<Box<dyn std::future::Future<Output = Result<Response, E>> + Send>>;

impl<S> Service<Request> for TraceService<S>
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
        let request_id = Uuid::now_v7();

        if let Ok(val) = HeaderValue::from_str(&request_id.to_string()) {
            req.headers_mut().insert(X_REQUEST_ID.clone(), val);
        }

        req.extensions_mut().insert(RequestId(request_id));

        let span = info_span!(
            "http_request",
            %request_id,
            method = %req.method(),
            uri = %req.uri(),
        );

        let mut inner = self.inner.clone();
        Box::pin(
            async move {
                let mut response = inner.call(req).await?;
                if let Ok(val) = HeaderValue::from_str(&request_id.to_string()) {
                    response.headers_mut().insert(X_REQUEST_ID.clone(), val);
                }
                Ok(response)
            }
            .instrument(span),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::{Layer, ServiceExt};

    #[test]
    fn test_make_request_uuid7() {
        let mut maker = MakeRequestUuid7;
        let req = axum::http::Request::new(());
        let id = maker.make_request_id(&req);
        assert!(id.is_some());
    }

    #[tokio::test]
    async fn test_trace_layer_injects_and_propagates_request_id() {
        let dummy = tower::service_fn(|req: Request| async move {
            assert!(req.headers().contains_key("x-request-id"));
            assert!(req.extensions().get::<RequestId>().is_some());
            Ok::<_, std::convert::Infallible>(Response::new(axum::body::Body::empty()))
        });

        let mut service = TraceLayer.layer(dummy);
        let req = Request::new(axum::body::Body::empty());
        let res = service.ready().await.unwrap().call(req).await.unwrap();
        assert!(res.headers().contains_key("x-request-id"));
    }
}
