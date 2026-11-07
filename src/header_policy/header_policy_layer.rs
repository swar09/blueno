use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::{ConnectInfo, Request};
use axum::http::header;
use tower::Service;

use crate::header_policy::client_ip::ClientIp;
use crate::header_policy::policy::HeaderPolicy;
use crate::header_policy::request_context::RequestContext;
use crate::middleware::{RequestId, X_REQUEST_ID};

#[derive(Clone)]
pub struct HeaderPolicyLayer {
    policy: Arc<HeaderPolicy>,
}

impl HeaderPolicyLayer {
    pub fn new(policy: Arc<HeaderPolicy>) -> Self {
        Self { policy }
    }
}

impl<S> tower::Layer<S> for HeaderPolicyLayer {
    type Service = HeaderPolicyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderPolicyService {
            inner,
            policy: self.policy.clone(),
        }
    }
}

#[derive(Clone)]
pub struct HeaderPolicyService<S> {
    inner: S,
    policy: Arc<HeaderPolicy>,
}

impl<S> Service<Request> for HeaderPolicyService<S>
where
    S: Service<Request>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        let client_ip = peer.map(|peer| {
            self.policy
                .client_ip_resolver()
                .resolve(peer.ip(), req.headers())
        });
        if let Some(ip) = client_ip {
            req.extensions_mut().insert(ClientIp(ip));
        }
        let context = if self.policy.needs_context() {
            self.build_context(&req, peer, client_ip)
        } else {
            RequestContext::default()
        };
        self.policy.apply(req.headers_mut(), &context);
        self.inner.call(req)
    }
}

impl<S> HeaderPolicyService<S> {
    fn build_context(
        &self,
        req: &Request,
        peer: Option<SocketAddr>,
        client_ip: Option<IpAddr>,
    ) -> RequestContext {
        let peer_ip = peer.map(|peer| peer.ip().to_canonical());
        let request_id = match req.extensions().get::<RequestId>() {
            Some(id) => Some(id.0.to_string()),
            None => req
                .headers()
                .get(&X_REQUEST_ID)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
        };
        RequestContext {
            client_ip,
            client_port: peer.map(|peer| peer.port()),
            peer_ip,
            peer_trusted: peer_ip.is_some_and(|ip| self.policy.client_ip_resolver().is_trusted(ip)),
            request_id,
            scheme: req.uri().scheme_str().unwrap_or("http").to_string(),
            host: req
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            method: req.method().as_str().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::convert::Infallible;
    use tower::{Layer, ServiceExt};

    #[tokio::test]
    async fn layer_applies_policy_before_inner_service() {
        let inner = tower::service_fn(|req: Request| async move {
            assert!(!req.headers().contains_key("x-evil"));
            assert!(req.headers().contains_key("authorization"));
            Ok::<_, Infallible>(axum::response::Response::new(axum::body::Body::empty()))
        });
        let mut service = HeaderPolicyLayer::new(Arc::new(HeaderPolicy::default())).layer(inner);

        let mut req = Request::new(axum::body::Body::empty());
        req.headers_mut()
            .insert("x-evil", HeaderValue::from_static("1"));
        req.headers_mut()
            .insert("authorization", HeaderValue::from_static("Bearer t"));

        let res = service
            .ready()
            .await
            .expect("service ready")
            .call(req)
            .await;
        assert!(res.is_ok());
    }

    async fn run_with(req: Request, trusted: &[&str]) -> Option<ClientIp> {
        let seen = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let seen_in = seen.clone();
        let inner = tower::service_fn(move |req: Request| {
            let seen = seen_in.clone();
            async move {
                *seen.lock() = req.extensions().get::<ClientIp>().copied();
                Ok::<_, Infallible>(axum::response::Response::new(axum::body::Body::empty()))
            }
        });
        let config = crate::config::HeadersConfig {
            forwarding: crate::config::ForwardingConfig {
                trusted_proxies: trusted.iter().map(|entry| (*entry).to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = HeaderPolicy::from_config(&config).expect("valid config");
        let mut service = HeaderPolicyLayer::new(Arc::new(policy)).layer(inner);
        service
            .ready()
            .await
            .expect("service ready")
            .call(req)
            .await
            .expect("infallible");
        let guard = seen.lock();
        *guard
    }

    #[tokio::test]
    async fn connect_info_yields_client_ip_extension() {
        let mut req = Request::new(axum::body::Body::empty());
        let peer: SocketAddr = "203.0.113.5:4000".parse().expect("valid addr");
        req.extensions_mut().insert(ConnectInfo(peer));
        let seen = run_with(req, &[]).await;
        assert_eq!(seen, Some(ClientIp(peer.ip())));
    }

    #[tokio::test]
    async fn forwarded_for_is_read_before_filtering() {
        let mut req = Request::new(axum::body::Body::empty());
        let peer: SocketAddr = "10.0.0.1:4000".parse().expect("valid addr");
        req.extensions_mut().insert(ConnectInfo(peer));
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        let seen = run_with(req, &["10.0.0.0/8"]).await;
        assert_eq!(seen, Some(ClientIp("1.2.3.4".parse().expect("valid ip"))));
    }

    #[tokio::test]
    async fn missing_connect_info_inserts_nothing() {
        let req = Request::new(axum::body::Body::empty());
        assert_eq!(run_with(req, &[]).await, None);
    }
}
