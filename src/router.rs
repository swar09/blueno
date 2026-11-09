use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    http::{
        HeaderName, Method,
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN},
    },
    response::{IntoResponse, Response},
    routing::{any, get},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::auth::{AuthLayer, AuthState};
use crate::config::{LimitsConfig, RequestBodyLimit, ServicesConfig};
use crate::header_policy::{HeaderPolicy, HeaderPolicyLayer};
use crate::load_balancer::{LoadBalancerLayer, LoadBalancerRegistry};
use crate::middleware::{RequestBodyLimitLayer, TimeoutLayer, TraceLayer};
use crate::proxy::{ProxyClient, ProxyRouteProvider, reverse_proxy_handler};
use crate::rate_limit::{RateLimitLayer, RateLimiter};

#[derive(Clone)]
pub struct RouterState {
    pub auth: Option<Arc<AuthState>>,
    pub proxy: Arc<ProxyClient>,
    pub services: Arc<ServicesConfig>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub load_balancer: Option<LoadBalancerRegistry>,
    pub limits: LimitsConfig,
    pub header_policy: Arc<HeaderPolicy>,
}

impl ProxyRouteProvider for RouterState {
    fn services(&self) -> &ServicesConfig {
        &self.services
    }

    fn proxy_client(&self) -> &ProxyClient {
        &self.proxy
    }

    fn header_policy(&self) -> &HeaderPolicy {
        &self.header_policy
    }
}

pub fn build_router(state: Arc<RouterState>) -> Router {
    let cors_layer = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
            ORIGIN,
            HeaderName::from_static("x-request-id"),
        ])
        .allow_credentials(true)
        .max_age(Duration::from_secs(86400));

    let proxy_any = any(reverse_proxy_handler::<RouterState>);

    let lb_layer = state
        .load_balancer
        .as_ref()
        .map(|lb| LoadBalancerLayer::new(lb.clone()));

    let mut public_routes = Router::new().route("/healthz", get(health_handler));
    let mut rl_only_routes = Router::new();
    let mut auth_only_routes = Router::new();
    let mut auth_and_rl_routes = Router::new();

    for route in &state.services.routes {
        let clean = route.path.trim_end_matches('/');
        let (exact, wildcard) = if clean.is_empty() {
            ("/".to_string(), "/{*path}".to_string())
        } else {
            (clean.to_string(), format!("{clean}/{{*path}}"))
        };

        match (route.auth, route.rate_limit) {
            (false, false) => {
                public_routes = public_routes
                    .route(&exact, proxy_any.clone())
                    .route(&wildcard, proxy_any.clone());
            }
            (false, true) => {
                rl_only_routes = rl_only_routes
                    .route(&exact, proxy_any.clone())
                    .route(&wildcard, proxy_any.clone());
            }
            (true, false) => {
                auth_only_routes = auth_only_routes
                    .route(&exact, proxy_any.clone())
                    .route(&wildcard, proxy_any.clone());
            }
            (true, true) => {
                auth_and_rl_routes = auth_and_rl_routes
                    .route(&exact, proxy_any.clone())
                    .route(&wildcard, proxy_any.clone());
            }
        }
    }

    if state.services.routes.is_empty() && state.services.default_upstream.is_some() {
        let has_auth = state.auth.is_some();
        let has_rl = state.rate_limiter.is_some();
        match (has_auth, has_rl) {
            (false, false) => {
                public_routes = public_routes
                    .route("/", proxy_any.clone())
                    .route("/{*path}", proxy_any.clone());
            }
            (false, true) => {
                rl_only_routes = rl_only_routes
                    .route("/", proxy_any.clone())
                    .route("/{*path}", proxy_any.clone());
            }
            (true, false) => {
                auth_only_routes = auth_only_routes
                    .route("/", proxy_any.clone())
                    .route("/{*path}", proxy_any.clone());
            }
            (true, true) => {
                auth_and_rl_routes = auth_and_rl_routes
                    .route("/", proxy_any.clone())
                    .route("/{*path}", proxy_any.clone());
            }
        }
    }

    if let Some(ref lb) = lb_layer {
        public_routes = public_routes.layer(lb.clone());
        rl_only_routes = rl_only_routes.layer(lb.clone());
        auth_only_routes = auth_only_routes.layer(lb.clone());
        auth_and_rl_routes = auth_and_rl_routes.layer(lb.clone());
    }

    if let Some(ref limiter) = state.rate_limiter {
        rl_only_routes = rl_only_routes.layer(RateLimitLayer::new(limiter.clone()));
        auth_and_rl_routes = auth_and_rl_routes.layer(RateLimitLayer::new(limiter.clone()));
    }

    if let Some(ref auth) = state.auth {
        auth_only_routes = auth_only_routes.layer(AuthLayer::new(auth.clone()));
        auth_and_rl_routes = auth_and_rl_routes.layer(AuthLayer::new(auth.clone()));
    }

    let router = Router::new()
        .merge(public_routes)
        .merge(rl_only_routes)
        .merge(auth_only_routes)
        .merge(auth_and_rl_routes);

    let middleware_stack = tower::ServiceBuilder::new()
        .layer(TraceLayer)
        .layer(cors_layer)
        .layer(HeaderPolicyLayer::new(state.header_policy.clone()));

    let mut router = router.layer(middleware_stack);

    if state.limits.enabled {
        if state.limits.max_request_body_bytes != RequestBodyLimit::Unlimited {
            router = router.layer(RequestBodyLimitLayer::new(
                state.limits.max_request_body_bytes,
            ));
        }
        router = router.layer(TimeoutLayer::new(Duration::from_secs(
            state.limits.request_timeout_secs,
        )));
    }

    router.with_state(state)
}

async fn health_handler() -> Response {
    "OK".into_response()
}
