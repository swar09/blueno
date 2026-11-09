use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower::{Layer, Service};

use crate::load_balancer::{Backend, LoadBalancer};

#[derive(Clone)]
pub struct SelectedBackend {
    pub addr: SocketAddr,
    pub backend: Arc<Backend>,
}

#[derive(Clone, Default)]
pub struct LoadBalancerRegistry {
    services: Arc<HashMap<String, Arc<LoadBalancer>>>,
    routes: Arc<Vec<(String, String)>>,
}

impl LoadBalancerRegistry {
    pub fn new(services: HashMap<String, Arc<LoadBalancer>>) -> Self {
        Self {
            services: Arc::new(services),
            routes: Arc::new(Vec::new()),
        }
    }

    pub fn with_routes(
        services: HashMap<String, Arc<LoadBalancer>>,
        routes: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self {
            services: Arc::new(services),
            routes: Arc::new(routes.into_iter().collect()),
        }
    }

    pub fn get(&self, service_name: &str) -> Option<Arc<LoadBalancer>> {
        self.services.get(service_name).cloned()
    }

    pub fn resolve_for_path(&self, path: &str) -> Option<Arc<LoadBalancer>> {
        let clean_path = path.trim_end_matches('/');

        let mut best_prefix: Option<(&Arc<LoadBalancer>, usize)> = None;
        for (key, lb) in self.services.as_ref() {
            let clean_key = key.trim_end_matches('/');
            if clean_path == clean_key || clean_path.starts_with(&format!("{clean_key}/")) {
                let len = clean_key.len();
                if best_prefix.as_ref().is_none_or(|(_, l)| len > *l) {
                    best_prefix = Some((lb, len));
                }
            }
        }
        if let Some((lb, _)) = best_prefix {
            return Some(Arc::clone(lb));
        }

        let mut best_route: Option<(&str, usize)> = None;
        for (prefix, svc_name) in self.routes.as_ref() {
            let clean_p = prefix.trim_end_matches('/');
            if clean_path == clean_p || clean_path.starts_with(&format!("{clean_p}/")) {
                let len = clean_p.len();
                if best_route.as_ref().is_none_or(|(_, l)| len > *l) {
                    best_route = Some((svc_name.as_str(), len));
                }
            }
        }
        if let Some((svc_name, _)) = best_route
            && let Some(lb) = self.services.get(svc_name)
        {
            return Some(Arc::clone(lb));
        }

        if let Some(svc_name) = resolve_service_name(path)
            && let Some(lb) = self.services.get(svc_name)
        {
            return Some(Arc::clone(lb));
        }

        None
    }
}

pub fn resolve_service_name(path: &str) -> Option<&str> {
    let clean = path.trim_matches('/');
    if clean.is_empty() {
        return None;
    }
    let segments: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }
    let mut idx = 0;
    if segments[idx] == "api" {
        idx += 1;
    }
    if idx < segments.len()
        && segments[idx].starts_with('v')
        && segments[idx][1..].chars().all(|c| c.is_ascii_digit())
    {
        idx += 1;
    }
    if idx < segments.len() {
        Some(segments[idx])
    } else {
        Some(segments[0])
    }
}

#[derive(Clone)]
pub struct LoadBalancerLayer {
    registry: LoadBalancerRegistry,
}

impl LoadBalancerLayer {
    pub fn new(registry: LoadBalancerRegistry) -> Self {
        Self { registry }
    }
}

impl<S> Layer<S> for LoadBalancerLayer {
    type Service = LoadBalancerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoadBalancerService {
            inner,
            registry: self.registry.clone(),
        }
    }
}

#[derive(Clone)]
pub struct LoadBalancerService<S> {
    inner: S,
    registry: LoadBalancerRegistry,
}

impl<S> Service<Request> for LoadBalancerService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let lb = self.registry.resolve_for_path(req.uri().path());

        if let Some(lb) = lb {
            match lb.select() {
                Ok((backend, guard)) => {
                    req.extensions_mut().insert(SelectedBackend {
                        addr: backend.addr,
                        backend: Arc::clone(&backend),
                    });
                    req.extensions_mut().insert(guard);
                }
                Err(_) => {
                    return Box::pin(
                        async move { Ok(StatusCode::SERVICE_UNAVAILABLE.into_response()) },
                    );
                }
            }
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}
