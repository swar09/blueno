use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use blueno::auth::{AuthState, JwksClient, JwksStore, RevocationList};
use blueno::config::{AuthMode, GatewayConfig, read_secret};
use blueno::header_policy::HeaderPolicy;
use blueno::proxy::ProxyClient;
use blueno::rate_limit::{
    AutonomousLimiter, BUILTIN_RATE_LIMIT_SCRIPT, DistributedLimiter, RateLimiter,
    RateLimiterEngine, RedisCoordinator,
};
use blueno::router::{RouterState, build_router};
use tokio::net::TcpListener;

pub async fn run(config: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let auth_state = build_auth_state(&config).await?;
    let rate_limiter = build_rate_limiter(&config).await?;
    let header_policy = Arc::new(HeaderPolicy::from_config(&config.headers)?);

    let router_state = Arc::new(RouterState {
        auth: auth_state,
        proxy: Arc::new(ProxyClient::new()),
        services: Arc::new(config.services),
        rate_limiter,
        load_balancer: None,
        limits: config.limits.clone(),
        header_policy,
    });
    let app = build_router(router_state);

    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&bind_addr).await?;

    println!("[gateway] running on http://{bind_addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn build_auth_state(
    config: &GatewayConfig,
) -> Result<Option<Arc<AuthState>>, Box<dyn std::error::Error>> {
    if !config.auth.enabled {
        return Ok(None);
    }

    match config.auth.mode {
        AuthMode::Secret => {
            let secret = read_secret("JWT_SECRET")?.ok_or(
                "auth mode 'secret' requires a JWT secret: set JWT_SECRET or JWT_SECRET_FILE",
            )?;
            let revocations = connect_revocations(config).await;
            Ok(Some(Arc::new(
                AuthState::new_with_secret(secret)
                    .with_logout_path(config.auth.logout_path.clone())
                    .with_revocations(revocations),
            )))
        }
        AuthMode::Jwks => {
            let jwks_client = match JwksClient::new(config.auth.jwks_endpoint.clone()) {
                Ok(client) => client,
                Err(e) => {
                    eprintln!("[gateway] invalid jwks endpoint in config: {e}");
                    return Err(e.into());
                }
            };

            let jwks_store = JwksStore::new(jwks_client).await;
            let revocations = connect_revocations(config).await;

            Ok(Some(Arc::new(
                AuthState::from_config(jwks_store, &config.jwt_cache)
                    .with_logout_path(config.auth.logout_path.clone())
                    .with_revocations(revocations),
            )))
        }
        AuthMode::None => Ok(None),
    }
}

async fn connect_revocations(config: &GatewayConfig) -> Arc<RevocationList> {
    match RevocationList::connect(&config.redis.url).await {
        Ok(list) => Arc::new(list),
        Err(e) => {
            eprintln!("[gateway] redis unavailable, token revocation disabled: {e}");
            Arc::new(RevocationList::disabled())
        }
    }
}

async fn build_rate_limiter(
    config: &GatewayConfig,
) -> Result<Option<Arc<RateLimiter>>, Box<dyn std::error::Error>> {
    if !config.rate_limiter.enabled {
        return Ok(None);
    }

    let script_source = match &config.rate_limiter.script_path {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read rate limit script '{}': {e}", path.display()))?,
        None => BUILTIN_RATE_LIMIT_SCRIPT.to_string(),
    };

    let rate_limiter_config = Arc::new(config.rate_limiter.clone());
    let coordinator = RedisCoordinator::new(
        &config.rate_limiter.redis_url,
        config.rate_limiter.key_prefix.clone(),
        &script_source,
    )
    .await;

    let engine = match coordinator {
        Ok(coordinator) => {
            let lease_duration = Duration::from_secs(config.rate_limiter.lease_duration_secs);
            let batch_window = Duration::from_micros(config.rate_limiter.batch_window_micros);
            RateLimiterEngine::Distributed(DistributedLimiter::new(
                Arc::new(coordinator),
                lease_duration,
                batch_window,
            ))
        }
        Err(e) => {
            eprintln!(
                "[gateway] rate limiter redis connection failed, falling back to autonomous mode: {e}"
            );
            RateLimiterEngine::Autonomous(AutonomousLimiter::new())
        }
    };

    Ok(Some(Arc::new(RateLimiter::new(
        rate_limiter_config,
        engine,
    ))))
}
