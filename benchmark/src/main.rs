use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use blueno::auth::{Audience, AuthState, Claims, JwksClient, JwksStore, UserRole};
use blueno::config::{RateLimiterConfig, Tier, TierLimitConfig, TiersConfig};
use blueno::load_balancer::{
    AlgorithmType, CircuitBreakerConfig, HealthCheckConfig, LoadBalancer, LoadBalancerConfig,
    LoadBalancerRegistry,
};
use blueno::proxy::ProxyClient;
use blueno::rate_limit::{AutonomousLimiter, RateLimiter, RateLimiterEngine};
use blueno::router::{RouterState, build_router};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::Jwk};
use serde_json::json;
use tokio::net::TcpListener;
use uuid::Uuid;

pub trait MockUpstreamBackend: Send + Sync {
    fn handle(&self, path: &str) -> axum::response::Response;
}

#[derive(Clone, Default)]
pub struct JsonMockBackend {
    status: u16,
    body: &'static str,
}

impl JsonMockBackend {
    pub const fn new(status: u16, body: &'static str) -> Self {
        Self { status, body }
    }
}

impl MockUpstreamBackend for JsonMockBackend {
    fn handle(&self, _path: &str) -> axum::response::Response {
        axum::response::Response::builder()
            .status(self.status)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(self.body))
            .unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkOptions {
    pub concurrency: usize,
    pub duration_secs: u64,
    pub downstream_count: usize,
    pub gateway_url_override: Option<String>,
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            concurrency: 32,
            duration_secs: 4,
            downstream_count: 10,
            gateway_url_override: None,
        }
    }
}

impl BenchmarkOptions {
    pub fn parse() -> Result<Self, String> {
        let mut opts = Self::default();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--concurrency" | "--concurrent-workers" | "-c" => {
                    let val = args.next().ok_or("missing value for --concurrency")?;
                    opts.concurrency = val.parse().map_err(|_| "invalid number for concurrency")?;
                }
                "--duration" | "--duration-secs" | "-d" => {
                    let val = args.next().ok_or("missing value for --duration")?;
                    opts.duration_secs = val.parse().map_err(|_| "invalid number for duration")?;
                }
                "--downstream-services" | "-s" => {
                    let val = args
                        .next()
                        .ok_or("missing value for --downstream-services")?;
                    opts.downstream_count = val
                        .parse()
                        .map_err(|_| "invalid number for downstream services")?;
                }
                "--gateway-url" | "-g" => {
                    opts.gateway_url_override =
                        Some(args.next().ok_or("missing value for --gateway-url")?);
                }
                "--help" | "-h" => {
                    println!("blueno benchmark cli tool");
                    println!("options:");
                    println!(
                        "  --concurrency, -c <n>         concurrent client workers (default: 32)"
                    );
                    println!(
                        "  --duration-secs, -d <secs>    benchmark test duration in seconds (default: 4)"
                    );
                    println!(
                        "  --downstream-services, -s <n> number of mock downstream backends (default: 10)"
                    );
                    println!(
                        "  --gateway-url, -g <url>       target gateway url (default: auto-spawned internal gateway)"
                    );
                    std::process::exit(0);
                }
                _ => {}
            }
        }
        Ok(opts)
    }
}

fn calculate_percentiles(mut latencies: Vec<u64>) -> (u64, u64, u64, u64) {
    if latencies.is_empty() {
        return (0, 0, 0, 0);
    }
    latencies.sort_unstable();
    let len = latencies.len();
    let p50 = latencies[len * 50 / 100];
    let p90 = latencies[len * 90 / 100];
    let p99 = latencies[len * 99 / 100];
    let p999 = latencies[((len as f64 * 0.999) as usize).min(len - 1)];
    (p50, p90, p99, p999)
}

struct SyntheticAuthData {
    pub jwk: Jwk,
    pub admin_token: String,
    pub client_tokens: Vec<String>,
    pub expired_token: String,
}

fn generate_synthetic_data() -> SyntheticAuthData {
    let raw_secret = b"super-secret-synthetic-benchmark-key-32-bytes";
    let encoding_key = EncodingKey::from_secret(raw_secret);
    let k_b64 = "c3VwZXItc2VjcmV0LXN5bnRoZXRpYy1iZW5jaG1hcmsta2V5LTMyLWJ5dGVz";
    let jwk_json = json!({
        "kty": "oct",
        "kid": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "alg": "HS256",
        "k": k_b64
    });
    let jwk: Jwk = serde_json::from_value(jwk_json).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string());

    let admin_claims = Claims {
        iss: "https://auth.internal".to_string(),
        sub: Uuid::new_v4(),
        iat: now,
        nbf: now,
        exp: now + 86400,
        aud: Audience::new("order"),
        role: UserRole::new("admin"),
        jti: Uuid::new_v4(),
    };
    let admin_token = encode(&header, &admin_claims, &encoding_key).unwrap();

    let mut client_tokens = Vec::with_capacity(100);
    for _ in 0..100 {
        let client_claims = Claims {
            iss: "https://auth.internal".to_string(),
            sub: Uuid::new_v4(),
            iat: now,
            nbf: now,
            exp: now + 86400,
            aud: Audience::new("order"),
            role: UserRole::new("client"),
            jti: Uuid::new_v4(),
        };
        client_tokens.push(encode(&header, &client_claims, &encoding_key).unwrap());
    }

    let expired_claims = Claims {
        iss: "https://auth.internal".to_string(),
        sub: Uuid::new_v4(),
        iat: now - 7200,
        nbf: now - 7200,
        exp: now - 3600,
        aud: Audience::new("order"),
        role: UserRole::new("client"),
        jti: Uuid::new_v4(),
    };
    let expired_token = encode(&header, &expired_claims, &encoding_key).unwrap();

    SyntheticAuthData {
        jwk,
        admin_token,
        client_tokens,
        expired_token,
    }
}

async fn spawn_internal_mock_servers<B: MockUpstreamBackend + 'static>(
    count: usize,
    backend: Arc<B>,
) -> Vec<SocketAddr> {
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        addrs.push(addr);
        let b = Arc::clone(&backend);
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
                let b = Arc::clone(&b);
                async move { b.handle(req.uri().path()) }
            });
            axum::serve(listener, app).await.ok();
        });
    }
    addrs
}

async fn spawn_benchmark_gateway(
    port: u16,
    auth_data: &SyntheticAuthData,
    upstream_addrs: Vec<SocketAddr>,
) -> String {
    let dummy_jwks =
        JwksClient::new("http://127.0.0.1:8086/.well_known/jwks.json".to_string()).unwrap();
    let cache = JwksStore::new_in_memory(dummy_jwks);
    cache.replace_local_jwks(vec![(
        "a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string(),
        auth_data.jwk.clone(),
    )]);

    let auth_state = Arc::new(AuthState::new(cache));
    let proxy_client = Arc::new(ProxyClient::new());
    let services_config = Arc::new(blueno::config::ServicesConfig {
        routes: vec![blueno::config::RouteRuleConfig {
            path: "/api/v1/orders".to_string(),
            upstream: "http://127.0.0.1".to_string(),
            auth: true,
            rate_limit: true,
        }],
        ..Default::default()
    });

    let tiers = TiersConfig {
        tier1: TierLimitConfig {
            initial_tokens: 1_000_000,
            fill_rate: 1_000_000,
            burst_interval_secs: 60,
            max_tokens: 5_000_000,
            lease_batch_size: 50_000,
        },
        tier3: TierLimitConfig {
            initial_tokens: 500_000,
            fill_rate: 500_000,
            burst_interval_secs: 60,
            max_tokens: 2_500_000,
            lease_batch_size: 25_000,
        },
        ..Default::default()
    };

    let rate_limiter = Arc::new(RateLimiter::new(
        Arc::new(RateLimiterConfig {
            enabled: true,
            redis_url: "redis://127.0.0.1:16379".to_string(),
            key_prefix: "rl_bench".to_string(),
            lease_duration_secs: 5,
            batch_window_micros: 2000,
            script_path: None,
            default_tier: Tier::Tier3,
            tiers,
            role_mapping: HashMap::new(),
        }),
        RateLimiterEngine::Autonomous(AutonomousLimiter::new()),
    ));

    let lb_config = LoadBalancerConfig {
        service_name: "orders".to_string(),
        algorithm: AlgorithmType::RoundRobin,
        health_check: HealthCheckConfig::default(),
        circuit_breaker: CircuitBreakerConfig::default(),
        initial_endpoints: upstream_addrs,
    };
    let lb = Arc::new(LoadBalancer::new(lb_config).unwrap());
    let mut services = std::collections::HashMap::new();
    services.insert("orders".to_string(), lb);
    let lb_registry = LoadBalancerRegistry::new(services);

    let router_state = Arc::new(RouterState {
        auth: Some(auth_state),
        proxy: proxy_client,
        services: services_config,
        rate_limiter: Some(rate_limiter),
        load_balancer: Some(lb_registry),
        limits: Default::default(),
        header_policy: Default::default(),
    });

    let app = build_router(router_state);
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let bound_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });

    format!("http://127.0.0.1:{}", bound_addr.port())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = BenchmarkOptions::parse().map_err(Box::<dyn std::error::Error>::from)?;

    println!("blueno benchmark suite");
    println!(
        "concurrency: {} | duration: {}s | downstreams: {}",
        opts.concurrency, opts.duration_secs, opts.downstream_count
    );

    let auth_data = generate_synthetic_data();
    let gateway_url = if let Some(url) = opts.gateway_url_override {
        url
    } else {
        let mock_backend = Arc::new(JsonMockBackend::new(200, r#"{"status":"ok"}"#));
        let upstream_addrs = spawn_internal_mock_servers(opts.downstream_count, mock_backend).await;
        let port = 9000 + (fastrand::u16(..1000));
        spawn_benchmark_gateway(port, &auth_data, upstream_addrs).await
    };

    println!("gateway ready: {gateway_url}");

    let http_client = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(opts.concurrency)
        .tcp_nodelay(true)
        .build()?;

    let test_url = format!("{gateway_url}/api/v1/orders/health");
    let unauth_res = http_client.get(&test_url).send().await?;
    if unauth_res.status() != reqwest::StatusCode::UNAUTHORIZED {
        eprintln!(
            "[benchmark warning] expected 401 for unauthenticated request, got {}",
            unauth_res.status()
        );
    }

    let expired_res = http_client
        .get(&test_url)
        .header(
            "Authorization",
            format!("Bearer {}", auth_data.expired_token),
        )
        .send()
        .await?;
    if expired_res.status() != reqwest::StatusCode::UNAUTHORIZED {
        eprintln!(
            "[benchmark warning] expected 401 for expired token, got {}",
            expired_res.status()
        );
    }

    let valid_res = http_client
        .get(&test_url)
        .header("Authorization", format!("Bearer {}", auth_data.admin_token))
        .send()
        .await?;

    if valid_res.status() != reqwest::StatusCode::OK {
        eprintln!(
            "\n[error] Gateway at {gateway_url} returned HTTP {} (expected 200 OK).\n\
            Note: When benchmarking an external gateway (-g), ensure the gateway is configured with matching JWT secrets and routes.\n\
            Tip: Omit the -g flag to run the benchmark with an auto-configured in-process gateway:\n  cargo run -p benchmark --release -- -c {} -d {} -s {}\n",
            valid_res.status(),
            opts.concurrency,
            opts.duration_secs,
            opts.downstream_count,
        );
        return Err(format!(
            "Gateway authentication check failed with HTTP {}",
            valid_res.status()
        )
        .into());
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let total_200 = Arc::new(AtomicU64::new(0));
    let total_429 = Arc::new(AtomicU64::new(0));
    let total_5xx = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));

    let auth_data = Arc::new(auth_data);
    let start_time = Instant::now();
    let mut worker_handles = Vec::with_capacity(opts.concurrency);
    let samples_per_worker = (100_000 / opts.concurrency).clamp(10, 5_000);

    for worker_id in 0..opts.concurrency {
        let stop_clone = Arc::clone(&stop_flag);
        let total_200_clone = Arc::clone(&total_200);
        let total_429_clone = Arc::clone(&total_429);
        let total_5xx_clone = Arc::clone(&total_5xx);
        let total_err_clone = Arc::clone(&total_errors);
        let auth_clone = Arc::clone(&auth_data);
        let client_clone = http_client.clone();
        let target_url = format!("{gateway_url}/api/v1/orders/trade/123");

        let handle = tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(samples_per_worker);
            let mut req_counter: u64 = 0;
            let token_idx = worker_id % auth_clone.client_tokens.len();
            let auth_header = format!("Bearer {}", auth_clone.client_tokens[token_idx]);

            while !stop_clone.load(Ordering::Relaxed) {
                let sample_now =
                    req_counter.is_multiple_of(20) && latencies.len() < samples_per_worker;
                let t0 = if sample_now {
                    Some(Instant::now())
                } else {
                    None
                };

                match client_clone
                    .get(&target_url)
                    .header("Authorization", &auth_header)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status();
                        if status == reqwest::StatusCode::OK {
                            total_200_clone.fetch_add(1, Ordering::Relaxed);
                        } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                            total_429_clone.fetch_add(1, Ordering::Relaxed);
                        } else if status.is_server_error() {
                            total_5xx_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        total_err_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }

                if let Some(t) = t0 {
                    latencies.push(t.elapsed().as_nanos() as u64);
                }
                req_counter += 1;
            }
            latencies
        });
        worker_handles.push(handle);
    }

    tokio::time::sleep(Duration::from_secs(opts.duration_secs)).await;
    stop_flag.store(true, Ordering::Relaxed);

    let mut all_latencies = Vec::new();
    for handle in worker_handles {
        let latencies = handle.await.unwrap();
        all_latencies.extend(latencies);
    }

    let elapsed = start_time.elapsed();
    let count_200 = total_200.load(Ordering::SeqCst);
    let count_429 = total_429.load(Ordering::SeqCst);
    let count_5xx = total_5xx.load(Ordering::SeqCst);
    let count_err = total_errors.load(Ordering::SeqCst);
    let total_reqs = count_200 + count_429 + count_5xx + count_err;
    let rps = total_reqs as f64 / elapsed.as_secs_f64();
    let (p50, p90, p99, p999) = calculate_percentiles(all_latencies);

    println!("\nbenchmark completed in {:.2}s:", elapsed.as_secs_f64());
    println!("  total requests:        {total_reqs}");
    println!("  http 200 ok:           {count_200}");
    println!("  http 429 throttled:    {count_429}");
    println!("  http 5xx server error: {count_5xx}");
    println!("  socket/network errors: {count_err}");
    println!("  throughput:            {rps:.2} req/sec");
    println!("  latency p50:           {:.2}µs", p50 as f64 / 1000.0);
    println!("  latency p90:           {:.2}µs", p90 as f64 / 1000.0);
    println!("  latency p99:           {:.2}µs", p99 as f64 / 1000.0);
    println!("  latency p99.9:         {:.2}µs", p999 as f64 / 1000.0);
    Ok(())
}
