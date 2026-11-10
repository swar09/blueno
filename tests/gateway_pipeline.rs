use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{body::Body, extract::Request, http::StatusCode, response::Response};
use blueno::auth::{Audience, AuthState, Claims, UserRole};
use blueno::config::{
    ForwardingConfig, HeaderFilter, HeaderRuleConfig, HeaderSafetyConfig, HeadersConfig,
    LimitsConfig, RateLimiterConfig, RequestBodyLimit, RouteRuleConfig, ServicesConfig, Tier,
    TierLimitConfig, TiersConfig,
};
use blueno::header_policy::HeaderPolicy;
use blueno::proxy::ProxyClient;
use blueno::rate_limit::{AutonomousLimiter, RateLimiter, RateLimiterEngine};
use blueno::router::{RouterState, build_router};
use jsonwebtoken::{EncodingKey, Header, encode};
use tokio::net::TcpListener;
use uuid::Uuid;

const TEST_SECRET: &[u8] = b"secret-for-integration-tests-32-bytes";

struct TestHarness {
    pub gateway_addr: SocketAddr,
}

impl TestHarness {
    async fn setup(initial_quota: u64, limits: LimitsConfig) -> Self {
        Self::setup_with_headers(initial_quota, limits, HeadersConfig::default()).await
    }

    async fn setup_with_headers(
        initial_quota: u64,
        limits: LimitsConfig,
        headers: HeadersConfig,
    ) -> Self {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|req: Request| async move {
                let user_id = req
                    .headers()
                    .get("x-user-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("none")
                    .to_string();
                let user_role = req
                    .headers()
                    .get("x-user-role")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("none")
                    .to_string();
                let request_id = req
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("none")
                    .to_string();
                let has_evil = req.headers().contains_key("x-evil-header");

                let header_names: Vec<&str> =
                    req.headers().keys().map(|name| name.as_str()).collect();

                let mut header_values: HashMap<String, Vec<String>> = HashMap::new();
                for (name, value) in req.headers() {
                    header_values
                        .entry(name.as_str().to_string())
                        .or_default()
                        .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
                }

                let body = serde_json::json!({
                    "user_id": user_id,
                    "role": user_role,
                    "req_id": request_id,
                    "evil": has_evil,
                    "headers": header_names,
                    "header_values": header_values,
                })
                .to_string();

                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap()
            });
            axum::serve(upstream_listener, app).await.ok();
        });

        let tiers = TiersConfig {
            tier1: TierLimitConfig {
                initial_tokens: initial_quota,
                fill_rate: 0,
                burst_interval_secs: 60,
                max_tokens: initial_quota,
                lease_batch_size: 10,
            },
            ..Default::default()
        };

        let rate_limiter = Arc::new(RateLimiter::new(
            Arc::new(RateLimiterConfig {
                enabled: true,
                redis_url: "redis://127.0.0.1:6379".to_string(),
                key_prefix: "test_rl".to_string(),
                lease_duration_secs: 10,
                batch_window_micros: 1000,
                script_path: None,
                default_tier: Tier::Tier1,
                tiers,
                role_mapping: HashMap::new(),
            }),
            RateLimiterEngine::Autonomous(AutonomousLimiter::new()),
        ));

        let auth_state = Arc::new(AuthState::new_with_secret(TEST_SECRET.to_vec()));
        let proxy_client = Arc::new(ProxyClient::new());

        let services_config = ServicesConfig {
            routes: vec![
                RouteRuleConfig {
                    path: "/api/orders".to_string(),
                    upstream: format!("http://{upstream_addr}"),
                    auth: true,
                    rate_limit: true,
                },
                RouteRuleConfig {
                    path: "/api/public".to_string(),
                    upstream: format!("http://{upstream_addr}"),
                    auth: false,
                    rate_limit: false,
                },
            ],
            ..Default::default()
        };

        let router_state = Arc::new(RouterState {
            auth: Some(auth_state),
            proxy: proxy_client,
            services: Arc::new(services_config),
            rate_limiter: Some(rate_limiter),
            load_balancer: None,
            limits,
            header_policy: Arc::new(
                HeaderPolicy::from_config(&headers).expect("test headers config is valid"),
            ),
        });

        let app = build_router(router_state);

        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway_listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(
                gateway_listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .ok();
        });

        Self { gateway_addr }
    }
}

fn create_valid_token(role: &str, user_id: Uuid) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        iss: "test_issuer".to_string(),
        sub: user_id,
        iat: now,
        nbf: now,
        exp: now + 3600,
        aud: Audience("api".to_string()),
        role: UserRole(role.to_string()),
        jti: Uuid::new_v4(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET),
    )
    .unwrap()
}

fn test_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
async fn test_healthz_endpoint_is_publicly_accessible() {
    let harness = TestHarness::setup(10, LimitsConfig::default()).await;
    let client = test_client();

    let res = client
        .get(format!("http://{}/healthz", harness.gateway_addr))
        .send()
        .await
        .unwrap();

    let status = res.status();
    let body = res.text().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "OK");
}

#[tokio::test]
async fn test_protected_route_rejects_missing_token() {
    let harness = TestHarness::setup(10, LimitsConfig::default()).await;
    let client = test_client();

    let res = client
        .get(format!("http://{}/api/orders/list", harness.gateway_addr))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_route_rejects_malformed_token() {
    let harness = TestHarness::setup(10, LimitsConfig::default()).await;
    let client = test_client();

    let res = client
        .get(format!("http://{}/api/orders/list", harness.gateway_addr))
        .header("Authorization", "Bearer invalid-garbage-token")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_route_forwards_with_injected_headers_and_sanitizes() {
    let harness = TestHarness::setup(10, LimitsConfig::default()).await;
    let client = test_client();
    let user_id = Uuid::new_v4();
    let token = create_valid_token("admin", user_id);

    let res = client
        .get(format!(
            "http://{}/api/orders/item/42",
            harness.gateway_addr
        ))
        .header("Authorization", format!("Bearer {token}"))
        .header("x-evil-header", "must-be-stripped")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert!(res.headers().contains_key("x-request-id"));

    let body_json: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body_json["user_id"], user_id.to_string());
    assert_eq!(body_json["role"], "admin");
    assert_eq!(body_json["evil"], false);
}

#[tokio::test]
async fn test_rate_limiter_throttles_when_quota_exhausted() {
    let harness = TestHarness::setup(2, LimitsConfig::default()).await;
    let client = test_client();
    let user_id = Uuid::new_v4();
    let token = create_valid_token("client", user_id);

    let url = format!("http://{}/api/orders/action", harness.gateway_addr);

    let res1 = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res1.status(), reqwest::StatusCode::OK);

    let res2 = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res2.status(), reqwest::StatusCode::OK);

    let res3 = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res3.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
}

fn limits_with(enabled: bool, max_bytes: u64) -> LimitsConfig {
    LimitsConfig {
        enabled,
        max_request_body_bytes: RequestBodyLimit::Bytes(max_bytes),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_over_limit_body_is_rejected_with_413() {
    let harness = TestHarness::setup(10, limits_with(true, 1024)).await;
    let res = test_client()
        .post(format!("http://{}/api/public/upload", harness.gateway_addr))
        .body(vec![0u8; 4096])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_under_limit_body_is_forwarded() {
    let harness = TestHarness::setup(10, limits_with(true, 1024)).await;
    let res = test_client()
        .post(format!("http://{}/api/public/upload", harness.gateway_addr))
        .body(vec![0u8; 512])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_disabled_limits_let_over_limit_body_through() {
    let harness = TestHarness::setup(10, limits_with(false, 1024)).await;
    let res = test_client()
        .post(format!("http://{}/api/public/upload", harness.gateway_addr))
        .body(vec![0u8; 4096])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

fn received_headers(body: &serde_json::Value) -> Vec<String> {
    body["headers"]
        .as_array()
        .expect("headers array")
        .iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect()
}

fn allowlist_headers(names: &[&str]) -> HeadersConfig {
    HeadersConfig {
        filter: HeaderFilter::Allowlist {
            names: names.iter().map(|name| (*name).to_string()).collect(),
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn test_disallowed_header_dropped_and_allowed_header_forwarded() {
    let harness = TestHarness::setup(10, LimitsConfig::default()).await;
    let res = test_client()
        .get(format!("http://{}/api/public/x", harness.gateway_addr))
        .header("x-evil-header", "1")
        .header("accept", "text/plain")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    let names = received_headers(&body);
    assert!(!names.contains(&"x-evil-header".to_string()));
    assert!(names.contains(&"accept".to_string()));
}

#[tokio::test]
async fn test_forged_identity_headers_never_reach_upstream_on_public_route() {
    let harness = TestHarness::setup(10, LimitsConfig::default()).await;
    let res = test_client()
        .get(format!("http://{}/api/public/x", harness.gateway_addr))
        .header("x-user-id", "forged")
        .header("x-user-role", "admin")
        .header("x-token-id", "forged")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["user_id"], "none");
    assert_eq!(body["role"], "none");
    let names = received_headers(&body);
    assert!(!names.contains(&"x-token-id".to_string()));
}

#[tokio::test]
async fn test_connection_listed_header_is_stripped_before_upstream() {
    let headers = allowlist_headers(&["accept", "x-secret", "connection"]);
    let harness = TestHarness::setup_with_headers(10, LimitsConfig::default(), headers).await;
    let res = test_client()
        .get(format!("http://{}/api/public/x", harness.gateway_addr))
        .header("connection", "x-secret")
        .header("x-secret", "1")
        .header("accept", "text/plain")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    let names = received_headers(&body);
    assert!(!names.contains(&"x-secret".to_string()));
    assert!(names.contains(&"accept".to_string()));
}

#[tokio::test]
async fn test_hop_by_hop_stripping_can_be_disabled() {
    let headers = HeadersConfig {
        safety: HeaderSafetyConfig {
            strip_hop_by_hop: false,
            ..Default::default()
        },
        ..allowlist_headers(&["accept", "x-secret", "connection"])
    };
    let harness = TestHarness::setup_with_headers(10, LimitsConfig::default(), headers).await;
    let res = test_client()
        .get(format!("http://{}/api/public/x", harness.gateway_addr))
        .header("connection", "x-secret")
        .header("x-secret", "1")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(received_headers(&body).contains(&"x-secret".to_string()));
}

fn filter_headers(filter: HeaderFilter) -> HeadersConfig {
    HeadersConfig {
        filter,
        ..Default::default()
    }
}

async fn public_request_header_names(
    filter: HeaderFilter,
    headers: &[(&str, &str)],
) -> (serde_json::Value, Vec<String>) {
    let harness =
        TestHarness::setup_with_headers(10, LimitsConfig::default(), filter_headers(filter)).await;
    let mut request = test_client().get(format!("http://{}/api/public/x", harness.gateway_addr));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let res = request.send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    let names = received_headers(&body);
    (body, names)
}

#[tokio::test]
async fn test_passthrough_forwards_arbitrary_header() {
    let (_, names) =
        public_request_header_names(HeaderFilter::Passthrough, &[("x-custom", "1")]).await;
    assert!(names.contains(&"x-custom".to_string()));
}

#[tokio::test]
async fn test_denylist_drops_cookie_but_forwards_custom_header() {
    let filter = HeaderFilter::Denylist {
        names: vec!["cookie".to_string()],
    };
    let (_, names) =
        public_request_header_names(filter, &[("cookie", "a=b"), ("x-custom", "1")]).await;
    assert!(!names.contains(&"cookie".to_string()));
    assert!(names.contains(&"x-custom".to_string()));
}

#[tokio::test]
async fn test_forged_identity_headers_blocked_in_passthrough_and_denylist() {
    let forged = [
        ("x-user-id", "forged"),
        ("x-user-role", "admin"),
        ("x-token-id", "forged"),
    ];
    let filters = [
        HeaderFilter::Passthrough,
        HeaderFilter::Denylist {
            names: vec!["cookie".to_string()],
        },
    ];
    for filter in filters {
        let (body, names) = public_request_header_names(filter, &forged).await;
        assert_eq!(body["user_id"], "none");
        assert_eq!(body["role"], "none");
        assert!(!names.contains(&"x-token-id".to_string()));
    }
}

fn received_values(body: &serde_json::Value, name: &str) -> Vec<String> {
    body["header_values"][name]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn rule(name: &str, value: &str) -> HeaderRuleConfig {
    HeaderRuleConfig {
        name: name.to_string(),
        value: value.to_string(),
    }
}

async fn public_body_with(config: HeadersConfig, headers: &[(&str, &str)]) -> serde_json::Value {
    let harness = TestHarness::setup_with_headers(10, LimitsConfig::default(), config).await;
    let mut request = test_client().get(format!("http://{}/api/public/x", harness.gateway_addr));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let res = request.send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    res.json().await.unwrap()
}

#[tokio::test]
async fn test_set_rule_renders_client_ip_for_upstream() {
    let config = HeadersConfig {
        set: vec![rule("x-real-ip", "{client_ip}")],
        ..Default::default()
    };
    let body = public_body_with(config, &[("x-real-ip", "6.6.6.6")]).await;
    assert_eq!(received_values(&body, "x-real-ip"), vec!["127.0.0.1"]);
}

#[tokio::test]
async fn test_add_rule_arrives_at_upstream() {
    let config = HeadersConfig {
        add: vec![rule("x-gateway", "blueno")],
        ..Default::default()
    };
    let body = public_body_with(config, &[]).await;
    assert_eq!(received_values(&body, "x-gateway"), vec!["blueno"]);
}

#[tokio::test]
async fn test_remove_rule_drops_header_in_passthrough_mode() {
    let config = HeadersConfig {
        filter: HeaderFilter::Passthrough,
        remove: vec!["x-debug".to_string()],
        ..Default::default()
    };
    let body = public_body_with(config, &[("x-debug", "1"), ("x-custom", "2")]).await;
    let names = received_headers(&body);
    assert!(!names.contains(&"x-debug".to_string()));
    assert!(names.contains(&"x-custom".to_string()));
}

fn trusting_loopback() -> HeadersConfig {
    HeadersConfig {
        forwarding: ForwardingConfig {
            trusted_proxies: vec!["127.0.0.1".to_string()],
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn test_default_forwarding_headers_discard_spoofed_chain() {
    let body = public_body_with(
        HeadersConfig::default(),
        &[("x-forwarded-for", "9.9.9.9"), ("x-real-ip", "6.6.6.6")],
    )
    .await;
    assert_eq!(received_values(&body, "x-forwarded-for"), vec!["127.0.0.1"]);
    assert_eq!(received_values(&body, "x-real-ip"), vec!["127.0.0.1"]);
    assert_eq!(received_values(&body, "x-forwarded-proto"), vec!["http"]);
    assert_eq!(received_values(&body, "x-forwarded-host").len(), 1);
}

#[tokio::test]
async fn test_trusted_proxy_chain_is_extended_and_client_resolved() {
    let body = public_body_with(trusting_loopback(), &[("x-forwarded-for", "203.0.113.7")]).await;
    assert_eq!(
        received_values(&body, "x-forwarded-for"),
        vec!["203.0.113.7, 127.0.0.1"]
    );
    assert_eq!(received_values(&body, "x-real-ip"), vec!["203.0.113.7"]);
}
