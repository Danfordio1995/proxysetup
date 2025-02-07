use warp::Filter;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use crate::config_manager::METRICS;
use futures_util::{StreamExt, SinkExt};
use prometheus::{Encoder, TextEncoder};
use warp::reply::Reply;
use warp::http::StatusCode;
use warp::Rejection;
use crate::auth::{with_auth, handle_rejection};
use crate::users::{UserRole, Claims};
use crate::acl::{self, AclConfig as AclConfigFromAcl};
use serde_json::json;

// Add configuration structures
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    pub acl: AclConfigFromAcl,
    pub cache: CacheConfig,
    pub tls: TlsConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AclConfig {
    pub blocked_domains: Vec<String>,
    pub allowed_ips: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    pub memory_size: usize,
    pub disk_size: usize,
    pub ttl: u64,
    pub serve_stale: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub enable_tls13: bool,
    pub session_tickets: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

// Request/Response types
#[derive(Debug, Serialize, Deserialize)]
pub struct DomainRequest {
    pub domain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpRequest {
    pub ip: String,
}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    InvalidCredentials,
    InsufficientPermissions,
}

impl warp::reject::Reject for AuthError {}

// Global configuration state
lazy_static! {
    static ref PROXY_CONFIG: Arc<RwLock<ProxyConfig>> = Arc::new(RwLock::new(ProxyConfig::default()));
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            blocked_domains: vec!["*.malicious.com".to_string()],
            allowed_ips: vec!["10.0.0.0/8".to_string()],
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            memory_size: 10240,
            disk_size: 10240,
            ttl: 3600,
            serve_stale: true,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: "/opt/proxy_project/certs/cert.pem".to_string(),
            key_path: "/opt/proxy_project/certs/key.pem".to_string(),
            enable_tls13: true,
            session_tickets: true,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 200,
        }
    }
}

/// Runs the web interface on port 9000, serving dashboard, metrics, configuration, and admin endpoints.
pub async fn run_web_interface() {
    // Serve static files
    let login_page = warp::path("login")
        .and(warp::get())
        .map(|| {
            warp::reply::html(include_str!("../static/login.html"))
        });

    // Root redirect to login
    let root = warp::path::end()
        .map(|| {
            warp::redirect::temporary(warp::http::Uri::from_static("/login"))
        });

    // Metrics endpoint exposes Prometheus-compatible metrics.
    let metrics = warp::path!("metrics")
        .map(|| {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            String::from_utf8(buffer).unwrap()
        })
        .boxed();

    // Configuration endpoint stub.
    let config = warp::path("config")
        .map(|| warp::reply::html(include_str!("config_page.html")))
        .boxed();

    // Admin dashboard endpoint: expects query parameters "user" and "pass".
    let admin = warp::path("admin")
        .and(warp::query::<HashMap<String, String>>())
        .map(|params: HashMap<String, String>| {
            let empty = String::new();
            let user = params.get("user").unwrap_or(&empty);
            let pass = params.get("pass").unwrap_or(&empty);
            
            if user == "admin" && pass == "password" {
                warp::reply::with_status(
                    warp::reply::html(include_str!("admin_dashboard.html")),
                    StatusCode::OK
                )
            } else {
                warp::reply::with_status(
                    warp::reply::html("Unauthorized: Invalid credentials"),
                    StatusCode::UNAUTHORIZED
                )
            }
        })
        .boxed();

    // Admin login page: Provides instructions on the admin credentials.
    let admin_login = warp::path!("admin" / "login")
        .map(|| warp::reply::html(include_str!("admin_login.html")))
        .boxed();

    // Add API endpoints for configuration
    let config_state = Arc::clone(&PROXY_CONFIG);
    
    // GET current configuration
    let get_config = {
        let config_state = Arc::clone(&config_state);
        warp::path!("api" / "config")
            .and(warp::get())
            .and_then(move || {
                let config_state = Arc::clone(&config_state);
                async move {
                    let config = config_state.read().await;
                    Ok::<_, Rejection>(warp::reply::json(&*config))
                }
            })
            .boxed()
    };

    // POST update configuration
    let update_config = {
        let config_state = Arc::clone(&config_state);
        warp::path!("api" / "config")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |new_config: ProxyConfig| {
                let config_state = Arc::clone(&config_state);
                async move {
                    let mut config = config_state.write().await;
                    // Clone new_config before moving it into config
                    let new_config_clone = new_config.clone();
                    *config = new_config;
                    
                    if let Err(e) = save_config_to_disk(&new_config_clone) {
                        log::error!("Failed to save configuration: {}", e);
                        return Ok::<_, Rejection>(warp::reply::with_status(
                            "Failed to save configuration",
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                    }

                    Ok(warp::reply::with_status(
                        "Configuration updated successfully",
                        StatusCode::OK,
                    ))
                }
            })
            .boxed()
    };

    // Add API endpoints for metrics
    let metrics_state = Arc::clone(&METRICS);
    
    // GET current metrics
    let get_metrics = {
        let metrics_state = Arc::clone(&metrics_state);
        warp::path!("api" / "metrics")
            .and(warp::get())
            .and_then(move || {
                let metrics_state = Arc::clone(&metrics_state);
                async move {
                    let metrics = metrics_state.read().await;
                    Ok::<_, Rejection>(warp::reply::json(&*metrics))
                }
            })
            .boxed()
    };

    // WebSocket endpoint for real-time metrics updates
    let ws_metrics = warp::path!("ws" / "metrics")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| {
            ws.on_upgrade(|websocket| handle_ws_client(websocket))
        })
        .boxed();

    // ACL Management Routes
    let acl_routes = get_acl_route()
        .or(add_blocked_domain_route())
        .or(remove_blocked_domain_route())
        .or(add_blocked_ip_route())
        .or(remove_blocked_ip_route())
        .with(warp::cors().allow_any_origin())
        .recover(handle_rejection);

    // Combine all routes
    let routes = root
        .or(login_page)
        .or(metrics)
        .or(config)
        .or(admin)
        .or(admin_login)
        .or(get_config)
        .or(update_config)
        .or(get_metrics)
        .or(ws_metrics)
        .or(acl_routes);

    println!("Web interface running on http://localhost:9000");
    
    // Serve the web interface on port 9000
    warp::serve(routes)
        .run(([0, 0, 0, 0], 9000))
        .await;
}

// Helper functions for configuration management
fn save_config_to_disk(config: &ProxyConfig) -> std::io::Result<()> {
    let config_path = "/opt/proxy_project/config/proxy.json";
    let config_str = serde_json::to_string_pretty(config)?;
    std::fs::write(config_path, config_str)
}

fn reload_proxy_config() -> std::io::Result<()> {
    // Signal the proxy to reload its configuration
    // This could be done through a Unix domain socket, shared memory, or other IPC mechanism
    Ok(())
}

// Add WebSocket handler for real-time metrics
async fn handle_ws_client(ws: warp::ws::WebSocket) {
    let metrics = Arc::clone(&METRICS);
    
    // Send metrics updates every second
    let (mut tx, _) = ws.split();
    
    loop {
        let current_metrics = metrics.read().await.clone();
        if let Ok(json) = serde_json::to_string(&current_metrics) {
            if tx.send(warp::ws::Message::text(json)).await.is_err() {
                break;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

// ACL Management Routes

fn get_acl_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "acl")
        .and(warp::get())
        .and(with_auth())
        .and_then(handle_get_acl)
}

fn add_blocked_domain_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "acl" / "domains")
        .and(warp::post())
        .and(with_auth())
        .and(warp::body::json())
        .and_then(handle_add_blocked_domain)
}

fn remove_blocked_domain_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "acl" / "domains" / String)
        .and(warp::delete())
        .and(with_auth())
        .and_then(handle_remove_blocked_domain)
}

fn add_blocked_ip_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "acl" / "ips")
        .and(warp::post())
        .and(with_auth())
        .and(warp::body::json())
        .and_then(handle_add_blocked_ip)
}

fn remove_blocked_ip_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "acl" / "ips" / String)
        .and(warp::delete())
        .and(with_auth())
        .and_then(handle_remove_blocked_ip)
}

async fn handle_get_acl(claims: Claims) -> Result<impl Reply, Rejection> {
    match claims.role {
        UserRole::Admin => {
            let config = acl::get_acl_config().await;
            Ok(warp::reply::json(&config))
        }
        _ => Err(warp::reject::custom(AuthError::InsufficientPermissions)),
    }
}

async fn handle_add_blocked_domain(claims: Claims, body: DomainRequest) -> Result<impl Reply, Rejection> {
    match claims.role {
        UserRole::Admin => {
            match acl::add_blocked_domain(body.domain).await {
                Ok(()) => Ok(warp::reply::json(&json!({ "message": "Domain blocked successfully" }))),
                Err(e) => Ok(warp::reply::json(&json!({ "error": e })))
            }
        }
        _ => Err(warp::reject::custom(AuthError::InsufficientPermissions)),
    }
}

async fn handle_remove_blocked_domain(domain: String, claims: Claims) -> Result<impl Reply, Rejection> {
    match claims.role {
        UserRole::Admin => {
            match acl::remove_blocked_domain(&domain).await {
                Ok(()) => Ok(warp::reply::json(&json!({ "message": "Domain unblocked successfully" }))),
                Err(e) => Ok(warp::reply::json(&json!({ "error": e })))
            }
        }
        _ => Err(warp::reject::custom(AuthError::InsufficientPermissions)),
    }
}

async fn handle_add_blocked_ip(claims: Claims, body: IpRequest) -> Result<impl Reply, Rejection> {
    match claims.role {
        UserRole::Admin => {
            match acl::add_blocked_ip(body.ip).await {
                Ok(()) => Ok(warp::reply::json(&json!({ "message": "IP blocked successfully" }))),
                Err(e) => Ok(warp::reply::json(&json!({ "error": e })))
            }
        }
        _ => Err(warp::reject::custom(AuthError::InsufficientPermissions)),
    }
}

async fn handle_remove_blocked_ip(ip: String, claims: Claims) -> Result<impl Reply, Rejection> {
    match claims.role {
        UserRole::Admin => {
            match acl::remove_blocked_ip(&ip).await {
                Ok(()) => Ok(warp::reply::json(&json!({ "message": "IP unblocked successfully" }))),
                Err(e) => Ok(warp::reply::json(&json!({ "error": e })))
            }
        }
        _ => Err(warp::reject::custom(AuthError::InsufficientPermissions)),
    }
} 