use warp::Filter;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use crate::config_manager::{self, MetricsData, METRICS};

// Add configuration structures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    acl: AclConfig,
    cache: CacheConfig,
    tls: TlsConfig,
    rate_limit: RateLimitConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AclConfig {
    blocked_domains: Vec<String>,
    allowed_ips: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheConfig {
    memory_size: usize,
    disk_size: usize,
    ttl: u64,
    serve_stale: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
    enable_tls13: bool,
    session_tickets: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RateLimitConfig {
    requests_per_second: u32,
    burst_size: u32,
}

// Global configuration state
lazy_static! {
    static ref PROXY_CONFIG: Arc<RwLock<ProxyConfig>> = Arc::new(RwLock::new(ProxyConfig::default()));
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            acl: AclConfig {
                blocked_domains: vec!["*.malicious.com".to_string()],
                allowed_ips: vec!["10.0.0.0/8".to_string()],
            },
            cache: CacheConfig {
                memory_size: 10240,
                disk_size: 10240,
                ttl: 3600,
                serve_stale: true,
            },
            tls: TlsConfig {
                cert_path: "/opt/proxy_project/certs/cert.pem".to_string(),
                key_path: "/opt/proxy_project/certs/key.pem".to_string(),
                enable_tls13: true,
                session_tickets: true,
            },
            rate_limit: RateLimitConfig {
                requests_per_second: 100,
                burst_size: 200,
            },
        }
    }
}

/// Runs the web interface on port 9000, serving dashboard, metrics, configuration, and admin endpoints.
pub async fn run_web_interface() {
    // Dashboard endpoint (root)
    let root = warp::path::end().map(|| {
        "Proxy Dashboard - Welcome! This is a stub for the production dashboard."
    });

    // Metrics endpoint exposes Prometheus-compatible metrics.
    let metrics = warp::path!("metrics").map(|| {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    });

    // Configuration endpoint stub.
    let config = warp::path("config").map(|| {
        warp::reply::html(include_str!("config_page.html"))
    });

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
                    warp::http::StatusCode::OK
                )
            } else {
                warp::reply::with_status(
                    warp::reply::html("Unauthorized: Invalid credentials"),
                    warp::http::StatusCode::UNAUTHORIZED
                )
            }
        });

    // Admin login page: Provides instructions on the admin credentials.
    let admin_login = warp::path!("admin" / "login").map(|| {
        warp::reply::html(include_str!("admin_login.html"))
    });

    // Add API endpoints for configuration
    let config_state = Arc::clone(&PROXY_CONFIG);
    
    // GET current configuration
    let get_config = warp::path!("api" / "config")
        .and(warp::get())
        .map(move || {
            let config = config_state.read().await;
            warp::reply::json(&*config)
        });

    // POST update configuration
    let update_config = warp::path!("api" / "config")
        .and(warp::post())
        .and(warp::body::json())
        .map(move |new_config: ProxyConfig| {
            let mut config = config_state.write().await;
            *config = new_config;
            
            // Save to disk
            if let Err(e) = save_config_to_disk(&new_config) {
                log::error!("Failed to save configuration: {}", e);
                return warp::reply::with_status(
                    "Failed to save configuration",
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                );
            }

            // Notify proxy to reload configuration
            if let Err(e) = reload_proxy_config() {
                log::error!("Failed to reload proxy configuration: {}", e);
                return warp::reply::with_status(
                    "Failed to reload configuration",
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                );
            }

            warp::reply::with_status(
                "Configuration updated successfully",
                warp::http::StatusCode::OK,
            )
        });

    // Add API endpoints for metrics
    let metrics_state = Arc::clone(&METRICS);
    
    // GET current metrics
    let get_metrics = warp::path!("api" / "metrics")
        .and(warp::get())
        .map(move || {
            let metrics = metrics_state.read().await;
            warp::reply::json(&*metrics)
        });

    // WebSocket endpoint for real-time metrics updates
    let ws_metrics = warp::path!("ws" / "metrics")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| {
            ws.on_upgrade(|socket| handle_ws_client(socket))
        });

    // Combine routes
    let routes = root
        .or(metrics)
        .or(config)
        .or(admin)
        .or(admin_login)
        .or(get_config)
        .or(update_config)
        .or(get_metrics)
        .or(ws_metrics);

    // Serve the web interface on port 9000.
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