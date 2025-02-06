use warp::Filter;
use prometheus::{Encoder, TextEncoder, IntCounter, register_int_counter};
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    // A Prometheus counter to record sample metrics.
    static ref REQUEST_COUNTER: IntCounter = register_int_counter!("requests_total", "Total number of requests").unwrap();
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
        "Configuration page (stub) - Manage ACLs, caching policies, TLS settings, etc."
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

    // Combine routes.
    let routes = root.or(metrics).or(config).or(admin).or(admin_login);

    // Serve the web interface on port 9000.
    warp::serve(routes)
        .run(([0, 0, 0, 0], 9000))
        .await;
} 