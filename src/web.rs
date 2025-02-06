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
        let response = String::from_utf8(buffer).unwrap();
        response
    });

    // Configuration endpoint stub.
    let config = warp::path("config").map(|| {
        "Configuration page (stub) - Manage ACLs, caching policies, TLS settings, etc."
    });

    // Admin dashboard endpoint: expects query parameters "user" and "pass".
    let admin = warp::path("admin")
        .and(warp::query::<HashMap<String, String>>())
        .map(|params: HashMap<String, String>| {
            let user = params.get("user").unwrap_or(&"".to_string());
            let pass = params.get("pass").unwrap_or(&"".to_string());
            if user == "admin" && pass == "password" {
                warp::reply::html(r#"<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body { padding:20px; }
        .fade-in { animation: fadeIn 1s ease-out; }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
    </style>
</head>
<body class="fade-in">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <a class="navbar-brand" href="#">Proxy Admin</a>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item active">
                    <a class="nav-link" href="/">Dashboard</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/metrics">Metrics</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/config">Configuration</a>
                </li>
            </ul>
        </div>
    </nav>
    <div class="container mt-4">
        <h1>Admin Dashboard</h1>
        <p>Welcome, admin! Manage the system configurations below.</p>
        <form id="adminForm">
            <div class="form-group">
                <label for="setting1">Setting 1:</label>
                <input type="text" class="form-control" id="setting1" placeholder="Enter value">
            </div>
            <div class="form-group">
                <label for="setting2">Setting 2:</label>
                <input type="text" class="form-control" id="setting2" placeholder="Enter value">
            </div>
            <button type="submit" class="btn btn-primary">Save Changes</button>
        </form>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        $(document).ready(function() {
            $("#adminForm").on("submit", function(e) {
                e.preventDefault();
                alert("Settings have been saved!");
            });
        });
    </script>
</body>
</html>"#)
            } else {
                warp::reply::with_status(
                    "Unauthorized: Invalid credentials".to_string(),
                    warp::http::StatusCode::UNAUTHORIZED
                )
            }
        });

    // Admin login page: Provides instructions on the admin credentials.
    let admin_login = warp::path!("admin" / "login").map(|| {
        warp::reply::html(r#"<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h1 class="mt-5">Admin Login</h1>
                <p>Login using <strong>admin</strong> as username and <strong>password</strong> as password. After login, access the dashboard at <code>/admin?user=admin&pass=password</code></p>
                <form>
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" placeholder="Enter username">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" id="password" placeholder="Enter password">
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"#)
    });

    // Combine routes.
    let routes = root.or(metrics).or(config).or(admin).or(admin_login);

    // Serve the web interface on port 9000.
    warp::serve(routes)
        .run(([0, 0, 0, 0], 9000))
        .await;
} 