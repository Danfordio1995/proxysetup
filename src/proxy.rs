use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, Client, Uri};
use std::convert::Infallible;
use lazy_static::lazy_static;
use tokio::sync::Mutex;
use std::net::SocketAddr;
use crate::{rate_limiter::RateLimiter, cache::cache_get, acl::check_acl};

// The backend address is a constant.
static BACKEND: &str = "http://127.0.0.1:8080";

lazy_static! {
    // Pre-parse the backend URI once at startup.
    static ref BACKEND_URI: Uri = BACKEND.parse().expect("Invalid backend URI");

    // Global rate limiter: capacity of 100 tokens with a refill rate of 100 tokens per second.
    static ref GLOBAL_RATE_LIMITER: Mutex<RateLimiter> = Mutex::new(RateLimiter::new(100.0, 100.0));
}

/// Handles incoming HTTP requests and forwards them to the backend.
async fn handle_request(req: Request<Body>, remote_addr: SocketAddr) -> Result<Response<Body>, hyper::Error> {
    log::info!("Proxying request: {} {} from {}", req.method(), req.uri(), remote_addr);

    // Global rate limiting.
    {
        let mut limiter = GLOBAL_RATE_LIMITER.lock().await;
        if !limiter.allow().await {
            log::warn!("Rate limit exceeded for {}", remote_addr);
            return Ok(Response::builder()
                .status(429)
                .header("Retry-After", "5")
                .body(Body::from("Too Many Requests"))
                .unwrap());
        }
    }

    // ACL check.
    let host = req.uri().host().unwrap_or_default();
    let path = req.uri().path();
    let ip = remote_addr.ip().to_string();

    if !check_acl(host, Some(&ip), Some(path)).await {
        log::warn!("Access denied for {}:{} from {}", host, path, ip);
        return Ok(Response::builder()
            .status(403)
            .body(Body::from("Forbidden"))
            .unwrap());
    }

    // Cache check for GET requests.
    if req.method() == hyper::Method::GET {
        if let Some(cached) = cache_get(req.uri().path()).await {
            log::debug!("Cache hit for {}", req.uri().path());
            return Ok(Response::builder()
                .status(200)
                .header("X-Cache", "HIT")
                .body(Body::from(cached))
                .unwrap());
        }
    }

    let client = Client::new();

    // Build a new URI by replacing the scheme and authority from the backend.
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = BACKEND_URI.scheme().cloned();
    parts.authority = BACKEND_URI.authority().cloned();

    let new_uri = match Uri::from_parts(parts) {
        Ok(uri) => uri,
        Err(e) => {
            log::error!("Failed to build URI: {}", e);
            return Ok(Response::builder()
                .status(500)
                .body(Body::from("Internal Server Error"))
                .unwrap());
        }
    };

    // Rebuild the request with the new URI.
    let (parts, body) = req.into_parts();
    let mut req_builder = Request::builder()
        .method(&parts.method)
        .uri(new_uri);

    // Copy the headers from the original request.
    for (key, value) in parts.headers.iter() {
        req_builder = req_builder.header(key, value);
    }

    // Add X-Forwarded headers.
    req_builder = req_builder
        .header("X-Forwarded-For", remote_addr.ip().to_string())
        .header("X-Forwarded-Proto", "http")
        .header("X-Forwarded-Host", host);

    let proxy_req = match req_builder.body(body) {
        Ok(req) => req,
        Err(e) => {
            log::error!("Failed to build proxy request: {}", e);
            return Ok(Response::builder()
                .status(500)
                .body(Body::from("Internal Server Error"))
                .unwrap());
        }
    };

    // Forward the request to the backend.
    let resp = client.request(proxy_req).await?;
    log::info!("Backend responded with status {} for {} {}",
              resp.status(), parts.method, parts.uri);
    Ok(resp)
}

/// Runs the proxy server on port 8000.
pub async fn run_proxy() {
    let addr = ([0, 0, 0, 0], 8000).into();
    
    let make_svc = make_service_fn(|conn: &hyper::server::conn::AddrStream| {
        let remote_addr = conn.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, remote_addr)
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    log::info!("HTTP Proxy running on http://{}", addr);

    if let Err(e) = server.await {
        log::error!("Server error: {}", e);
    }
}
