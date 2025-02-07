use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, Client, Uri};
use std::convert::Infallible;
use lazy_static::lazy_static;
use tokio::sync::Mutex;
use std::net::SocketAddr;
use crate::{rate_limiter::RateLimiter, cache::cache_get, acl::check_acl};
use std::error::Error as StdError;

static BACKEND: &str = "http://127.0.0.1:8080"; // Backend server address (adjust as needed)

lazy_static! {
    // Global rate limiter: Here, capacity is 100 tokens and 100 tokens are refilled per second.
    static ref GLOBAL_RATE_LIMITER: Mutex<RateLimiter> = Mutex::new(RateLimiter::new(100.0, 100.0));
}

/// Handles incoming HTTP requests and forwards them to the backend.
async fn handle_request(req: Request<Body>, remote_addr: SocketAddr) -> Result<Response<Body>, hyper::Error> {
    log::info!("Proxying request: {} {} from {}", req.method(), req.uri(), remote_addr);

    // Check global rate limiter before processing the request.
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

    // Extract host and path for ACL check
    let host = req.uri().host().unwrap_or_default();
    let path = req.uri().path();
    let ip = remote_addr.ip().to_string();

    // Enhanced ACL check with IP and path
    if !check_acl(host, Some(&ip), Some(path)).await {
        log::warn!("Access denied for {}:{} from {}", host, path, ip);
        return Ok(Response::builder()
            .status(403)
            .body(Body::from("Forbidden"))
            .unwrap());
    }

    // Check cache for GET requests
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

    // Build new URI based on the BACKEND address
    let mut parts = req.uri().clone().into_parts();
    let backend_uri: Uri = BACKEND.parse().map_err(|e: hyper::http::uri::InvalidUri| {
        log::error!("Failed to parse backend URI: {}", e);
        hyper::Error::new_user_body(Box::new(e))
    })?;
    
    parts.scheme = backend_uri.scheme().cloned();
    parts.authority = backend_uri.authority().cloned();
    
    let new_uri = Uri::from_parts(parts).map_err(|e: hyper::http::Error| {
        log::error!("Failed to build URI: {}", e);
        hyper::Error::new_user_body(Box::new(e))
    })?;

    // Rebuild the request with the updated URI
    let (parts, body) = req.into_parts();
    let mut req_builder = Request::builder()
        .method(&parts.method)
        .uri(new_uri);

    // Copy all headers from the original request
    for (key, value) in parts.headers.iter() {
        req_builder = req_builder.header(key, value);
    }

    // Add X-Forwarded headers
    req_builder = req_builder
        .header("X-Forwarded-For", remote_addr.ip().to_string())
        .header("X-Forwarded-Proto", "http")
        .header("X-Forwarded-Host", host);

    let proxy_req = req_builder.body(body).map_err(|e: hyper::http::Error| {
        log::error!("Failed to build proxy request: {}", e);
        hyper::Error::new_user_body(Box::new(e))
    })?;

    // Forward the request to the backend and return the response
    let resp = client.request(proxy_req).await?;
    
    // Log response status
    log::info!("Backend responded with status {} for {} {}", 
        resp.status(), 
        parts.method, 
        parts.uri
    );

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