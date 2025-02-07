use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, Client, Uri};
use std::convert::Infallible;
use lazy_static::lazy_static;
use tokio::sync::Mutex;
use std::net::SocketAddr;
use crate::{rate_limiter::RateLimiter, cache::cache_get, acl::check_acl};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

static BACKEND: &str = "http://127.0.0.1:8080";

lazy_static! {
    // Pre-parse the backend URI once at startup.
    static ref BACKEND_URI: Uri = BACKEND.parse().expect("Invalid backend URI");

    // Global rate limiter: capacity of 100 tokens with a refill rate of 100 tokens per second.
    static ref GLOBAL_RATE_LIMITER: Mutex<RateLimiter> = Mutex::new(RateLimiter::new(100.0, 100.0));
}

async fn tunnel(mut client_conn: hyper::upgrade::Upgraded, addr: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut server_conn = TcpStream::connect(addr).await?;
    
    let (mut client_read, mut client_write) = tokio::io::split(client_conn);
    let (mut server_read, mut server_write) = server_conn.split();

    let client_to_server = async {
        tokio::io::copy(&mut client_read, &mut server_write).await?;
        server_write.shutdown().await?;
        Ok::<_, std::io::Error>(())
    };

    let server_to_client = async {
        tokio::io::copy(&mut server_read, &mut client_write).await?;
        client_write.shutdown().await?;
        Ok::<_, std::io::Error>(())
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
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

    // Handle CONNECT method for HTTPS tunneling
    if req.method() == hyper::Method::CONNECT {
        let addr = match req.uri().authority() {
            Some(authority) => authority.to_string(),
            None => {
                return Ok(Response::builder()
                    .status(400)
                    .body(Body::from("Missing authority in CONNECT request"))
                    .unwrap());
            }
        };

        // Create a response that will be upgraded
        let resp = Response::builder()
            .status(200)
            .body(Body::empty())
            .unwrap();

        // Spawn a task to handle the tunnel
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, addr).await {
                        log::error!("Tunnel error: {}", e);
                    }
                }
                Err(e) => log::error!("Upgrade error: {}", e),
            }
        });

        return Ok(resp);
    }

    // Clone the host string to avoid borrowing issues when consuming `req` later.
    let host = req.uri().host().unwrap_or_default().to_string();
    let path = req.uri().path();
    let ip = remote_addr.ip().to_string();

    // Enhanced ACL check with IP and path.
    if !check_acl(&host, Some(&ip), Some(path)).await {
        log::warn!("Access denied for {}:{} from {}", host, path, ip);
        return Ok(Response::builder()
            .status(403)
            .body(Body::from("Forbidden"))
            .unwrap());
    }

    // Check cache for GET requests.
    if req.method() == hyper::Method::GET {
        if let Some(cached) = cache_get(path).await {
            log::debug!("Cache hit for {}", path);
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

    // Consume the request to get its parts and body.
    let (parts, body) = req.into_parts();
    let mut req_builder = Request::builder()
        .method(&parts.method)
        .uri(new_uri);

    // Copy headers from the original request.
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
    log::info!(
        "Backend responded with status {} for {} {}",
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

#[tokio::main]
async fn main() {
    // Initialize logging; ensure you have env_logger as a dependency.
    env_logger::init();
    run_proxy().await;
}
