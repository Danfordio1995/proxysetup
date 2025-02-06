use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, Client, Uri};
use std::convert::Infallible;

static BACKEND: &str = "http://127.0.0.1:8080"; // Backend server address (adjust as needed)

/// Handles incoming HTTP requests and forwards them to the backend.
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    log::info!("Proxying request: {} {}", req.method(), req.uri());

    let client = Client::new();

    // Build new URI based on the BACKEND address.  
    // The original URI is adjusted to use the backend's scheme/authority.
    let mut parts = req.uri().clone().into_parts();
    let backend_uri: Uri = BACKEND.parse().expect("Invalid backend URI");
    parts.scheme = backend_uri.scheme().cloned();
    parts.authority = backend_uri.authority().cloned();
    let new_uri = Uri::from_parts(parts).expect("Failed to build new URI");

    // Rebuild the request with the updated URI.
    let (parts, body) = req.into_parts();
    let mut req_builder = Request::builder()
        .method(&parts.method)
        .uri(new_uri);
    // Copy all headers from the original request.
    for (key, value) in parts.headers.iter() {
        req_builder = req_builder.header(key, value);
    }
    let proxy_req = req_builder.body(body).expect("Failed to build proxy request");

    // Forward the request to the backend and return the response.
    let resp = client.request(proxy_req).await?;
    Ok(resp)
}

/// Runs the proxy server on port 8000.
pub async fn run_proxy() {
    let addr = ([0, 0, 0, 0], 8000).into();
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_request))
    });

    let server = Server::bind(&addr).serve(make_svc);
    log::info!("HTTP Proxy running on http://{}", addr);

    if let Err(e) = server.await {
        log::error!("Server error: {}", e);
    }
} 