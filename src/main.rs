mod proxy;
mod tls;
mod cache;
mod acl;
mod web;
mod logger;
mod rate_limiter;

use tokio::join;

#[tokio::main]
async fn main() {
    // Initialize logging (see logger.rs)
    logger::init();

    log::info!("Starting Proxy Server...");

    // Launch both the proxy server and the web interface concurrently.
    let proxy_task = tokio::spawn(async { proxy::run_proxy().await });
    let web_task = tokio::spawn(async { web::run_web_interface().await });

    // Wait for both servers (they will run indefinitely).
    let _ = join!(proxy_task, web_task);
} 