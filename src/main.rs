mod proxy;
mod tls;
mod cache;
mod acl;
mod web;
mod logger;
mod rate_limiter;
mod config_manager;

use tokio::join;

#[tokio::main]
async fn main() {
    // Initialize logging (see logger.rs)
    logger::init();

    log::info!("Starting Proxy Server...");

    // Launch both the proxy server and the web interface concurrently.
    let proxy_task = tokio::spawn(proxy::run_proxy());
    let web_task = tokio::spawn(web::run_web_interface());

    // Wait for both servers (they will run indefinitely).
    let _ = join!(proxy_task, web_task);
} 