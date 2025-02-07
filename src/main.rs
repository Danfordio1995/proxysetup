mod acl;
mod auth;
mod cache;
mod config_manager;
mod proxy;
mod rate_limiter;
mod users;
mod web;

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    // Run the proxy server in a separate task
    tokio::spawn(proxy::run_proxy());

    // Run the web interface (this will block)
    web::run_web_interface().await;
} 