use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::fs;
use lazy_static::lazy_static;
use crate::web::ProxyConfig;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsData {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub throttled_requests: u64,
    pub active_connections: u64,
}

impl Default for MetricsData {
    fn default() -> Self {
        Self {
            total_requests: 0,
            cache_hits: 0,
            cache_misses: 0,
            throttled_requests: 0,
            active_connections: 0,
        }
    }
}

lazy_static! {
    pub static ref METRICS: Arc<RwLock<MetricsData>> = Arc::new(RwLock::new(MetricsData::default()));
}

// Function to increment metrics
pub async fn increment_metric(metric: &str) {
    let mut metrics = METRICS.write().await;
    match metric {
        "total_requests" => metrics.total_requests += 1,
        "cache_hits" => metrics.cache_hits += 1,
        "cache_misses" => metrics.cache_misses += 1,
        "throttled_requests" => metrics.throttled_requests += 1,
        "active_connections" => metrics.active_connections += 1,
        _ => log::warn!("Unknown metric: {}", metric),
    }
}

pub async fn decrement_metric(metric: &str) {
    let mut metrics = METRICS.write().await;
    match metric {
        "active_connections" => {
            if metrics.active_connections > 0 {
                metrics.active_connections -= 1;
            }
        }
        _ => log::warn!("Cannot decrement metric: {}", metric),
    }
}

pub async fn get_metrics() -> MetricsData {
    METRICS.read().await.clone()
}

// Configuration management
pub async fn save_config(config: &ProxyConfig) -> std::io::Result<()> {
    let config_path = "proxy_project/config/proxy.json";
    let config_str = serde_json::to_string_pretty(config)?;
    fs::write(config_path, config_str)?;
    
    // Signal the proxy to reload configuration
    reload_configuration().await?;
    Ok(())
}

pub async fn load_config() -> std::io::Result<ProxyConfig> {
    let config_path = "proxy_project/config/proxy.json";
    if let Ok(config_str) = fs::read_to_string(config_path) {
        Ok(serde_json::from_str(&config_str)?)
    } else {
        Ok(ProxyConfig::default())
    }
}

async fn reload_configuration() -> std::io::Result<()> {
    // Implement configuration reload logic here
    // This might involve signaling other parts of the application
    Ok(())
} 