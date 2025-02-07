use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::fs;
use lazy_static::lazy_static;
use crate::web::ProxyConfig;
use std::collections::HashMap;

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
    let config_path = "/opt/proxy_project/config/proxy.json";
    let config_str = serde_json::to_string_pretty(config)?;
    fs::write(config_path, config_str)?;
    
    // Signal the proxy to reload configuration
    reload_configuration().await?;
    Ok(())
}

pub async fn load_config() -> std::io::Result<ProxyConfig> {
    let config_path = "/opt/proxy_project/config/proxy.json";
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackendConfig {
    pub url: String,
    pub enabled: bool,
    #[serde(default)]
    pub rate_limit: Option<f64>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub backends: HashMap<String, BackendConfig>,
    pub default_backend: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    8000
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let mut backends = HashMap::new();
        backends.insert(
            "default".to_string(),
            BackendConfig {
                url: "http://127.0.0.1:8080".to_string(),
                enabled: true,
                rate_limit: Some(100.0),
                timeout_seconds: Some(30),
            },
        );

        ProxyConfig {
            backends,
            default_backend: "default".to_string(),
            port: default_port(),
        }
    }
}

#[derive(Clone)]
pub struct ConfigManager {
    config: Arc<RwLock<ProxyConfig>>,
}

impl ConfigManager {
    pub fn new() -> Self {
        ConfigManager {
            config: Arc::new(RwLock::new(ProxyConfig::default())),
        }
    }

    pub async fn load_config(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config_str = fs::read_to_string(path)?;
        let config: ProxyConfig = serde_json::from_str(&config_str)?;
        
        // Validate the configuration
        if !config.backends.contains_key(&config.default_backend) {
            return Err("Default backend not found in backends list".into());
        }

        let mut write_guard = self.config.write().await;
        *write_guard = config;
        Ok(())
    }

    pub async fn get_backend(&self, host: &str) -> Option<BackendConfig> {
        let config = self.config.read().await;
        
        // First try to find a direct match for the host
        if let Some(backend) = config.backends.get(host) {
            if backend.enabled {
                return Some(backend.clone());
            }
        }

        // If no direct match, return the default backend if it's enabled
        config.backends.get(&config.default_backend)
            .filter(|b| b.enabled)
            .cloned()
    }

    pub async fn get_port(&self) -> u16 {
        self.config.read().await.port
    }

    pub async fn add_backend(&self, host: String, backend: BackendConfig) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = self.config.write().await;
        config.backends.insert(host, backend);
        Ok(())
    }

    pub async fn remove_backend(&self, host: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = self.config.write().await;
        if host == config.default_backend {
            return Err("Cannot remove default backend".into());
        }
        config.backends.remove(host);
        Ok(())
    }

    pub async fn save_config(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.read().await;
        let config_str = serde_json::to_string_pretty(&*config)?;
        fs::write(path, config_str)?;
        Ok(())
    }
} 