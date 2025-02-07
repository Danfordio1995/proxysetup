use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use lazy_static::lazy_static;
use regex::Regex;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    pub blocked_domains: Vec<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

impl Default for AclConfig {
    fn default() -> Self {
        AclConfig {
            blocked_domains: Vec::new(),
            allowed_ips: vec!["0.0.0.0/0".to_string()], // Allow all by default
            blocked_ips: Vec::new(),
            allowed_domains: Vec::new(),
        }
    }
}

lazy_static! {
    static ref ACL_CONFIG: Arc<RwLock<AclConfig>> = Arc::new(RwLock::new(AclConfig::default()));
}

pub async fn update_acl_config(config: AclConfig) {
    let mut acl = ACL_CONFIG.write().await;
    *acl = config;
}

pub async fn check_acl(host: &str, ip: Option<&str>, _path: Option<&str>) -> bool {
    let config = ACL_CONFIG.read().await;

    // Check IP restrictions if an IP is provided
    if let Some(ip_str) = ip {
        if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
            // Check blocked IPs first
            for blocked in &config.blocked_ips {
                if let Ok(network) = blocked.parse::<IpNet>() {
                    if network.contains(&ip_addr) {
                        log::warn!("IP {} is blocked by ACL", ip_str);
                        return false;
                    }
                }
            }

            // Then check if IP is in allowed ranges
            let mut ip_allowed = false;
            for allowed in &config.allowed_ips {
                if let Ok(network) = allowed.parse::<IpNet>() {
                    if network.contains(&ip_addr) {
                        ip_allowed = true;
                        break;
                    }
                }
            }

            if !ip_allowed {
                log::warn!("IP {} is not in allowed ranges", ip_str);
                return false;
            }
        }
    }

    // Check domain restrictions
    // First check if domain is explicitly blocked
    for pattern in &config.blocked_domains {
        if let Ok(re) = create_domain_pattern(pattern) {
            if re.is_match(host) {
                log::warn!("Domain {} is blocked by pattern {}", host, pattern);
                return false;
            }
        }
    }

    // If there are allowed domains, check if the host matches any
    if !config.allowed_domains.is_empty() {
        let mut domain_allowed = false;
        for pattern in &config.allowed_domains {
            if let Ok(re) = create_domain_pattern(pattern) {
                if re.is_match(host) {
                    domain_allowed = true;
                    break;
                }
            }
        }

        if !domain_allowed {
            log::warn!("Domain {} is not in allowed list", host);
            return false;
        }
    }

    true
}

fn create_domain_pattern(pattern: &str) -> Result<Regex, regex::Error> {
    let pattern = pattern
        .replace(".", "\\.")
        .replace("*", ".*");
    Regex::new(&format!("^{}$", pattern))
}

pub async fn load_acl_from_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(config_path)?;
    let config: serde_json::Value = serde_json::from_str(&config_str)?;
    
    if let Some(acl) = config.get("acl") {
        let acl_config: AclConfig = serde_json::from_value(acl.clone())?;
        update_acl_config(acl_config).await;
    }
    
    Ok(())
} 