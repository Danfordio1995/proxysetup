use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use lazy_static::lazy_static;
use regex::Regex;
use ipnet::IpNet;
use std::net::IpAddr;
use std::fs;

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

pub async fn get_acl_config() -> AclConfig {
    ACL_CONFIG.read().await.clone()
}

pub async fn add_blocked_domain(domain: String) -> Result<(), String> {
    let mut acl = ACL_CONFIG.write().await;
    if !acl.blocked_domains.contains(&domain) {
        acl.blocked_domains.push(domain);
        save_acl_config(&acl).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub async fn remove_blocked_domain(domain: &str) -> Result<(), String> {
    let mut acl = ACL_CONFIG.write().await;
    if let Some(pos) = acl.blocked_domains.iter().position(|x| x == domain) {
        acl.blocked_domains.remove(pos);
        save_acl_config(&acl).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub async fn add_blocked_ip(ip: String) -> Result<(), String> {
    // Validate IP/CIDR format
    if ip.parse::<IpNet>().is_err() {
        return Err("Invalid IP or CIDR format".to_string());
    }

    let mut acl = ACL_CONFIG.write().await;
    if !acl.blocked_ips.contains(&ip) {
        acl.blocked_ips.push(ip);
        save_acl_config(&acl).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub async fn remove_blocked_ip(ip: &str) -> Result<(), String> {
    let mut acl = ACL_CONFIG.write().await;
    if let Some(pos) = acl.blocked_ips.iter().position(|x| x == ip) {
        acl.blocked_ips.remove(pos);
        save_acl_config(&acl).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn save_acl_config(config: &AclConfig) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = serde_json::to_string_pretty(&config)?;
    fs::write("config/acl.json", config_str)?;
    Ok(())
}

pub async fn load_acl_config(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(contents) = fs::read_to_string(path) {
        let config: AclConfig = serde_json::from_str(&contents)?;
        update_acl_config(config).await;
    }
    Ok(())
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