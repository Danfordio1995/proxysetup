use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct AclRule {
    pub domain_pattern: String,
    pub ip_ranges: Vec<String>,
    pub paths: Vec<String>,
    pub is_blacklist: bool,
}

lazy_static! {
    static ref ACL_RULES: RwLock<Vec<AclRule>> = RwLock::new(Vec::new());
    static ref DOMAIN_CACHE: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
}

/// Checks if access is permitted for a given domain and IP
pub async fn check_acl(domain: &str, ip: Option<&str>, path: Option<&str>) -> bool {
    let rules = ACL_RULES.read().await;
    
    // First check domain cache for quick lookups
    {
        let cache = DOMAIN_CACHE.read().await;
        if cache.contains(domain) {
            return false;
        }
    }

    for rule in rules.iter() {
        // Check domain pattern
        if let Ok(pattern) = Regex::new(&rule.domain_pattern) {
            if pattern.is_match(domain) {
                // If it's a blacklist rule and matches, deny access
                if rule.is_blacklist {
                    // Cache the blocked domain
                    DOMAIN_CACHE.write().await.insert(domain.to_string());
                    return false;
                }
            }
        }

        // Check IP ranges if provided
        if let Some(ip_str) = ip {
            if let Ok(ip_addr) = IpAddr::from_str(ip_str) {
                for range in &rule.ip_ranges {
                    if is_ip_in_range(&ip_addr, range) {
                        return !rule.is_blacklist;
                    }
                }
            }
        }

        // Check paths if provided
        if let Some(request_path) = path {
            for rule_path in &rule.paths {
                if let Ok(path_pattern) = Regex::new(rule_path) {
                    if path_pattern.is_match(request_path) {
                        return !rule.is_blacklist;
                    }
                }
            }
        }
    }

    // Default allow if no rules match
    true
}

/// Adds a new ACL rule
pub async fn add_rule(rule: AclRule) {
    ACL_RULES.write().await.push(rule);
}

/// Clears all ACL rules
pub async fn clear_rules() {
    ACL_RULES.write().await.clear();
    DOMAIN_CACHE.write().await.clear();
}

/// Helper function to check if an IP is in a CIDR range
fn is_ip_in_range(ip: &IpAddr, range: &str) -> bool {
    // Basic implementation - in production, use a proper CIDR parsing library
    match (ip, range.split('/').collect::<Vec<_>>().as_slice()) {
        (IpAddr::V4(_ip), [network, bits]) => {
            if let (Ok(_network_ip), Ok(_bits)) = (
                IpAddr::from_str(network),
                bits.parse::<u8>(),
            ) {
                // Implement CIDR range checking logic here
                true // Placeholder - implement actual CIDR check
            } else {
                false
            }
        }
        _ => false,
    }
} 