/// Checks whether access is permitted for a given domain or resource using a simple rule.
/// For example, domains ending with "disallowed.com" are blocked.
pub fn check_acl(domain: &str) -> bool {
    if domain.ends_with("disallowed.com") {
        return false;
    }
    true
} 