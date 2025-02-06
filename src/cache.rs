use std::collections::HashMap;
use tokio::sync::Mutex;
use lazy_static::lazy_static;

/// A simple in-memory cache represented by a HashMap.  
/// In a high-performance production system, you would implement an LRU cache with memory-mapped indexes (e.g., using LMDB).
lazy_static! {
    pub static ref CACHE: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
}

/// Stores a key-value pair in the cache.
pub async fn cache_set(key: String, value: Vec<u8>) {
    let mut cache = CACHE.lock().await;
    cache.insert(key, value);
}

/// Retrieves the value associated with a key from the cache.
pub async fn cache_get(key: &str) -> Option<Vec<u8>> {
    let cache = CACHE.lock().await;
    cache.get(key).cloned()
} 