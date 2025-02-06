use lru::LruCache;
use tokio::sync::Mutex;
use lazy_static::lazy_static;

/// A simple in-memory cache implemented as an LRU cache.
/// In a full production system, you might also integrate a disk-based cache with memory-mapped indexes (e.g., LMDB).

const CACHE_CAPACITY: usize = 100; // Adjust capacity based on memory requirements.

lazy_static! {
    pub static ref CACHE: Mutex<LruCache<String, Vec<u8>>> = Mutex::new(LruCache::new(CACHE_CAPACITY));
}

/// Stores a key-value pair in the cache.
pub async fn cache_set(key: String, value: Vec<u8>) {
    let mut cache = CACHE.lock().await;
    cache.put(key, value);
}

/// Retrieves the value associated with a key from the cache.
pub async fn cache_get(key: &str) -> Option<Vec<u8>> {
    let mut cache = CACHE.lock().await;
    // Using `pop` here updates the recency. If you don't want to remove it,
    // you can instead use `get` followed by cloning.
    cache.get(key).cloned()
} 