use std::time::{Instant};
use lazy_static::lazy_static;

/// A basic token bucket rate limiter.
pub struct RateLimiter {
    capacity: f64,      // Maximum number of tokens.
    tokens: f64,        // Current number of tokens.
    refill_rate: f64,   // Tokens to add per second.
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume one token. Returns true if allowed.
    pub async fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        // Refill tokens based on elapsed time.
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
} 