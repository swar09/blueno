use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

use crate::config::{Tier, TierLimitConfig};
use crate::rate_limit::Decision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitEntry {
    pub tier: Tier,
    pub quota: u64,
    pub last_fill: Instant,
    pub last_burst: Instant,
}

impl RateLimitEntry {
    #[inline]
    pub fn new(tier: Tier, quota: u64, now: Instant) -> Self {
        Self {
            tier,
            quota,
            last_fill: now,
            last_burst: now,
        }
    }
}

#[derive(Clone)]
pub struct AutonomousLimiter {
    entries: Arc<DashMap<Uuid, RateLimitEntry>>,
}

impl AutonomousLimiter {
    pub fn new() -> Self {
        let limiter = Self {
            entries: Arc::new(DashMap::new()),
        };
        limiter.spawn_cleaner();
        limiter
    }

    fn spawn_cleaner(&self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let entries = Arc::clone(&self.entries);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    let ttl = Duration::from_secs(300);
                    entries.retain(|_, entry| now.duration_since(entry.last_fill) < ttl);
                }
            });
        }
    }

    pub fn prune_stale(&self, now: Instant, ttl: Duration) {
        self.entries
            .retain(|_, entry| now.duration_since(entry.last_fill) < ttl);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn check(&self, user_id: &Uuid, tier: Tier, config: &TierLimitConfig) -> Decision {
        let now = Instant::now();
        let mut entry = self
            .entries
            .entry(*user_id)
            .or_insert_with(|| RateLimitEntry::new(tier, config.initial_tokens, now));

        entry.tier = tier;

        let elapsed_fill = now.duration_since(entry.last_fill).as_secs();
        if elapsed_fill > 0 {
            entry.quota = entry.quota.saturating_add(elapsed_fill * config.fill_rate);
            entry.last_fill = now;
        }

        let elapsed_burst = now.duration_since(entry.last_burst).as_secs();
        if elapsed_burst >= config.burst_interval_secs {
            let bursts = elapsed_burst / config.burst_interval_secs;
            entry.quota = entry.quota.saturating_add(bursts * config.initial_tokens);
            entry.last_burst = now;
        }

        entry.quota = entry.quota.min(config.max_tokens);

        if entry.quota > 0 {
            entry.quota -= 1;
            Decision::Allowed {
                remaining: entry.quota,
                limit: config.max_tokens,
            }
        } else {
            let retry_after = if config.fill_rate > 0 {
                1
            } else {
                config.burst_interval_secs
            };
            Decision::Throttled {
                retry_after_secs: retry_after,
                limit: config.max_tokens,
            }
        }
    }

    pub fn clear(&self) {
        self.entries.clear();
    }
}

impl Default for AutonomousLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tier_config(initial: u64, max: u64) -> TierLimitConfig {
        TierLimitConfig {
            initial_tokens: initial,
            fill_rate: 0,
            burst_interval_secs: 60,
            max_tokens: max,
            lease_batch_size: 10,
        }
    }

    #[test]
    fn test_autonomous_limiter_quota_depletion_and_throttling() {
        let limiter = AutonomousLimiter::new();
        let user_id = Uuid::new_v4();
        let config = test_tier_config(2, 2);

        let first = limiter.check(&user_id, Tier::Tier1, &config);
        assert_eq!(
            first,
            Decision::Allowed {
                remaining: 1,
                limit: 2
            }
        );

        let second = limiter.check(&user_id, Tier::Tier1, &config);
        assert_eq!(
            second,
            Decision::Allowed {
                remaining: 0,
                limit: 2
            }
        );

        let third = limiter.check(&user_id, Tier::Tier1, &config);
        assert_eq!(
            third,
            Decision::Throttled {
                retry_after_secs: 60,
                limit: 2
            }
        );
    }

    #[test]
    fn test_autonomous_limiter_prune_stale() {
        let limiter = AutonomousLimiter::new();
        let user_id = Uuid::new_v4();
        let config = test_tier_config(5, 5);

        limiter.check(&user_id, Tier::Tier1, &config);
        assert_eq!(limiter.len(), 1);

        let now = Instant::now();
        limiter.prune_stale(now + Duration::from_secs(400), Duration::from_secs(300));
        assert!(limiter.is_empty());
    }
}
