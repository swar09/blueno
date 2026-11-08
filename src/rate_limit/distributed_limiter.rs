use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use uuid::Uuid;

use crate::config::{Tier, TierLimitConfig};
use crate::rate_limit::{AutonomousLimiter, Decision, RateLimitError, RedisCoordinator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseEntry {
    pub tier: Tier,
    pub available: u64,
    pub expiry: Instant,
    pub max_limit: u64,
}

impl LeaseEntry {
    #[inline]
    pub fn new(tier: Tier, available: u64, expiry: Instant, max_limit: u64) -> Self {
        Self {
            tier,
            available,
            expiry,
            max_limit,
        }
    }

    #[inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expiry
    }

    #[inline]
    pub fn try_consume(&mut self, now: Instant) -> Option<u64> {
        if self.is_expired(now) || self.available == 0 {
            return None;
        }
        self.available -= 1;
        Some(self.available)
    }

    #[inline]
    pub fn update_lease(&mut self, tier: Tier, available: u64, expiry: Instant, max_limit: u64) {
        self.tier = tier;
        self.available = available;
        self.expiry = expiry;
        self.max_limit = max_limit;
    }
}

#[derive(Clone)]
pub struct DistributedLimiter {
    leases: Arc<DashMap<Uuid, LeaseEntry>>,
    coordinator: Arc<RedisCoordinator>,
    fallback: AutonomousLimiter,
    lease_duration: Duration,
    batch_window: Duration,
    redis_cooldown_until: Arc<Mutex<Option<Instant>>>,
}

impl DistributedLimiter {
    pub fn new(
        coordinator: Arc<RedisCoordinator>,
        lease_duration: Duration,
        batch_window: Duration,
    ) -> Self {
        let limiter = Self {
            leases: Arc::new(DashMap::new()),
            coordinator,
            fallback: AutonomousLimiter::new(),
            lease_duration,
            batch_window,
            redis_cooldown_until: Arc::new(Mutex::new(None)),
        };
        limiter.spawn_cleaner();
        limiter
    }

    #[inline]
    pub fn batch_window(&self) -> Duration {
        self.batch_window
    }

    #[inline]
    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    fn spawn_cleaner(&self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let leases = Arc::clone(&self.leases);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    leases.retain(|_, lease| !lease.is_expired(now));
                }
            });
        }
    }

    pub fn prune_expired(&self, now: Instant) {
        self.leases.retain(|_, lease| !lease.is_expired(now));
    }

    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    pub async fn acquire(
        &self,
        user_id: &Uuid,
        tier: Tier,
        config: &TierLimitConfig,
    ) -> Result<Decision, RateLimitError> {
        let now = Instant::now();

        if let Some(mut lease) = self.leases.get_mut(user_id)
            && let Some(remaining) = lease.try_consume(now)
        {
            return Ok(Decision::Allowed {
                remaining,
                limit: lease.max_limit,
            });
        }

        if let Some(cooldown) = *self.redis_cooldown_until.lock()
            && now < cooldown
        {
            return Ok(self.fallback.check(user_id, tier, config));
        }

        let grant = match self.coordinator.lease_quota(user_id, tier, config).await {
            Ok(grant) => {
                *self.redis_cooldown_until.lock() = None;
                grant
            }
            Err(err) => {
                *self.redis_cooldown_until.lock() = Some(now + Duration::from_secs(5));
                tracing::warn!(%err, "redis rate limiter failed, tripping circuit to autonomous limiter for 5s");
                return Ok(self.fallback.check(user_id, tier, config));
            }
        };

        if grant.granted == 0 {
            return Ok(Decision::Throttled {
                retry_after_secs: grant.retry_after_secs.max(1),
                limit: config.max_tokens,
            });
        }

        let new_expiry = now + self.lease_duration;
        let remaining = grant.granted - 1;

        match self.leases.entry(*user_id) {
            dashmap::Entry::Occupied(mut entry) => {
                entry
                    .get_mut()
                    .update_lease(tier, remaining, new_expiry, config.max_tokens);
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(LeaseEntry::new(
                    tier,
                    remaining,
                    new_expiry,
                    config.max_tokens,
                ));
            }
        }

        Ok(Decision::Allowed {
            remaining,
            limit: config.max_tokens,
        })
    }

    pub fn clear(&self) {
        self.leases.clear();
        self.fallback.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_entry_try_consume_and_expiry() {
        let now = Instant::now();
        let mut entry = LeaseEntry::new(Tier::Tier1, 2, now + Duration::from_secs(10), 10);

        assert_eq!(entry.try_consume(now), Some(1));
        assert_eq!(entry.try_consume(now), Some(0));
        assert_eq!(entry.try_consume(now), None);

        let future = now + Duration::from_secs(11);
        assert!(entry.is_expired(future));
    }
}
