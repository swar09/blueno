use std::time::Duration;

use redis::{
    Client, Script,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use uuid::Uuid;

use crate::config::{Tier, TierLimitConfig};
use crate::rate_limit::{LeaseGrant, RateLimitError};

pub const BUILTIN_RATE_LIMIT_SCRIPT: &str = include_str!("../../conf/rate_limit.lua");

pub struct RedisCoordinator {
    conn: ConnectionManager,
    key_prefix: String,
    script: Script,
}

impl RedisCoordinator {
    pub async fn new(
        redis_url: &str,
        key_prefix: String,
        script_source: &str,
    ) -> Result<Self, RateLimitError> {
        let client = Client::open(redis_url)?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_secs(2)))
            .set_response_timeout(Some(Duration::from_secs(1)));
        let conn = ConnectionManager::new_with_config(client, config).await?;

        let script = Script::new(script_source);
        Ok(Self {
            conn,
            key_prefix,
            script,
        })
    }

    pub async fn lease_quota(
        &self,
        user_id: &Uuid,
        _tier: Tier,
        config: &TierLimitConfig,
    ) -> Result<LeaseGrant, RateLimitError> {
        let key = format!("{}:user:{}", self.key_prefix, user_id);
        let ttl = config.burst_interval_secs.max(60) * 2;
        let mut conn = self.conn.clone();

        let result: Vec<u64> = self
            .script
            .key(&key)
            .arg(config.initial_tokens)
            .arg(config.fill_rate)
            .arg(config.burst_interval_secs)
            .arg(config.max_tokens)
            .arg(config.lease_batch_size)
            .arg(ttl)
            .invoke_async(&mut conn)
            .await?;

        let granted = result.first().copied().unwrap_or(0);
        let retry_after_secs = result.get(1).copied().unwrap_or(0);

        Ok(LeaseGrant {
            granted,
            retry_after_secs,
        })
    }
}
