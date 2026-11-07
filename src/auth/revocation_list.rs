use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use redis::{
    AsyncCommands, Client, SetOptions,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use uuid::Uuid;

use crate::auth::{RevocationCheck, RevocationError};

#[derive(Clone)]
pub struct RevocationList {
    conn: Option<ConnectionManager>,
}

impl RevocationList {
    pub async fn connect(redis_url: &str) -> Result<Self, RevocationError> {
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_secs(3)))
            .set_response_timeout(Some(Duration::from_secs(2)));
        let client = Client::open(redis_url)?;
        let conn = ConnectionManager::new_with_config(client, config).await?;
        Ok(Self { conn: Some(conn) })
    }

    pub fn disabled() -> Self {
        Self { conn: None }
    }

    pub fn is_enabled(&self) -> bool {
        self.conn.is_some()
    }

    pub async fn revoke(&self, jti: Uuid, ttl_secs: u64) -> Result<bool, RevocationError> {
        let Some(mut conn) = self.conn.clone() else {
            return Ok(true);
        };
        let options = SetOptions::default().with_expiration(redis::SetExpiry::EX(ttl_secs));
        let key = format!("blacklist:{jti}");
        let value = format!("{jti}");
        let result: Option<String> = conn.set_options(key, value, options).await?;
        Ok(result.as_deref() == Some("OK"))
    }

    pub async fn is_revoked(&self, jti: Uuid) -> Result<bool, RevocationError> {
        let Some(mut conn) = self.conn.clone() else {
            return Ok(false);
        };
        let key = format!("blacklist:{jti}");
        let result: bool = conn.exists(key).await?;
        Ok(result)
    }
}

impl RevocationCheck for RevocationList {
    fn is_revoked<'a>(
        &'a self,
        jti: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RevocationError>> + Send + 'a>> {
        Box::pin(RevocationList::is_revoked(self, jti))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_list_never_reports_revoked() {
        let list = RevocationList::disabled();
        assert!(!list.is_enabled());
        assert!(
            !list
                .is_revoked(Uuid::new_v4())
                .await
                .expect("disabled never errors")
        );
    }

    #[tokio::test]
    async fn disabled_list_revoke_is_noop_success() {
        let list = RevocationList::disabled();
        let jti = Uuid::new_v4();
        assert!(list.revoke(jti, 60).await.expect("disabled never errors"));
        assert!(!list.is_revoked(jti).await.expect("disabled never errors"));
    }

    #[tokio::test]
    async fn connect_to_unreachable_address_fails() {
        let result = RevocationList::connect("redis://127.0.0.1:1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connect_with_invalid_url_fails() {
        let result = RevocationList::connect("not a url").await;
        assert!(matches!(result, Err(RevocationError::Redis(_))));
    }
}
