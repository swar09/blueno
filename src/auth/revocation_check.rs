use std::future::Future;
use std::pin::Pin;

use uuid::Uuid;

use crate::auth::RevocationError;

pub trait RevocationCheck: Send + Sync {
    fn is_revoked<'a>(
        &'a self,
        jti: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RevocationError>> + Send + 'a>>;
}
