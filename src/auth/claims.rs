use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{Audience, UserRole};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    #[serde(default)]
    pub iss: String,
    pub sub: Uuid,
    #[serde(default)]
    pub iat: u64,
    #[serde(default)]
    pub nbf: u64,
    pub exp: u64,
    #[serde(default)]
    pub aud: Audience,
    #[serde(default)]
    pub role: UserRole,
    #[serde(default = "Uuid::new_v4")]
    pub jti: Uuid,
}
