use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserRole(pub String);

impl Default for UserRole {
    fn default() -> Self {
        Self("default".to_string())
    }
}

impl<'de> Deserialize<'de> for UserRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RoleHelper {
            Single(String),
            Multiple(Vec<String>),
        }

        match RoleHelper::deserialize(deserializer)? {
            RoleHelper::Single(s) => Ok(UserRole(s)),
            RoleHelper::Multiple(v) => Ok(UserRole(
                v.first().cloned().unwrap_or_else(|| "default".to_string()),
            )),
        }
    }
}

impl Serialize for UserRole {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl UserRole {
    pub fn new(role: impl Into<String>) -> Self {
        Self(role.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<T: Into<String>> From<T> for UserRole {
    fn from(s: T) -> Self {
        Self(s.into())
    }
}

impl std::ops::Deref for UserRole {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
