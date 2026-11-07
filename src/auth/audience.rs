use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Audience(pub String);

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum AudHelper {
            Single(String),
            Multiple(Vec<String>),
        }

        match AudHelper::deserialize(deserializer)? {
            AudHelper::Single(s) => Ok(Audience(s)),
            AudHelper::Multiple(v) => Ok(Audience(v.join(","))),
        }
    }
}

impl Serialize for Audience {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl Audience {
    pub fn new(aud: impl Into<String>) -> Self {
        Self(aud.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<T: Into<String>> From<T> for Audience {
    fn from(s: T) -> Self {
        Self(s.into())
    }
}

impl std::ops::Deref for Audience {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for Audience {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
