use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderRuleConfig {
    pub name: String,
    pub value: String,
}
