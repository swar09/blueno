#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IncomingForwarding {
    pub(crate) chain: Option<String>,
    pub(crate) proto: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) forwarded: Option<String>,
}
