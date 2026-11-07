use std::net::IpAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestContext {
    pub client_ip: Option<IpAddr>,
    pub client_port: Option<u16>,
    pub peer_ip: Option<IpAddr>,
    pub peer_trusted: bool,
    pub request_id: Option<String>,
    pub scheme: String,
    pub host: Option<String>,
    pub method: String,
}
