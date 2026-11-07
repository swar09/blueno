use axum::http::HeaderName;

pub const IDENTITY_USER_ID: &str = "x-user-id";
pub const IDENTITY_USER_ROLE: &str = "x-user-role";
pub const IDENTITY_TOKEN_ID: &str = "x-token-id";

pub const IDENTITY_HEADERS: [&str; 3] = [IDENTITY_USER_ID, IDENTITY_USER_ROLE, IDENTITY_TOKEN_ID];

pub const HOP_BY_HOP_HEADERS: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn is_identity_header(name: &HeaderName) -> bool {
    IDENTITY_HEADERS.contains(&name.as_str())
}

pub fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    HOP_BY_HOP_HEADERS.contains(&name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_headers_are_recognized() {
        for name in IDENTITY_HEADERS {
            assert!(is_identity_header(&HeaderName::from_static(name)));
        }
        assert!(!is_identity_header(&HeaderName::from_static("x-other")));
    }

    #[test]
    fn hop_by_hop_headers_are_recognized() {
        for name in HOP_BY_HOP_HEADERS {
            assert!(is_hop_by_hop_header(&HeaderName::from_static(name)));
        }
        assert!(!is_hop_by_hop_header(&HeaderName::from_static("accept")));
    }
}
